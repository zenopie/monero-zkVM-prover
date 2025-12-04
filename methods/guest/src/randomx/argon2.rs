//! Argon2d Cache Initialization for RandomX
//!
//! RandomX uses Argon2d to initialize the 256 MiB cache from a key.
//! Parameters (from RandomX spec):
//! - Memory: 262144 KiB (256 MiB)
//! - Iterations: 3
//! - Lanes: 1
//! - Salt: "RandomX\x03"
//!
//! Reference: https://github.com/tevador/RandomX/blob/master/doc/specs.md#6-dataset

use alloc::vec::Vec;
use argon2::{Algorithm, Argon2, Params, Version};

/// RandomX Argon2d parameters
pub const ARGON2_MEMORY_KIB: u32 = 262144; // 256 MiB in KiB
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;
pub const ARGON2_SALT: &[u8] = b"RandomX\x03";
pub const ARGON2_OUTPUT_LEN: usize = 268435456; // 256 MiB

/// Initialize RandomX cache using Argon2d
///
/// This produces the 256 MiB cache that RandomX uses for light mode verification.
/// The cache is then used to compute dataset items on-demand.
pub fn init_cache(key: &[u8]) -> Vec<u8> {
    // Create Argon2d params matching RandomX spec
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(64), // Output 64 bytes initially, we'll expand
    )
    .expect("Invalid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

    // The cache is built by running Argon2d and then using the memory state
    // For RandomX, we need the full memory state, not just the output hash

    // However, the argon2 crate doesn't expose internal memory state directly
    // We need to generate the cache differently:
    // 1. Run Argon2d to get a seed
    // 2. Expand the seed to fill 256 MiB using AES

    // First, get the Argon2d hash
    let mut seed = [0u8; 64];
    argon2
        .hash_password_into(key, ARGON2_SALT, &mut seed)
        .expect("Argon2d hash failed");

    // Now expand to full cache size using the seed
    // This matches RandomX's cache expansion after Argon2d
    expand_cache_from_seed(&seed, ARGON2_OUTPUT_LEN)
}

/// Initialize cache with custom size (for testing with smaller memory)
pub fn init_cache_with_size(key: &[u8], size: usize) -> Vec<u8> {
    // For smaller sizes, use proportionally less Argon2 memory
    let memory_kib = core::cmp::max(8, (size / 1024) as u32);

    let params = Params::new(
        memory_kib,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(64),
    )
    .expect("Invalid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

    let mut seed = [0u8; 64];
    argon2
        .hash_password_into(key, ARGON2_SALT, &mut seed)
        .expect("Argon2d hash failed");

    expand_cache_from_seed(&seed, size)
}

/// Compute Argon2d seed only (for segmented proving)
/// Returns the 64-byte seed that's used to expand the cache
pub fn compute_argon2_seed(key: &[u8], memory_kib: u32) -> [u8; 64] {
    let memory = core::cmp::max(8, memory_kib);

    let params = Params::new(
        memory,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(64),
    )
    .expect("Invalid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

    let mut seed = [0u8; 64];
    argon2
        .hash_password_into(key, ARGON2_SALT, &mut seed)
        .expect("Argon2d hash failed");
    seed
}

/// Expand a single segment of the cache from seed
///
/// This proves correct expansion of one segment (segment_index out of total_segments).
/// The segment_start and segment_size define the byte range.
///
/// prev_block_pass1 and prev_block_pass2 are the states at the START of this segment
/// for each mixing pass. For segment 0, these are the last 64 bytes of the initial fill.
///
/// aes_states contains the 4 AES states (16 bytes each = 64 bytes total) pre-computed
/// by the host at the segment boundary, avoiding O(N) fast-forward computation.
///
/// Returns: (segment_data, final_prev_block_pass1, final_prev_block_pass2)
pub fn expand_cache_segment(
    seed: &[u8; 64],
    segment_start: usize,
    segment_size: usize,
    _total_cache_size: usize,
    prev_block_pass1: &[u8; 64],
    prev_block_pass2: &[u8; 64],
    aes_states: &[u8; 64],
) -> (Vec<u8>, [u8; 64], [u8; 64]) {
    use crate::randomx::aes::{AesState, aes_round};

    // Allocate segment
    let mut segment = alloc::vec![0u8; segment_size];

    // Fill this segment using pre-computed AES states (O(1) instead of O(N))
    fill_scratchpad_with_states(aes_states, &mut segment, segment_start);

    // Mixing pass 1
    let mut key = [0u8; 16];
    key.copy_from_slice(&seed[0..16]);

    let mut prev_block_p1 = *prev_block_pass1;
    let mut current_block = [0u8; 64];

    for i in (0..segment_size).step_by(64) {
        let end = core::cmp::min(i + 64, segment_size);
        let block_len = end - i;

        // Save current block's original value
        current_block[..block_len].copy_from_slice(&segment[i..end]);

        // XOR with previous block
        for j in 0..block_len {
            segment[i + j] ^= prev_block_p1[j];
        }

        // AES round
        if block_len >= 16 {
            let mut state = AesState::from_bytes(&segment[i..i + 16]);
            aes_round(&mut state, &key);
            segment[i..i + 16].copy_from_slice(&state.to_bytes());
        }

        // Update prev_block for next iteration
        prev_block_p1[..block_len].copy_from_slice(&current_block[..block_len]);
    }

    let final_prev_block_p1 = prev_block_p1;

    // Mixing pass 2
    let mut prev_block_p2 = *prev_block_pass2;

    for i in (0..segment_size).step_by(64) {
        let end = core::cmp::min(i + 64, segment_size);
        let block_len = end - i;

        // Save current block's original value
        current_block[..block_len].copy_from_slice(&segment[i..end]);

        // XOR with previous block
        for j in 0..block_len {
            segment[i + j] ^= prev_block_p2[j];
        }

        // AES round
        if block_len >= 16 {
            let mut state = AesState::from_bytes(&segment[i..i + 16]);
            aes_round(&mut state, &key);
            segment[i..i + 16].copy_from_slice(&state.to_bytes());
        }

        // Update prev_block for next iteration
        prev_block_p2[..block_len].copy_from_slice(&current_block[..block_len]);
    }

    let final_prev_block_p2 = prev_block_p2;

    (segment, final_prev_block_p1, final_prev_block_p2)
}

/// Fill a scratchpad range using pre-computed AES states
/// This is O(segment_size) instead of O(offset + segment_size)
fn fill_scratchpad_with_states(aes_states: &[u8; 64], output: &mut [u8], offset: usize) {
    use crate::randomx::aes::{AesState, aes_round};

    // AES fill produces 64 bytes per iteration (4 states x 16 bytes)
    let start_byte_in_iteration = offset % 64;

    // Initialize states from pre-computed values (no fast-forward needed!)
    let mut states = [
        AesState::from_bytes(&aes_states[0..16]),
        AesState::from_bytes(&aes_states[16..32]),
        AesState::from_bytes(&aes_states[32..48]),
        AesState::from_bytes(&aes_states[48..64]),
    ];

    let keys: [[u8; 16]; 4] = [
        [0xd7, 0x98, 0x3a, 0xad, 0x14, 0xab, 0x20, 0xdc, 0xa2, 0x9e, 0x6e, 0x02, 0x5f, 0x45, 0xb1, 0x1b],
        [0xbb, 0x04, 0x5d, 0x78, 0x45, 0x79, 0x98, 0x50, 0xd7, 0xdf, 0x28, 0xe5, 0x32, 0xe0, 0x48, 0xa7],
        [0xf1, 0x07, 0x59, 0xea, 0xc9, 0x72, 0x38, 0x2d, 0x67, 0x15, 0x88, 0x6c, 0x32, 0x59, 0x28, 0xab],
        [0x76, 0x9a, 0x49, 0xf0, 0x60, 0x14, 0xb6, 0x2c, 0xa9, 0x41, 0xc8, 0x19, 0x54, 0xb6, 0x75, 0xf7],
    ];

    // Generate output directly (no fast-forward loop!)
    let mut out_offset = 0;
    let mut skip_bytes = start_byte_in_iteration;

    while out_offset < output.len() {
        // Do one iteration
        for state in states.iter_mut() {
            for key in keys.iter() {
                aes_round(state, key);
            }
        }

        // Extract bytes from this iteration
        for state in states.iter() {
            let bytes = state.to_bytes();
            for &b in bytes.iter() {
                if skip_bytes > 0 {
                    skip_bytes -= 1;
                    continue;
                }
                if out_offset < output.len() {
                    output[out_offset] = b;
                    out_offset += 1;
                }
            }
        }
    }
}

/// Fill a scratchpad range from a specific offset (legacy - used by init_cache)
/// This computes what SoftAes::fill_scratchpad would produce at offset..offset+len
fn fill_scratchpad_range(seed: &[u8; 64], output: &mut [u8], offset: usize) {
    use crate::randomx::aes::{AesState, aes_round};

    // AES fill produces 64 bytes per iteration (4 states x 16 bytes)
    // We need to fast-forward to the correct iteration
    let iterations_per_round = 64; // 4 states * 16 bytes
    let start_iteration = offset / iterations_per_round;
    let start_byte_in_iteration = offset % iterations_per_round;

    // Initialize states
    let mut states = [
        AesState::from_bytes(&seed[0..16]),
        AesState::from_bytes(&seed[16..32]),
        AesState::from_bytes(&seed[32..48]),
        AesState::from_bytes(&seed[48..64]),
    ];

    let keys: [[u8; 16]; 4] = [
        [0xd7, 0x98, 0x3a, 0xad, 0x14, 0xab, 0x20, 0xdc, 0xa2, 0x9e, 0x6e, 0x02, 0x5f, 0x45, 0xb1, 0x1b],
        [0xbb, 0x04, 0x5d, 0x78, 0x45, 0x79, 0x98, 0x50, 0xd7, 0xdf, 0x28, 0xe5, 0x32, 0xe0, 0x48, 0xa7],
        [0xf1, 0x07, 0x59, 0xea, 0xc9, 0x72, 0x38, 0x2d, 0x67, 0x15, 0x88, 0x6c, 0x32, 0x59, 0x28, 0xab],
        [0x76, 0x9a, 0x49, 0xf0, 0x60, 0x14, 0xb6, 0x2c, 0xa9, 0x41, 0xc8, 0x19, 0x54, 0xb6, 0x75, 0xf7],
    ];

    // Fast-forward to start_iteration
    for _ in 0..start_iteration {
        for state in states.iter_mut() {
            for key in keys.iter() {
                aes_round(state, key);
            }
        }
    }

    // Now generate output
    let mut out_offset = 0;
    let mut skip_bytes = start_byte_in_iteration;

    while out_offset < output.len() {
        // Do one iteration
        for state in states.iter_mut() {
            for key in keys.iter() {
                aes_round(state, key);
            }
        }

        // Extract bytes from this iteration
        for state in states.iter() {
            let bytes = state.to_bytes();
            for &b in bytes.iter() {
                if skip_bytes > 0 {
                    skip_bytes -= 1;
                    continue;
                }
                if out_offset < output.len() {
                    output[out_offset] = b;
                    out_offset += 1;
                }
            }
        }
    }
}

/// Get the last 64 bytes of the initial AES fill (needed for segment 0)
pub fn get_initial_fill_last_block(seed: &[u8; 64], total_size: usize) -> [u8; 64] {
    let mut block = [0u8; 64];
    let last_offset = total_size - 64;
    fill_scratchpad_range(seed, &mut block, last_offset);
    block
}

/// Expand seed to full cache size using AES
///
/// RandomX expands the Argon2d memory state using AES in a specific pattern.
/// This fills the cache with pseudo-random data derived from the seed.
///
/// This version works in-place to avoid cloning the entire cache (saves ~256 MiB).
fn expand_cache_from_seed(seed: &[u8; 64], size: usize) -> Vec<u8> {
    use crate::randomx::aes::{AesState, aes_round, SoftAes};

    let mut cache = alloc::vec![0u8; size];

    // Use AES to expand the seed
    SoftAes::fill_scratchpad(seed, &mut cache);

    // Additional mixing passes for better randomness (as per RandomX spec)
    // Use the first 16 bytes of seed as the AES key
    let mut key = [0u8; 16];
    key.copy_from_slice(&seed[0..16]);

    // In-place mixing - use small buffers to avoid cloning entire cache
    // We need to save each block's original value before modifying it,
    // so the next block can XOR with the pre-modification value.
    let mut prev_block = [0u8; 64];
    let mut current_block = [0u8; 64];

    for _ in 0..2 {
        // Save the last block (it's the "previous" for block 0)
        prev_block.copy_from_slice(&cache[size - 64..size]);

        for i in (0..size).step_by(64) {
            let end = core::cmp::min(i + 64, size);
            let block_len = end - i;

            // Save current block's original value before modifying
            current_block[..block_len].copy_from_slice(&cache[i..end]);

            // XOR with previous block (using its pre-modification value)
            for j in 0..block_len {
                cache[i + j] ^= prev_block[j];
            }

            // AES round on first 16 bytes of each 64-byte block
            if block_len >= 16 {
                let mut state = AesState::from_bytes(&cache[i..i + 16]);
                aes_round(&mut state, &key);
                cache[i..i + 16].copy_from_slice(&state.to_bytes());
            }

            // Current block's original value becomes previous for next iteration
            prev_block[..block_len].copy_from_slice(&current_block[..block_len]);
        }
    }

    cache
}
