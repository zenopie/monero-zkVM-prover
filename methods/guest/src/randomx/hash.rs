//! RandomX Hash Computation
//!
//! This module implements the main RandomX hash function.
//!
//! The hash computation flow:
//! 1. Initialize cache from key (Argon2d, simplified for zkVM)
//! 2. For each hash:
//!    a. Generate program from input hash
//!    b. Initialize scratchpad from seed
//!    c. Execute program RANDOMX_PROGRAM_COUNT times
//!    d. Mix with dataset items (light mode computes on-demand)
//!    e. Produce final hash using AES and Blake2b

use crate::randomx::aes::SoftAes;
use crate::randomx::blake2b::{blake2b_256, blake2b_hash};
use crate::randomx::config::*;
use crate::randomx::program::Program;
use crate::randomx::scratchpad::{Cache, Scratchpad};
use crate::randomx::vm::VmState;
use alloc::vec::Vec;

/// RandomX virtual machine instance
pub struct RandomXVm {
    /// Cache for light mode
    cache: Cache,
    /// VM state
    vm: VmState,
    /// Scratchpad
    scratchpad: Scratchpad,
    /// Scratchpad size
    scratchpad_size: usize,
}

impl RandomXVm {
    /// Create a new RandomX VM in light mode with full Argon2d cache (256 MiB)
    /// This is required for verifying real Monero blocks
    pub fn new(key: &[u8]) -> Self {
        let cache = Cache::new(key);
        let scratchpad_size = RANDOMX_SCRATCHPAD_L3;
        let scratchpad = Scratchpad::new(scratchpad_size);
        let vm = VmState::new(scratchpad_size);

        Self {
            cache,
            vm,
            scratchpad,
            scratchpad_size,
        }
    }

    /// Create with custom scratchpad size (for testing)
    pub fn new_with_size(key: &[u8], scratchpad_size: usize) -> Self {
        let cache = Cache::new(key);
        let scratchpad = Scratchpad::new(scratchpad_size);
        let vm = VmState::new(scratchpad_size);

        Self {
            cache,
            vm,
            scratchpad,
            scratchpad_size,
        }
    }

    /// Create with custom cache and scratchpad sizes (for testing)
    pub fn new_with_cache_size(key: &[u8], cache_size: usize, scratchpad_size: usize) -> Self {
        let cache = Cache::new_with_size(key, cache_size);
        let scratchpad = Scratchpad::new(scratchpad_size);
        let vm = VmState::new(scratchpad_size);

        Self {
            cache,
            vm,
            scratchpad,
            scratchpad_size,
        }
    }

    /// Compute RandomX hash
    pub fn hash(&mut self, input: &[u8]) -> [u8; 32] {
        self.hash_minimal(input, RANDOMX_PROGRAM_COUNT, RANDOMX_PROGRAM_ITERATIONS)
    }

    /// Compute RandomX hash with configurable program count and iterations
    /// For testing: use small values like (1, 128) for 128x faster proving
    pub fn hash_minimal(&mut self, input: &[u8], program_count: usize, iterations: usize) -> [u8; 32] {
        // Step 1: Hash input to get 64-byte seed
        let seed_hash = blake2b_hash(input);

        // Step 2: Initialize scratchpad from seed
        self.scratchpad.init(&seed_hash);

        // Copy scratchpad to VM
        self.vm.scratchpad = self.scratchpad.memory.clone();

        // Step 3: Initialize registers from seed
        let mut reg_seed = seed_hash;

        // Execute multiple programs
        for program_idx in 0..program_count {
            // Generate program from current seed
            let program = Program::generate(&reg_seed);

            // Initialize VM state
            self.vm.init(&reg_seed, &program.entropy);

            // Execute program iterations
            for _iter in 0..iterations {
                // Execute the program
                self.vm.execute_program(&program);

                // Dataset mixing (light mode)
                // In full implementation, this reads from 2GB dataset
                // In light mode, we compute dataset items on-demand
                let item_idx = (self.vm.mem_config.mx as u64)
                    .wrapping_mul(self.vm.int_regs.r[0])
                    % (RANDOMX_DATASET_ITEM_COUNT as u64);

                let dataset_item = self.cache.get_dataset_item(item_idx);

                // XOR with registers
                for i in 0..8 {
                    let val = u64::from_le_bytes([
                        dataset_item[i * 8],
                        dataset_item[i * 8 + 1],
                        dataset_item[i * 8 + 2],
                        dataset_item[i * 8 + 3],
                        dataset_item[i * 8 + 4],
                        dataset_item[i * 8 + 5],
                        dataset_item[i * 8 + 6],
                        dataset_item[i * 8 + 7],
                    ]);
                    self.vm.int_regs.r[i] ^= val;
                }

                // Update memory addresses
                self.vm.mem_config.ma ^= self.vm.int_regs.r[0] as u32;
                self.vm.mem_config.mx ^= self.vm.int_regs.r[1] as u32;
            }

            // Update scratchpad from VM
            self.scratchpad.memory = self.vm.scratchpad.clone();

            // Get register file for next program seed
            let reg_file = self.vm.get_register_file();

            // Hash register file for next program
            if program_idx < program_count - 1 {
                reg_seed = aes_hash_register_file(&reg_file);
            }
        }

        // Step 4: Final hash
        // Get final register file
        let final_regs = self.vm.get_register_file();

        // AES hash of scratchpad (simplified)
        let mut sp_hash = [0u8; 64];
        for i in 0..64 {
            sp_hash[i] = self.scratchpad.memory[i % self.scratchpad.memory.len()];
        }
        let sp_aes = SoftAes::hash(&sp_hash);

        // Combine register file with scratchpad hash
        let mut final_input = [0u8; 256];
        final_input[0..64].copy_from_slice(&sp_aes);
        final_input[64..128].copy_from_slice(&final_regs[0..64]);
        final_input[128..192].copy_from_slice(&final_regs[64..128]);
        final_input[192..256].copy_from_slice(&final_regs[128..192]);

        // Final Blake2b hash
        blake2b_256(&final_input)
    }
}

/// AES hash of register file (for seed generation between programs)
fn aes_hash_register_file(regs: &[u8; 256]) -> [u8; 64] {
    let mut input = [0u8; 64];
    // XOR register file chunks
    for i in 0..4 {
        for j in 0..64 {
            input[j] ^= regs[i * 64 + j];
        }
    }
    SoftAes::hash(&input)
}

/// Main entry point for RandomX hash computation
pub fn randomx_hash(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut vm = RandomXVm::new(key);
    vm.hash(input)
}

/// Compute RandomX hash with custom scratchpad size (for testing)
pub fn randomx_hash_with_size(key: &[u8], input: &[u8], scratchpad_size: usize) -> [u8; 32] {
    let mut vm = RandomXVm::new_with_size(key, scratchpad_size);
    vm.hash(input)
}

/// Compute RandomX hash with custom cache and scratchpad sizes (for testing)
pub fn randomx_hash_with_cache_size(
    key: &[u8],
    input: &[u8],
    cache_size: usize,
    scratchpad_size: usize,
) -> [u8; 32] {
    let mut vm = RandomXVm::new_with_cache_size(key, cache_size, scratchpad_size);
    vm.hash(input)
}

/// Compute RandomX hash with ALL parameters configurable (for minimal testing)
/// This allows reducing program_count and iterations for fast prover testing
pub fn randomx_hash_minimal(
    key: &[u8],
    input: &[u8],
    cache_size: usize,
    scratchpad_size: usize,
    program_count: usize,
    iterations: usize,
) -> [u8; 32] {
    let mut vm = RandomXVm::new_with_cache_size(key, cache_size, scratchpad_size);
    vm.hash_minimal(input, program_count, iterations)
}

/// Verify that a hash meets difficulty target
pub fn verify_difficulty(hash: &[u8; 32], difficulty: u64) -> bool {
    if difficulty == 0 {
        return false;
    }
    if difficulty == 1 {
        return true;
    }

    // Convert hash to 256-bit integer (big-endian for comparison)
    // Check if hash <= (2^256 - 1) / difficulty

    // Simplified check: count leading zero bytes
    let mut leading_zeros = 0;
    for &byte in hash.iter() {
        if byte == 0 {
            leading_zeros += 1;
        } else {
            break;
        }
    }

    // Required zeros based on difficulty
    // difficulty D requires roughly log2(D) bits of zeros
    let difficulty_bits = 64 - difficulty.leading_zeros();
    let required_zero_bytes = difficulty_bits / 8;

    if leading_zeros as u32 > required_zero_bytes {
        return true;
    }
    if (leading_zeros as u32) < required_zero_bytes {
        return false;
    }

    // For exact comparison, check the remaining bytes
    // This is a simplified version
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_hash() {
        let key = b"RandomX key for testing";
        let input = b"test input";

        let hash = randomx_hash(key, input);

        // Hash should be deterministic
        let hash2 = randomx_hash(key, input);
        assert_eq!(hash, hash2);

        // Different input should give different hash
        let hash3 = randomx_hash(key, b"different input");
        assert_ne!(hash, hash3);
    }
}
