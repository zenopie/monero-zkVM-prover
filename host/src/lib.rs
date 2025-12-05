//! Monero RandomX zkVM Prover Library
//!
//! This library provides the core proving functionality for Monero RandomX verification.

pub mod randomx_vm;

use methods::{
    PHASE1A_CACHE_SEGMENT_ELF, PHASE1A_CACHE_SEGMENT_ID,
    PHASE2_PROGRAM_ELF, PHASE2_PROGRAM_ID,
};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, VerifierContext};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Instant;

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b512, Digest};
use sha2::Sha256;

/// Library version
pub const VERSION: &str = "v33";

// ============================================================
// MONERO RANDOMX SPECIFICATION
// ============================================================
pub const CACHE_SIZE: usize = 268435456;  // 256 MiB
pub const CACHE_SEGMENTS: usize = 64;     // 4 MiB per segment
pub const SCRATCHPAD_SIZE: usize = 2097152;  // 2 MiB
pub const PROGRAM_COUNT: usize = 8;
pub const ITERATIONS: usize = 2048;
pub const RANDOMX_DATASET_ITEM_COUNT: usize = CACHE_SIZE / 64;

// Block segment constants (256 segments = 8 programs × 32 chunks)
const CHUNKS_PER_PROGRAM: usize = 32;
const ITERATIONS_PER_CHUNK: usize = ITERATIONS / CHUNKS_PER_PROGRAM;  // 64 iterations per chunk
const TOTAL_BLOCK_SEGMENTS: usize = PROGRAM_COUNT * CHUNKS_PER_PROGRAM;  // 256 total

const PROOFS_DIR: &str = "proofs";
const CACHE_DIR: &str = "cache";

// ============================================================
// PREP DATA CACHE (reusable for ~2048 blocks with same RandomX key)
// ============================================================

/// Cached prep data for fast segment proving
/// This is expensive to compute (~10 mins) but reusable for ~2048 blocks
pub struct PrepCache {
    pub randomx_key: [u8; 32],
    pub seed: [u8; 64],
    pub cache: Vec<u8>,
    pub merkle_root: [u8; 32],
    pub merkle_tree: Vec<Vec<[u8; 32]>>,
}

impl PrepCache {
    /// Build prep cache from RandomX key (expensive - ~10 mins)
    pub fn build(randomx_key: [u8; 32]) -> Self {
        let argon2_memory_kib = (CACHE_SIZE / 1024) as u32;
        let seed = compute_argon2_seed(&randomx_key, argon2_memory_kib);
        let cache = expand_cache_from_seed(&seed, CACHE_SIZE);
        let (merkle_root, merkle_tree) = build_merkle_tree(&cache);

        Self {
            randomx_key,
            seed,
            cache,
            merkle_root,
            merkle_tree,
        }
    }

    /// Save prep cache to disk
    pub fn save(&self) -> std::io::Result<()> {
        fs::create_dir_all(CACHE_DIR)?;

        let key_hex = hex::encode(&self.randomx_key[..8]);
        let path = format!("{}/prep_{}.bin", CACHE_DIR, key_hex);

        // Serialize: seed (64) + cache (256MiB) + merkle_root (32) + merkle_tree
        let mut data = Vec::new();
        data.extend_from_slice(&self.randomx_key);
        data.extend_from_slice(&self.seed);
        data.extend_from_slice(&self.cache);
        data.extend_from_slice(&self.merkle_root);

        // Serialize merkle tree: num_levels, then each level
        let num_levels = self.merkle_tree.len() as u32;
        data.extend_from_slice(&num_levels.to_le_bytes());
        for level in &self.merkle_tree {
            let level_len = level.len() as u32;
            data.extend_from_slice(&level_len.to_le_bytes());
            for hash in level {
                data.extend_from_slice(hash);
            }
        }

        fs::write(&path, data)
    }

    /// Load prep cache from disk (fast - just file read)
    pub fn load(randomx_key: &[u8; 32]) -> Option<Self> {
        let key_hex = hex::encode(&randomx_key[..8]);
        let path = format!("{}/prep_{}.bin", CACHE_DIR, key_hex);

        let data = fs::read(&path).ok()?;
        if data.len() < 32 + 64 + CACHE_SIZE + 32 + 4 {
            return None;
        }

        let mut offset = 0;

        // Read randomx_key
        let mut stored_key = [0u8; 32];
        stored_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Verify key matches
        if stored_key != *randomx_key {
            return None;
        }

        // Read seed
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&data[offset..offset + 64]);
        offset += 64;

        // Read cache
        let cache = data[offset..offset + CACHE_SIZE].to_vec();
        offset += CACHE_SIZE;

        // Read merkle_root
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Read merkle tree
        let num_levels = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        let mut merkle_tree = Vec::with_capacity(num_levels);
        for _ in 0..num_levels {
            if offset + 4 > data.len() {
                return None;
            }
            let level_len = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]) as usize;
            offset += 4;

            let mut level = Vec::with_capacity(level_len);
            for _ in 0..level_len {
                if offset + 32 > data.len() {
                    return None;
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;
                level.push(hash);
            }
            merkle_tree.push(level);
        }

        Some(Self {
            randomx_key: stored_key,
            seed,
            cache,
            merkle_root,
            merkle_tree,
        })
    }

    /// Load or build prep cache
    pub fn load_or_build(randomx_key: [u8; 32]) -> Self {
        if let Some(cached) = Self::load(&randomx_key) {
            return cached;
        }

        let prep = Self::build(randomx_key);
        let _ = prep.save(); // Best effort save
        prep
    }
}

// ============================================================
// PUBLIC TYPES
// ============================================================

/// Proof mode selection
#[derive(Debug, Clone, PartialEq)]
pub enum ProofMode {
    Cache,
    CacheSegment(usize),
    Block,
    BlockSegment(usize),
    Full,
}

/// Configuration for proving
#[derive(Debug, Clone)]
pub struct ProverConfig {
    pub mode: ProofMode,
    pub randomx_key: [u8; 32],
    pub hashing_blob: Vec<u8>,
    pub difficulty: u64,
    pub resume: bool,
}

impl ProverConfig {
    /// Create a new prover config with required parameters
    pub fn new(randomx_key: [u8; 32], hashing_blob: Vec<u8>, difficulty: u64) -> Self {
        Self {
            mode: ProofMode::Full,
            randomx_key,
            hashing_blob,
            difficulty,
            resume: false,
        }
    }

    /// Set the proof mode
    pub fn with_mode(mut self, mode: ProofMode) -> Self {
        self.mode = mode;
        self
    }

    /// Enable resume mode (skip existing valid proofs)
    pub fn with_resume(mut self, resume: bool) -> Self {
        self.resume = resume;
        self
    }
}

/// Result of a proving operation
#[derive(Debug, Clone)]
pub struct ProofResult {
    pub success: bool,
    pub pow_hash: Option<[u8; 32]>,
    pub difficulty_valid: Option<bool>,
    pub merkle_root: Option<[u8; 32]>,
    pub cache_hash: Option<[u8; 32]>,
    pub total_cycles: u64,
    pub proving_time_secs: u64,
    pub error: Option<String>,
}

impl Default for ProofResult {
    fn default() -> Self {
        Self {
            success: false,
            pow_hash: None,
            difficulty_valid: None,
            merkle_root: None,
            cache_hash: None,
            total_cycles: 0,
            proving_time_secs: 0,
            error: None,
        }
    }
}

/// Phase 1 Input (Cache Segment)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase1aInput {
    #[serde(with = "BigArray")]
    pub seed: [u8; 64],
    pub segment_index: usize,
    pub total_segments: usize,
    pub segment_start: usize,
    pub segment_size: usize,
    pub total_cache_size: usize,
    #[serde(with = "BigArray")]
    pub prev_block_pass1: [u8; 64],
    #[serde(with = "BigArray")]
    pub prev_block_pass2: [u8; 64],
    #[serde(with = "BigArray")]
    pub aes_states: [u8; 64],
}

/// Phase 1a Output (Cache Segment)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase1aOutput {
    pub segment_hash: [u8; 32],
    pub segment_index: usize,
    pub total_segments: usize,
    pub segment_start: usize,
    pub segment_size: usize,
    pub seed_hash: [u8; 32],
    #[serde(with = "BigArray")]
    pub final_prev_block_pass1: [u8; 64],
    #[serde(with = "BigArray")]
    pub final_prev_block_pass2: [u8; 64],
}

/// Program segment input
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramSegmentInput {
    pub program_index: u8,
    pub is_first: bool,
    pub is_last: bool,
    pub iteration_start: u16,
    pub iteration_count: u16,
    pub dataset_merkle_root: [u8; 32],
    pub input_data: Vec<u8>,
    #[serde(with = "BigArray")]
    pub seed: [u8; 64],
    pub scratchpad: Vec<u8>,
    pub initial_registers: Vec<u8>,
    pub initial_ma: u32,
    pub initial_mx: u32,
    pub dataset_items: Vec<DatasetItemEntry>,
    pub difficulty: u64,
    /// Pre-computed program instructions (256 × 8 bytes)
    pub program_instructions: Vec<u8>,
    /// Pre-computed program entropy (16 × u64)
    #[serde(with = "BigArray")]
    pub program_entropy: [u64; 16],
}

/// Dataset item with Merkle proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatasetItemEntry {
    pub index: u64,
    #[serde(with = "BigArray")]
    pub item: [u8; 64],
    pub proof: Vec<u8>,
}

/// Program segment output
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramSegmentOutput {
    pub program_index: u8,
    pub iteration_start: u16,
    pub iteration_count: u16,
    #[serde(with = "BigArray")]
    pub next_seed: [u8; 64],
    pub pow_hash: Option<[u8; 32]>,
    pub difficulty_valid: Option<bool>,
    pub dataset_merkle_root: [u8; 32],
}

// ============================================================
// AES IMPLEMENTATION
// ============================================================

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn xtime(x: u8) -> u8 {
    if x & 0x80 != 0 { (x << 1) ^ 0x1b } else { x << 1 }
}

#[derive(Clone, Copy)]
pub(crate) struct AesState {
    state: [u8; 16],
}

impl AesState {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let mut state = [0u8; 16];
        state.copy_from_slice(&bytes[..16]);
        Self { state }
    }

    pub(crate) fn to_bytes(&self) -> [u8; 16] {
        self.state
    }

    fn sub_bytes(&mut self) {
        for byte in self.state.iter_mut() {
            *byte = SBOX[*byte as usize];
        }
    }

    fn shift_rows(&mut self) {
        let tmp = self.state[1];
        self.state[1] = self.state[5];
        self.state[5] = self.state[9];
        self.state[9] = self.state[13];
        self.state[13] = tmp;

        let tmp0 = self.state[2];
        let tmp1 = self.state[6];
        self.state[2] = self.state[10];
        self.state[6] = self.state[14];
        self.state[10] = tmp0;
        self.state[14] = tmp1;

        let tmp = self.state[15];
        self.state[15] = self.state[11];
        self.state[11] = self.state[7];
        self.state[7] = self.state[3];
        self.state[3] = tmp;
    }

    fn mix_columns(&mut self) {
        for col in 0..4 {
            let i = col * 4;
            let a = self.state[i];
            let b = self.state[i + 1];
            let c = self.state[i + 2];
            let d = self.state[i + 3];

            self.state[i] = xtime(a) ^ xtime(b) ^ b ^ c ^ d;
            self.state[i + 1] = a ^ xtime(b) ^ xtime(c) ^ c ^ d;
            self.state[i + 2] = a ^ b ^ xtime(c) ^ xtime(d) ^ d;
            self.state[i + 3] = xtime(a) ^ a ^ b ^ c ^ xtime(d);
        }
    }

    fn add_round_key(&mut self, key: &[u8; 16]) {
        for (s, k) in self.state.iter_mut().zip(key.iter()) {
            *s ^= *k;
        }
    }
}

pub(crate) fn aes_round(state: &mut AesState, key: &[u8; 16]) {
    state.sub_bytes();
    state.shift_rows();
    state.mix_columns();
    state.add_round_key(key);
}

pub(crate) fn soft_aes_fill_scratchpad(seed: &[u8; 64], scratchpad: &mut [u8]) {
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

    let mut offset = 0;
    while offset < scratchpad.len() {
        for state in states.iter_mut() {
            for key in keys.iter() {
                aes_round(state, key);
            }
        }

        for state in states.iter() {
            let bytes = state.to_bytes();
            let end = std::cmp::min(offset + 16, scratchpad.len());
            let len = end - offset;
            scratchpad[offset..end].copy_from_slice(&bytes[..len]);
            offset += 16;
            if offset >= scratchpad.len() {
                break;
            }
        }
    }
}

// ============================================================
// CORE FUNCTIONS
// ============================================================

const ARGON2_SALT: &[u8] = b"RandomX\x03";
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;


/// Compute Blake2b-256 hash
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let full: [u8; 64] = hasher.finalize().into();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&full[..32]);
    hash
}

/// Compute SHA-256 hash (used for Merkle tree - accelerated in zkVM)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as Sha2Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute Argon2d seed
pub fn compute_argon2_seed(key: &[u8], memory_kib: u32) -> [u8; 64] {
    let memory = std::cmp::max(8, memory_kib);

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

/// Expand seed to cache using AES
pub fn expand_cache_from_seed(seed: &[u8; 64], size: usize) -> Vec<u8> {
    let mut cache = vec![0u8; size];
    soft_aes_fill_scratchpad(seed, &mut cache);

    let key: [u8; 16] = seed[0..16].try_into().unwrap();

    let mut prev_block = [0u8; 64];
    let mut current_block = [0u8; 64];

    for _ in 0..2 {
        prev_block.copy_from_slice(&cache[size - 64..size]);

        for i in (0..size).step_by(64) {
            let end = std::cmp::min(i + 64, size);
            let block_len = end - i;

            current_block[..block_len].copy_from_slice(&cache[i..end]);

            for j in 0..block_len {
                cache[i + j] ^= prev_block[j];
            }

            if block_len >= 16 {
                let mut state = AesState::from_bytes(&cache[i..i + 16]);
                aes_round(&mut state, &key);
                cache[i..i + 16].copy_from_slice(&state.to_bytes());
            }

            prev_block[..block_len].copy_from_slice(&current_block[..block_len]);
        }
    }

    cache
}

/// Extract AES states at segment boundaries
fn extract_aes_states_at_boundaries(
    seed: &[u8; 64],
    num_segments: usize,
    segment_size: usize,
) -> Vec<[u8; 64]> {
    let keys: [[u8; 16]; 4] = [
        [0xd7, 0x98, 0x3a, 0xad, 0x14, 0xab, 0x20, 0xdc, 0xa2, 0x9e, 0x6e, 0x02, 0x5f, 0x45, 0xb1, 0x1b],
        [0xbb, 0x04, 0x5d, 0x78, 0x45, 0x79, 0x98, 0x50, 0xd7, 0xdf, 0x28, 0xe5, 0x32, 0xe0, 0x48, 0xa7],
        [0xf1, 0x07, 0x59, 0xea, 0xc9, 0x72, 0x38, 0x2d, 0x67, 0x15, 0x88, 0x6c, 0x32, 0x59, 0x28, 0xab],
        [0x76, 0x9a, 0x49, 0xf0, 0x60, 0x14, 0xb6, 0x2c, 0xa9, 0x41, 0xc8, 0x19, 0x54, 0xb6, 0x75, 0xf7],
    ];

    let mut aes_boundaries = Vec::with_capacity(num_segments);

    let mut states = [
        AesState::from_bytes(&seed[0..16]),
        AesState::from_bytes(&seed[16..32]),
        AesState::from_bytes(&seed[32..48]),
        AesState::from_bytes(&seed[48..64]),
    ];

    let iterations_per_segment = segment_size / 64;

    for _seg_idx in 0..num_segments {
        let mut state_bytes = [0u8; 64];
        for (i, state) in states.iter().enumerate() {
            state_bytes[i * 16..(i + 1) * 16].copy_from_slice(&state.to_bytes());
        }
        aes_boundaries.push(state_bytes);

        for _ in 0..iterations_per_segment {
            for state in states.iter_mut() {
                for key in keys.iter() {
                    aes_round(state, key);
                }
            }
        }
    }

    aes_boundaries
}

/// Extract segment boundaries for segmented proving
fn extract_segment_boundaries(
    seed: &[u8; 64],
    cache: &[u8],
    num_segments: usize,
) -> Vec<([u8; 64], [u8; 64])> {
    let size = cache.len();
    let segment_size = size / num_segments;

    let key: [u8; 16] = seed[0..16].try_into().unwrap();

    let mut initial_fill = vec![0u8; size];
    soft_aes_fill_scratchpad(seed, &mut initial_fill);

    let mut boundaries = Vec::with_capacity(num_segments);

    let mut prev_block_p1 = [0u8; 64];
    prev_block_p1.copy_from_slice(&initial_fill[size - 64..size]);

    let mut pass1_boundaries = vec![[0u8; 64]; num_segments];
    pass1_boundaries[0] = prev_block_p1;

    let mut current_block = [0u8; 64];
    for i in (0..size).step_by(64) {
        let end = std::cmp::min(i + 64, size);
        let block_len = end - i;

        current_block[..block_len].copy_from_slice(&initial_fill[i..end]);

        let segment_idx = i / segment_size;
        if i > 0 && i % segment_size == 0 && segment_idx < num_segments {
            pass1_boundaries[segment_idx] = prev_block_p1;
        }

        prev_block_p1[..block_len].copy_from_slice(&current_block[..block_len]);
    }

    let mut after_pass1 = initial_fill.clone();
    let mut prev = [0u8; 64];
    prev.copy_from_slice(&after_pass1[size - 64..size]);
    let mut curr = [0u8; 64];

    for i in (0..size).step_by(64) {
        let end = std::cmp::min(i + 64, size);
        let block_len = end - i;

        curr[..block_len].copy_from_slice(&after_pass1[i..end]);

        for j in 0..block_len {
            after_pass1[i + j] ^= prev[j];
        }

        if block_len >= 16 {
            let mut state = AesState::from_bytes(&after_pass1[i..i + 16]);
            aes_round(&mut state, &key);
            after_pass1[i..i + 16].copy_from_slice(&state.to_bytes());
        }

        prev[..block_len].copy_from_slice(&curr[..block_len]);
    }

    let mut pass2_boundaries = vec![[0u8; 64]; num_segments];
    let mut prev_block_p2 = [0u8; 64];
    prev_block_p2.copy_from_slice(&after_pass1[size - 64..size]);
    pass2_boundaries[0] = prev_block_p2;

    for i in (0..size).step_by(64) {
        let end = std::cmp::min(i + 64, size);
        let block_len = end - i;

        current_block[..block_len].copy_from_slice(&after_pass1[i..end]);

        let segment_idx = i / segment_size;
        if i > 0 && i % segment_size == 0 && segment_idx < num_segments {
            pass2_boundaries[segment_idx] = prev_block_p2;
        }

        prev_block_p2[..block_len].copy_from_slice(&current_block[..block_len]);
    }

    for i in 0..num_segments {
        boundaries.push((pass1_boundaries[i], pass2_boundaries[i]));
    }

    boundaries
}

/// Build Merkle tree from cache using SHA-256 (accelerated in zkVM)
pub fn build_merkle_tree(cache: &[u8]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    let num_items = cache.len() / 64;

    // Hash each 64-byte item with SHA-256 to get leaves
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(num_items);
    for i in 0..num_items {
        let start = i * 64;
        let item = &cache[start..start + 64];
        leaves.push(sha256(item));
    }

    // Pad to power of 2
    let mut size = 1;
    while size < leaves.len() {
        size *= 2;
    }
    while leaves.len() < size {
        leaves.push([0u8; 32]);
    }

    let mut tree: Vec<Vec<[u8; 32]>> = vec![leaves];

    // Build tree levels using SHA-256
    while tree.last().unwrap().len() > 1 {
        let prev_level = tree.last().unwrap();
        let mut next_level = Vec::with_capacity(prev_level.len() / 2);

        for i in (0..prev_level.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[0..32].copy_from_slice(&prev_level[i]);
            combined[32..64].copy_from_slice(&prev_level[i + 1]);
            next_level.push(sha256(&combined));
        }
        tree.push(next_level);
    }

    let root = tree.last().unwrap()[0];
    (root, tree)
}

/// Generate Merkle proof for a specific item index
fn generate_merkle_proof(tree: &[Vec<[u8; 32]>], index: usize) -> Vec<u8> {
    let mut proof = Vec::new();
    let mut idx = index;

    for level in &tree[..tree.len() - 1] {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < level.len() {
            proof.extend_from_slice(&level[sibling_idx]);
        } else {
            proof.extend_from_slice(&[0u8; 32]);
        }
        idx /= 2;
    }

    proof
}

/// Verify a Merkle proof (host-side, for debugging)
pub fn verify_merkle_proof_host(
    root: &[u8; 32],
    index: u64,
    item: &[u8; 64],
    siblings: &[u8],
    total_items: u64,
) -> bool {
    let mut current = sha256(item);

    let height = 64 - (total_items - 1).leading_zeros();
    let expected_siblings = height as usize;

    if siblings.len() != expected_siblings * 32 {
        eprintln!("Proof length mismatch: got {} bytes, expected {} bytes ({} siblings)",
            siblings.len(), expected_siblings * 32, expected_siblings);
        return false;
    }

    let mut idx = index;
    for i in 0..expected_siblings {
        let sibling_start = i * 32;
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&siblings[sibling_start..sibling_start + 32]);

        let mut combined = [0u8; 64];
        if idx % 2 == 0 {
            combined[0..32].copy_from_slice(&current);
            combined[32..64].copy_from_slice(&sibling);
        } else {
            combined[0..32].copy_from_slice(&sibling);
            combined[32..64].copy_from_slice(&current);
        }
        current = sha256(&combined);
        idx /= 2;
    }

    if current != *root {
        eprintln!("Root mismatch: computed {:?}, expected {:?}",
            hex::encode(&current[..8]), hex::encode(&root[..8]));
        return false;
    }
    true
}

/// Convert segment ID to program parameters
fn segment_to_params(segment_id: usize) -> (usize, usize, usize) {
    let program_index = segment_id / CHUNKS_PER_PROGRAM;
    let chunk_index = segment_id % CHUNKS_PER_PROGRAM;
    let iteration_start = chunk_index * ITERATIONS_PER_CHUNK;
    (program_index, iteration_start, ITERATIONS_PER_CHUNK)
}

// ============================================================
// PROOF PERSISTENCE
// ============================================================

fn ensure_proofs_dir() {
    if !Path::new(PROOFS_DIR).exists() {
        fs::create_dir_all(PROOFS_DIR).expect("Failed to create proofs directory");
    }
}

fn save_receipt(name: &str, receipt: &Receipt) -> std::io::Result<()> {
    ensure_proofs_dir();
    let path = format!("{}/{}.bin", PROOFS_DIR, name);
    let bytes = bincode::serialize(receipt).expect("Failed to serialize receipt");
    fs::write(&path, bytes)
}

fn load_receipt(name: &str) -> Option<Receipt> {
    let path = format!("{}/{}.bin", PROOFS_DIR, name);
    if Path::new(&path).exists() {
        match fs::read(&path) {
            Ok(bytes) => bincode::deserialize(&bytes).ok(),
            Err(_) => None,
        }
    } else {
        None
    }
}

fn has_valid_segment_proof(seg_idx: usize) -> bool {
    let name = format!("cache_segment_{:02}", seg_idx);
    if let Some(receipt) = load_receipt(&name) {
        return receipt.verify(PHASE1A_CACHE_SEGMENT_ID).is_ok();
    }
    false
}

fn has_valid_program_proof(prog_idx: usize) -> bool {
    let name = format!("program_{}", prog_idx);
    if let Some(receipt) = load_receipt(&name) {
        return receipt.verify(PHASE2_PROGRAM_ID).is_ok();
    }
    false
}

// ============================================================
// MAIN PROVING FUNCTIONS
// ============================================================

/// Prove cache (all 64 segments)
pub fn prove_cache(config: &ProverConfig) -> ProofResult {
    let total_start = Instant::now();
    let mut result = ProofResult::default();

    let argon2_memory_kib = (CACHE_SIZE / 1024) as u32;
    let seed = compute_argon2_seed(&config.randomx_key, argon2_memory_kib);
    let cache = expand_cache_from_seed(&seed, CACHE_SIZE);
    let cache_hash = blake2b_256(&cache);
    result.cache_hash = Some(cache_hash);

    let segment_size = CACHE_SIZE / CACHE_SEGMENTS;
    let boundaries = extract_segment_boundaries(&seed, &cache, CACHE_SEGMENTS);
    let aes_states = extract_aes_states_at_boundaries(&seed, CACHE_SEGMENTS, segment_size);

    let prover = default_prover();
    let opts = ProverOpts::default();

    for seg_idx in 0..CACHE_SEGMENTS {
        let proof_name = format!("cache_segment_{:02}", seg_idx);

        if config.resume && has_valid_segment_proof(seg_idx) {
            continue;
        }

        let segment_start = seg_idx * segment_size;
        let (prev_p1, prev_p2) = &boundaries[seg_idx];

        let phase1a_input = Phase1aInput {
            seed,
            segment_index: seg_idx,
            total_segments: CACHE_SEGMENTS,
            segment_start,
            segment_size,
            total_cache_size: CACHE_SIZE,
            prev_block_pass1: *prev_p1,
            prev_block_pass2: *prev_p2,
            aes_states: aes_states[seg_idx],
        };

        let seg_env = ExecutorEnv::builder()
            .write(&phase1a_input)
            .expect("Failed to write Phase 1a input")
            .build()
            .expect("Failed to build Phase 1a executor env");

        match prover.prove_with_ctx(
            seg_env,
            &VerifierContext::default(),
            PHASE1A_CACHE_SEGMENT_ELF,
            &opts,
        ) {
            Ok(info) => {
                result.total_cycles += info.stats.total_cycles;

                if info.receipt.verify(PHASE1A_CACHE_SEGMENT_ID).is_err() {
                    result.error = Some(format!("Segment {} verification failed", seg_idx));
                    return result;
                }

                let _ = save_receipt(&proof_name, &info.receipt);
            }
            Err(e) => {
                result.error = Some(format!("Segment {} failed: {}", seg_idx, e));
                return result;
            }
        }
    }

    result.success = true;
    result.proving_time_secs = total_start.elapsed().as_secs();
    result
}

/// Prove a single cache segment
pub fn prove_cache_segment(config: &ProverConfig, segment: usize) -> ProofResult {
    if segment >= CACHE_SEGMENTS {
        return ProofResult {
            error: Some(format!("Invalid segment: {} (max {})", segment, CACHE_SEGMENTS - 1)),
            ..Default::default()
        };
    }

    let total_start = Instant::now();
    let mut result = ProofResult::default();

    let argon2_memory_kib = (CACHE_SIZE / 1024) as u32;
    let seed = compute_argon2_seed(&config.randomx_key, argon2_memory_kib);
    let cache = expand_cache_from_seed(&seed, CACHE_SIZE);

    let segment_size = CACHE_SIZE / CACHE_SEGMENTS;
    let boundaries = extract_segment_boundaries(&seed, &cache, CACHE_SEGMENTS);
    let aes_states = extract_aes_states_at_boundaries(&seed, CACHE_SEGMENTS, segment_size);

    let prover = default_prover();
    let opts = ProverOpts::default();

    let segment_start = segment * segment_size;
    let (prev_p1, prev_p2) = &boundaries[segment];

    let phase1a_input = Phase1aInput {
        seed,
        segment_index: segment,
        total_segments: CACHE_SEGMENTS,
        segment_start,
        segment_size,
        total_cache_size: CACHE_SIZE,
        prev_block_pass1: *prev_p1,
        prev_block_pass2: *prev_p2,
        aes_states: aes_states[segment],
    };

    let seg_env = ExecutorEnv::builder()
        .write(&phase1a_input)
        .expect("Failed to write Phase 1a input")
        .build()
        .expect("Failed to build Phase 1a executor env");

    match prover.prove_with_ctx(
        seg_env,
        &VerifierContext::default(),
        PHASE1A_CACHE_SEGMENT_ELF,
        &opts,
    ) {
        Ok(info) => {
            result.total_cycles = info.stats.total_cycles;

            if info.receipt.verify(PHASE1A_CACHE_SEGMENT_ID).is_err() {
                result.error = Some(format!("Segment {} verification failed", segment));
                return result;
            }

            let proof_name = format!("cache_segment_{:02}", segment);
            let _ = save_receipt(&proof_name, &info.receipt);
            result.success = true;
        }
        Err(e) => {
            result.error = Some(format!("Segment {} failed: {}", segment, e));
        }
    }

    result.proving_time_secs = total_start.elapsed().as_secs();
    result
}

/// Prove block (all 8 programs)
pub fn prove_block(config: &ProverConfig) -> ProofResult {
    let total_start = Instant::now();
    let mut result = ProofResult::default();

    let argon2_memory_kib = (CACHE_SIZE / 1024) as u32;
    let seed = compute_argon2_seed(&config.randomx_key, argon2_memory_kib);
    let cache = expand_cache_from_seed(&seed, CACHE_SIZE);
    let cache_hash = blake2b_256(&cache);
    result.cache_hash = Some(cache_hash);

    let (merkle_root, merkle_tree) = build_merkle_tree(&cache);
    result.merkle_root = Some(merkle_root);

    let simulation = randomx_vm::simulate_all_programs(
        &cache,
        &config.hashing_blob,
        SCRATCHPAD_SIZE,
        ITERATIONS,
        RANDOMX_DATASET_ITEM_COUNT,
    );

    let prover = default_prover();
    let opts = ProverOpts::default();

    for prog_idx in 0..PROGRAM_COUNT {
        let proof_name = format!("program_{}", prog_idx);

        if config.resume && has_valid_program_proof(prog_idx) {
            if prog_idx == PROGRAM_COUNT - 1 {
                if let Some(existing_receipt) = load_receipt(&proof_name) {
                    if let Ok(output) = existing_receipt.journal.decode::<ProgramSegmentOutput>() {
                        result.pow_hash = output.pow_hash;
                        result.difficulty_valid = output.difficulty_valid;
                    }
                }
            }
            continue;
        }

        let is_first = prog_idx == 0;
        let is_last = prog_idx == PROGRAM_COUNT - 1;

        let current_seed = simulation.seeds[prog_idx];
        let current_scratchpad = &simulation.scratchpads[prog_idx];

        let accesses = &simulation.accesses[prog_idx];
        let unique_indices: BTreeSet<u64> = accesses.iter().copied().collect();

        let mut dataset_items: Vec<DatasetItemEntry> = Vec::with_capacity(unique_indices.len());
        for &idx in &unique_indices {
            let item_start = (idx as usize) * 64;
            let mut item = [0u8; 64];
            item.copy_from_slice(&cache[item_start..item_start + 64]);
            let proof = generate_merkle_proof(&merkle_tree, idx as usize);
            dataset_items.push(DatasetItemEntry {
                index: idx,
                item,
                proof,
            });
        }

        // Generate program data on host for the current seed
        let (program_instructions, program_entropy) = randomx_vm::Program::generate_raw(&current_seed);

        let segment_input = ProgramSegmentInput {
            program_index: prog_idx as u8,
            is_first,
            is_last,
            iteration_start: 0,
            iteration_count: ITERATIONS as u16,
            dataset_merkle_root: merkle_root,
            input_data: if is_first { config.hashing_blob.clone() } else { vec![] },
            seed: current_seed,
            scratchpad: current_scratchpad.to_vec(),
            initial_registers: vec![],
            initial_ma: 0,
            initial_mx: 0,
            dataset_items,
            difficulty: config.difficulty,
            program_instructions,
            program_entropy,
        };

        let seg_env = ExecutorEnv::builder()
            .write(&segment_input)
            .expect("Failed to write segment input")
            .build()
            .expect("Failed to build segment executor env");

        match prover.prove_with_ctx(
            seg_env,
            &VerifierContext::default(),
            PHASE2_PROGRAM_ELF,
            &opts,
        ) {
            Ok(info) => {
                let output: ProgramSegmentOutput = info.receipt.journal.decode()
                    .expect("Failed to decode segment output");

                result.total_cycles += info.stats.total_cycles;

                if info.receipt.verify(PHASE2_PROGRAM_ID).is_err() {
                    result.error = Some(format!("Program {} verification failed", prog_idx));
                    return result;
                }

                let _ = save_receipt(&proof_name, &info.receipt);

                if is_last {
                    result.pow_hash = output.pow_hash;
                    result.difficulty_valid = output.difficulty_valid;
                }
            }
            Err(e) => {
                result.error = Some(format!("Program {} failed: {}", prog_idx, e));
                return result;
            }
        }
    }

    result.success = true;
    result.proving_time_secs = total_start.elapsed().as_secs();
    result
}

/// Prove a single block segment (0-255)
pub fn prove_block_segment(config: &ProverConfig, segment: usize) -> ProofResult {
    if segment >= TOTAL_BLOCK_SEGMENTS {
        return ProofResult {
            error: Some(format!("Invalid segment: {} (max {})", segment, TOTAL_BLOCK_SEGMENTS - 1)),
            ..Default::default()
        };
    }

    let total_start = Instant::now();
    let mut result = ProofResult::default();

    let (prog_idx, iteration_start, iteration_count) = segment_to_params(segment);

    let argon2_memory_kib = (CACHE_SIZE / 1024) as u32;
    let seed = compute_argon2_seed(&config.randomx_key, argon2_memory_kib);
    let cache = expand_cache_from_seed(&seed, CACHE_SIZE);

    let (merkle_root, merkle_tree) = build_merkle_tree(&cache);
    result.merkle_root = Some(merkle_root);

    let simulation = randomx_vm::simulate_all_programs(
        &cache,
        &config.hashing_blob,
        SCRATCHPAD_SIZE,
        ITERATIONS,
        RANDOMX_DATASET_ITEM_COUNT,
    );

    let chunk_sim = randomx_vm::simulate_program_chunk(
        &cache,
        &simulation.seeds[prog_idx],
        &simulation.scratchpads[prog_idx],
        iteration_start,
        iteration_count,
        RANDOMX_DATASET_ITEM_COUNT,
    );

    let unique_indices: BTreeSet<u64> = chunk_sim.accesses.iter().copied().collect();

    let mut dataset_items: Vec<DatasetItemEntry> = Vec::with_capacity(unique_indices.len());
    for &idx in &unique_indices {
        let item_start = (idx as usize) * 64;
        let mut item = [0u8; 64];
        item.copy_from_slice(&cache[item_start..item_start + 64]);
        let proof = generate_merkle_proof(&merkle_tree, idx as usize);
        dataset_items.push(DatasetItemEntry {
            index: idx,
            item,
            proof,
        });
    }

    let is_first = prog_idx == 0 && iteration_start == 0;
    let is_last = prog_idx == PROGRAM_COUNT - 1 && (iteration_start + iteration_count) == ITERATIONS;

    // Generate program data on host
    let (program_instructions, program_entropy) = randomx_vm::Program::generate_raw(&simulation.seeds[prog_idx]);

    let segment_input = ProgramSegmentInput {
        program_index: prog_idx as u8,
        is_first,
        is_last,
        iteration_start: iteration_start as u16,
        iteration_count: iteration_count as u16,
        dataset_merkle_root: merkle_root,
        input_data: if is_first { config.hashing_blob.clone() } else { vec![] },
        seed: simulation.seeds[prog_idx],
        scratchpad: chunk_sim.scratchpad_at_start.clone(),
        initial_registers: chunk_sim.initial_registers.clone(),
        initial_ma: chunk_sim.initial_ma,
        initial_mx: chunk_sim.initial_mx,
        dataset_items,
        difficulty: config.difficulty,
        program_instructions,
        program_entropy,
    };

    let prover = default_prover();
    let opts = ProverOpts::default();

    let seg_env = ExecutorEnv::builder()
        .write(&segment_input)
        .expect("Failed to write segment input")
        .build()
        .expect("Failed to build segment executor env");

    match prover.prove_with_ctx(
        seg_env,
        &VerifierContext::default(),
        PHASE2_PROGRAM_ELF,
        &opts,
    ) {
        Ok(info) => {
            let output: ProgramSegmentOutput = info.receipt.journal.decode()
                .expect("Failed to decode segment output");

            result.total_cycles = info.stats.total_cycles;

            if info.receipt.verify(PHASE2_PROGRAM_ID).is_err() {
                result.error = Some(format!("Segment {} verification failed", segment));
                return result;
            }

            let proof_name = format!("segment_{}", segment);
            let _ = save_receipt(&proof_name, &info.receipt);

            if is_last {
                result.pow_hash = output.pow_hash;
                result.difficulty_valid = output.difficulty_valid;
            }

            result.success = true;
        }
        Err(e) => {
            result.error = Some(format!("Segment {} failed: {}", segment, e));
        }
    }

    result.proving_time_secs = total_start.elapsed().as_secs();
    result
}

/// Prove a single block segment using cached prep data (FAST - for production)
///
/// This is the main function for production use. First call with a new RandomX key
/// will be slow (~10 mins) to build the cache. Subsequent calls reuse the cache.
pub fn prove_block_segment_cached(
    prep: &PrepCache,
    hashing_blob: &[u8],
    difficulty: u64,
    segment: usize,
) -> ProofResult {
    if segment >= TOTAL_BLOCK_SEGMENTS {
        return ProofResult {
            error: Some(format!("Invalid segment: {} (max {})", segment, TOTAL_BLOCK_SEGMENTS - 1)),
            ..Default::default()
        };
    }

    let total_start = Instant::now();
    let mut result = ProofResult::default();
    result.merkle_root = Some(prep.merkle_root);

    let (prog_idx, iteration_start, iteration_count) = segment_to_params(segment);

    // Simulation is per-block (depends on hashing_blob) - but it's fast
    let simulation = randomx_vm::simulate_all_programs(
        &prep.cache,
        hashing_blob,
        SCRATCHPAD_SIZE,
        ITERATIONS,
        RANDOMX_DATASET_ITEM_COUNT,
    );

    let chunk_sim = randomx_vm::simulate_program_chunk(
        &prep.cache,
        &simulation.seeds[prog_idx],
        &simulation.scratchpads[prog_idx],
        iteration_start,
        iteration_count,
        RANDOMX_DATASET_ITEM_COUNT,
    );

    let unique_indices: BTreeSet<u64> = chunk_sim.accesses.iter().copied().collect();

    let mut dataset_items: Vec<DatasetItemEntry> = Vec::with_capacity(unique_indices.len());
    for &idx in &unique_indices {
        let item_start = (idx as usize) * 64;
        let mut item = [0u8; 64];
        item.copy_from_slice(&prep.cache[item_start..item_start + 64]);
        let proof = generate_merkle_proof(&prep.merkle_tree, idx as usize);

        // Verify proof before sending to guest (debug)
        if !verify_merkle_proof_host(&prep.merkle_root, idx, &item, &proof, RANDOMX_DATASET_ITEM_COUNT as u64) {
            eprintln!("ERROR: Host-side proof verification failed for item {}", idx);
            eprintln!("  Tree levels: {}", prep.merkle_tree.len());
            eprintln!("  Proof length: {} bytes ({} siblings)", proof.len(), proof.len() / 32);
        }

        dataset_items.push(DatasetItemEntry {
            index: idx,
            item,
            proof,
        });
    }

    let is_first = prog_idx == 0 && iteration_start == 0;
    let is_last = prog_idx == PROGRAM_COUNT - 1 && (iteration_start + iteration_count) == ITERATIONS;

    // Generate program data on host
    let (program_instructions, program_entropy) = randomx_vm::Program::generate_raw(&simulation.seeds[prog_idx]);

    let segment_input = ProgramSegmentInput {
        program_index: prog_idx as u8,
        is_first,
        is_last,
        iteration_start: iteration_start as u16,
        iteration_count: iteration_count as u16,
        dataset_merkle_root: prep.merkle_root,
        input_data: if is_first { hashing_blob.to_vec() } else { vec![] },
        seed: simulation.seeds[prog_idx],
        scratchpad: chunk_sim.scratchpad_at_start.clone(),
        initial_registers: chunk_sim.initial_registers.clone(),
        initial_ma: chunk_sim.initial_ma,
        initial_mx: chunk_sim.initial_mx,
        dataset_items,
        difficulty,
        program_instructions,
        program_entropy,
    };

    let prover = default_prover();
    let opts = ProverOpts::default();

    let seg_env = ExecutorEnv::builder()
        .write(&segment_input)
        .expect("Failed to write segment input")
        .build()
        .expect("Failed to build segment executor env");

    match prover.prove_with_ctx(
        seg_env,
        &VerifierContext::default(),
        PHASE2_PROGRAM_ELF,
        &opts,
    ) {
        Ok(info) => {
            let output: ProgramSegmentOutput = info.receipt.journal.decode()
                .expect("Failed to decode segment output");

            result.total_cycles = info.stats.total_cycles;

            if info.receipt.verify(PHASE2_PROGRAM_ID).is_err() {
                result.error = Some(format!("Segment {} verification failed", segment));
                return result;
            }

            let proof_name = format!("segment_{}", segment);
            let _ = save_receipt(&proof_name, &info.receipt);

            if is_last {
                result.pow_hash = output.pow_hash;
                result.difficulty_valid = output.difficulty_valid;
            }

            result.success = true;
        }
        Err(e) => {
            result.error = Some(format!("Segment {} failed: {}", segment, e));
        }
    }

    result.proving_time_secs = total_start.elapsed().as_secs();
    result
}

/// Prove full (cache + block)
pub fn prove_full(config: &ProverConfig) -> ProofResult {
    let total_start = Instant::now();

    // First prove cache
    let cache_result = prove_cache(config);
    if !cache_result.success {
        return cache_result;
    }

    // Then prove block
    let mut block_result = prove_block(config);
    block_result.total_cycles += cache_result.total_cycles;
    block_result.cache_hash = cache_result.cache_hash;
    block_result.proving_time_secs = total_start.elapsed().as_secs();

    block_result
}

/// Main prove function that dispatches based on mode
pub fn prove(config: &ProverConfig) -> ProofResult {
    match &config.mode {
        ProofMode::Cache => prove_cache(config),
        ProofMode::CacheSegment(n) => prove_cache_segment(config, *n),
        ProofMode::Block => prove_block(config),
        ProofMode::BlockSegment(n) => prove_block_segment(config, *n),
        ProofMode::Full => prove_full(config),
    }
}
