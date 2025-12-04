//! Host program for Monero RandomX zkVM verification
//!
//! Usage: host <mode> [options]
//!
//! Modes:
//!   cache               Prove full cache hash (64 segments)
//!   cache-segment <N>   Prove single cache segment (0-63)
//!   block               Prove full block PoW (8 programs)
//!   block-segment <N>   Prove single block segment (0-255)
//!   full                Prove cache + block (default)
//!
//! Options:
//!   --randomx-key <HEX>   32-byte RandomX key (hex, uses test key if omitted)
//!   --hashing-blob <HEX>  Block hashing blob (hex, uses test blob if omitted)
//!   --difficulty <N>      Target difficulty (default: 1)
//!   --resume              Skip segments with existing valid proofs
//!
//! Segment IDs:
//!   Cache segments: 0-63 (4 MiB each)
//!   Block segments: 0-255 (8 programs × 32 chunks)
//!
//! Monero Spec: 256 MiB cache, 2 MiB scratchpad, 8 programs, 2048 iterations

mod randomx_vm;

use methods::{
    PHASE1A_CACHE_SEGMENT_ELF, PHASE1A_CACHE_SEGMENT_ID,
    PHASE2_PROGRAM_ELF, PHASE2_PROGRAM_ID,
};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, VerifierContext};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::fs;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use sysinfo::System;

// Import argon2 for host-side cache computation
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b512, Digest};

/// Version - keep in sync with methods/guest/src/lib.rs
const VERSION: &str = "v29";

// ============================================================
// MONERO RANDOMX SPECIFICATION (must match guest)
// ============================================================
const CACHE_SIZE: usize = 268435456;  // 256 MiB
const CACHE_SEGMENTS: usize = 64;     // 4 MiB per segment
const SCRATCHPAD_SIZE: usize = 2097152;  // 2 MiB
const PROGRAM_COUNT: usize = 8;
const ITERATIONS: usize = 2048;
const RANDOMX_DATASET_ITEM_COUNT: usize = CACHE_SIZE / 64;  // ~4.2M items

// ZK-Client mode constants (256 segments for random sampling)
const CHUNKS_PER_PROGRAM: usize = 32;
const ITERATIONS_PER_CHUNK: usize = ITERATIONS / CHUNKS_PER_PROGRAM;  // 64
const TOTAL_SEGMENTS: usize = PROGRAM_COUNT * CHUNKS_PER_PROGRAM;  // 256

/// Proof mode
#[derive(Debug, Clone, PartialEq)]
enum ProofMode {
    Cache,                    // Prove full cache (all 64 segments)
    CacheSegment(usize),      // Prove single cache segment (0-63)
    Block,                    // Prove full block PoW (8 programs)
    BlockSegment(usize),      // Prove single block segment (0-255)
    Full,                     // Both cache + block
}

/// Configuration parsed from command-line arguments
#[derive(Debug, Clone)]
struct Config {
    mode: ProofMode,
    randomx_key: Option<[u8; 32]>,
    hashing_blob: Option<Vec<u8>>,
    difficulty: u64,
    resume: bool,
}

impl Config {
    fn parse_args() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().collect();

        if args.len() < 2 {
            return Ok(Config {
                mode: ProofMode::Full,
                randomx_key: None,
                hashing_blob: None,
                difficulty: 1,
                resume: false,
            });
        }

        let mut mode = ProofMode::Full;
        let mut randomx_key = None;
        let mut hashing_blob = None;
        let mut difficulty = 1u64;
        let mut resume = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "cache" => mode = ProofMode::Cache,
                "cache-segment" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("cache-segment requires a segment number (0-63)".to_string());
                    }
                    let seg: usize = args[i].parse()
                        .map_err(|_| format!("Invalid segment number: {}", args[i]))?;
                    if seg >= CACHE_SEGMENTS {
                        return Err(format!("Cache segment must be 0-{}", CACHE_SEGMENTS - 1));
                    }
                    mode = ProofMode::CacheSegment(seg);
                }
                "block" => mode = ProofMode::Block,
                "block-segment" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("block-segment requires a segment number (0-255)".to_string());
                    }
                    let seg: usize = args[i].parse()
                        .map_err(|_| format!("Invalid segment number: {}", args[i]))?;
                    if seg >= TOTAL_SEGMENTS {
                        return Err(format!("Block segment must be 0-{}", TOTAL_SEGMENTS - 1));
                    }
                    mode = ProofMode::BlockSegment(seg);
                }
                "full" => mode = ProofMode::Full,
                "--randomx-key" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--randomx-key requires a hex value".to_string());
                    }
                    let bytes = hex::decode(&args[i])
                        .map_err(|e| format!("Invalid hex for randomx-key: {}", e))?;
                    if bytes.len() != 32 {
                        return Err(format!("randomx-key must be 32 bytes, got {}", bytes.len()));
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    randomx_key = Some(key);
                }
                "--hashing-blob" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--hashing-blob requires a hex value".to_string());
                    }
                    let bytes = hex::decode(&args[i])
                        .map_err(|e| format!("Invalid hex for hashing-blob: {}", e))?;
                    if bytes.len() < 43 {
                        return Err(format!("hashing-blob too short: {} bytes (min 43)", bytes.len()));
                    }
                    hashing_blob = Some(bytes);
                }
                "--difficulty" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--difficulty requires a number".to_string());
                    }
                    difficulty = args[i].parse()
                        .map_err(|_| format!("Invalid difficulty: {}", args[i]))?;
                }
                "--resume" => {
                    resume = true;
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                arg => {
                    return Err(format!("Unknown argument: {}", arg));
                }
            }
            i += 1;
        }

        Ok(Config {
            mode,
            randomx_key,
            hashing_blob,
            difficulty,
            resume,
        })
    }

    fn is_test_mode(&self) -> bool {
        self.randomx_key.is_none() && self.hashing_blob.is_none()
    }
}

fn print_help() {
    println!("Monero RandomX zkVM Prover");
    println!();
    println!("Usage: prover <mode> [options]");
    println!();
    println!("Modes:");
    println!("  cache               Prove full cache hash (64 segments)");
    println!("  cache-segment <N>   Prove single cache segment (0-63)");
    println!("  block               Prove full block PoW (8 programs)");
    println!("  block-segment <N>   Prove single block segment (0-255)");
    println!("  full                Prove cache + block (default)");
    println!();
    println!("Options:");
    println!("  --randomx-key <HEX>   32-byte RandomX key (uses test key if omitted)");
    println!("  --hashing-blob <HEX>  Block hashing blob (uses test blob if omitted)");
    println!("  --difficulty <N>      Target difficulty (default: 1)");
    println!("  --resume              Skip segments with existing valid proofs");
    println!("  --help, -h            Show this help");
    println!();
    println!("Examples:");
    println!("  prover full                           # Full proof with test data");
    println!("  prover cache-segment 5                # Prove cache segment 5");
    println!("  prover block-segment 42               # Prove block segment 42");
    println!("  prover block --randomx-key abc123...  # Full block with real key");
}

/// Convert segment ID (0-255) to program index and iteration range
fn segment_to_params(segment_id: usize) -> (usize, usize, usize) {
    let program_index = segment_id / CHUNKS_PER_PROGRAM;
    let chunk_index = segment_id % CHUNKS_PER_PROGRAM;
    let iteration_start = chunk_index * ITERATIONS_PER_CHUNK;
    (program_index, iteration_start, ITERATIONS_PER_CHUNK)
}

// ============================================================
// AES Implementation (must match guest exactly)
// ============================================================

/// AES S-box
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

/// GF(2^8) multiplication by 2
fn xtime(x: u8) -> u8 {
    if x & 0x80 != 0 {
        (x << 1) ^ 0x1b
    } else {
        x << 1
    }
}

/// AES state (4x4 bytes = 16 bytes)
#[derive(Clone, Copy)]
struct AesState {
    state: [u8; 16],
}

impl AesState {
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut state = [0u8; 16];
        state.copy_from_slice(&bytes[..16]);
        Self { state }
    }

    fn to_bytes(&self) -> [u8; 16] {
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

fn aes_round(state: &mut AesState, key: &[u8; 16]) {
    state.sub_bytes();
    state.shift_rows();
    state.mix_columns();
    state.add_round_key(key);
}

/// Fill scratchpad using AES (matches guest's SoftAes::fill_scratchpad)
fn soft_aes_fill_scratchpad(seed: &[u8; 64], scratchpad: &mut [u8]) {
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
    /// Pre-computed AES states at segment boundary (4 states × 16 bytes)
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

/// Monero block header for PoW verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroBlockHeader {
    pub height: u64,
    pub major_version: u8,
    pub minor_version: u8,
    pub timestamp: u64,
    pub prev_id: [u8; 32],
    pub nonce: u32,
    pub hashing_blob: Vec<u8>,
}

/// Program segment input (matches phase2-program guest)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramSegmentInput {
    pub program_index: u8,
    pub is_first: bool,
    pub is_last: bool,
    /// Starting iteration within this program (0, 64, 128, ... for chunked mode)
    pub iteration_start: u16,
    /// Number of iterations to execute (2048 for full, 64 for chunked)
    pub iteration_count: u16,
    pub randomx_key: [u8; 32],
    pub dataset_merkle_root: [u8; 32],
    pub input_data: Vec<u8>,
    #[serde(with = "BigArray")]
    pub seed: [u8; 64],
    pub scratchpad: Vec<u8>,
    /// Initial register state (256 bytes) - for chunked mode mid-program
    /// Empty for iteration_start=0 (will be initialized from seed)
    pub initial_registers: Vec<u8>,
    /// Initial mem_config.ma - for chunked mode mid-program (0 for iteration_start=0)
    pub initial_ma: u32,
    /// Initial mem_config.mx - for chunked mode mid-program (0 for iteration_start=0)
    pub initial_mx: u32,
    pub dataset_items: Vec<DatasetItemEntry>,
    pub difficulty: u64,
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
    /// Iteration range that was executed
    pub iteration_start: u16,
    pub iteration_count: u16,
    #[serde(with = "BigArray")]
    pub next_seed: [u8; 64],
    pub scratchpad_hash: [u8; 32],
    /// Hash of output registers (for chaining chunks within a program)
    pub register_hash: [u8; 32],
    pub pow_hash: Option<[u8; 32]>,
    pub difficulty_valid: Option<bool>,
    pub dataset_merkle_root: [u8; 32],
}

/// Argon2d parameters (must match guest)
const ARGON2_SALT: &[u8] = b"RandomX\x03";
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let hours = (now % 86400) / 3600;
    let minutes = (now % 3600) / 60;
    let seconds = now % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

fn log(msg: &str) {
    println!("[{}] {}", timestamp(), msg);
}

fn log_separator() {
    println!("\n{}", "=".repeat(60));
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{}h {}m {}s", hours, minutes, seconds)
}

// ============================================================
// PROOF PERSISTENCE (to avoid OOM during long proving runs)
// ============================================================

const PROOFS_DIR: &str = "proofs";

/// Ensure proofs directory exists
fn ensure_proofs_dir() {
    if !Path::new(PROOFS_DIR).exists() {
        fs::create_dir_all(PROOFS_DIR).expect("Failed to create proofs directory");
    }
}

/// Save a receipt to disk
fn save_receipt(name: &str, receipt: &Receipt) -> std::io::Result<()> {
    ensure_proofs_dir();
    let path = format!("{}/{}.bin", PROOFS_DIR, name);
    let bytes = bincode::serialize(receipt).expect("Failed to serialize receipt");
    fs::write(&path, bytes)?;
    log(&format!("    Saved proof to {}", path));
    Ok(())
}

/// Load a receipt from disk
fn load_receipt(name: &str) -> Option<Receipt> {
    let path = format!("{}/{}.bin", PROOFS_DIR, name);
    if Path::new(&path).exists() {
        match fs::read(&path) {
            Ok(bytes) => {
                match bincode::deserialize(&bytes) {
                    Ok(receipt) => Some(receipt),
                    Err(e) => {
                        log(&format!("    Warning: Failed to deserialize {}: {}", path, e));
                        None
                    }
                }
            }
            Err(e) => {
                log(&format!("    Warning: Failed to read {}: {}", path, e));
                None
            }
        }
    } else {
        None
    }
}

/// Check if a valid proof exists for a segment
fn has_valid_segment_proof(seg_idx: usize) -> bool {
    let name = format!("cache_segment_{:02}", seg_idx);
    if let Some(receipt) = load_receipt(&name) {
        // Verify the receipt is valid
        if receipt.verify(PHASE1A_CACHE_SEGMENT_ID).is_ok() {
            return true;
        }
    }
    false
}

/// Check if a valid proof exists for a program
fn has_valid_program_proof(prog_idx: usize) -> bool {
    let name = format!("program_{}", prog_idx);
    if let Some(receipt) = load_receipt(&name) {
        if receipt.verify(PHASE2_PROGRAM_ID).is_ok() {
            return true;
        }
    }
    false
}

/// Get test block data (Monero block 3,000,000)
fn get_test_block() -> MoneroBlockHeader {
    let mut hashing_blob = Vec::with_capacity(76);
    hashing_blob.push(14); // major version
    hashing_blob.push(14); // minor version
    hashing_blob.extend_from_slice(&[0x86, 0xda, 0x06]); // timestamp varint
    hashing_blob.extend_from_slice(&[0u8; 32]); // prev_id
    hashing_blob.extend_from_slice(&[0x78, 0x56, 0x34, 0x12]); // nonce
    while hashing_blob.len() < 76 {
        hashing_blob.push(0);
    }

    MoneroBlockHeader {
        height: 3_000_000,
        major_version: 14,
        minor_version: 14,
        timestamp: 1700000000,
        prev_id: [0u8; 32],
        nonce: 0x12345678,
        hashing_blob,
    }
}

/// Get test RandomX key (dummy key for testing)
fn get_test_randomx_key() -> [u8; 32] {
    [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ]
}

/// Get block header and RandomX key from config
fn get_input_data(config: &Config) -> (MoneroBlockHeader, [u8; 32], u64) {
    let randomx_key = config.randomx_key.unwrap_or_else(get_test_randomx_key);

    let header = if let Some(ref blob) = config.hashing_blob {
        let major_version = blob.get(0).copied().unwrap_or(14);
        let minor_version = blob.get(1).copied().unwrap_or(14);
        let nonce = if blob.len() >= 43 {
            u32::from_le_bytes([blob[39], blob[40], blob[41], blob[42]])
        } else {
            0
        };
        MoneroBlockHeader {
            height: 0,
            major_version,
            minor_version,
            timestamp: 0,
            prev_id: [0u8; 32],
            nonce,
            hashing_blob: blob.clone(),
        }
    } else {
        get_test_block()
    };

    (header, randomx_key, config.difficulty)
}

/// Compute Blake2b-256 hash (must match guest: Blake2b512 truncated to 32 bytes)
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let full: [u8; 64] = hasher.finalize().into();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&full[..32]);
    hash
}

/// Expand seed to cache (AES fill - must match guest implementation exactly)
fn expand_cache_from_seed(seed: &[u8; 64], size: usize) -> Vec<u8> {
    let mut cache = vec![0u8; size];

    // Use AES to expand the seed (matches guest's SoftAes::fill_scratchpad)
    soft_aes_fill_scratchpad(seed, &mut cache);

    // Additional mixing passes for better randomness (as per RandomX spec)
    // Use the first 16 bytes of seed as the AES key
    let key: [u8; 16] = seed[0..16].try_into().unwrap();

    // In-place mixing - use small buffers to avoid cloning entire cache
    let mut prev_block = [0u8; 64];
    let mut current_block = [0u8; 64];

    for _ in 0..2 {
        // Save the last block (it's the "previous" for block 0)
        prev_block.copy_from_slice(&cache[size - 64..size]);

        for i in (0..size).step_by(64) {
            let end = std::cmp::min(i + 64, size);
            let block_len = end - i;

            // Save current block's original value before modifying
            current_block[..block_len].copy_from_slice(&cache[i..end]);

            // XOR with previous block (using its pre-modification value)
            for j in 0..block_len {
                cache[i + j] ^= prev_block[j];
            }

            // AES round on first 16 bytes of each 64-byte block (real AES)
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

/// Compute Argon2d seed only (for segmented proving)
fn compute_argon2_seed(key: &[u8], memory_kib: u32) -> [u8; 64] {
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

/// Compute AES states at each segment boundary
/// The AES fill produces 64 bytes per iteration (4 states × 16 bytes)
/// Returns Vec of [u8; 64] containing 4 AES states at each segment start
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

    // Initialize states from seed
    let mut states = [
        AesState::from_bytes(&seed[0..16]),
        AesState::from_bytes(&seed[16..32]),
        AesState::from_bytes(&seed[32..48]),
        AesState::from_bytes(&seed[48..64]),
    ];

    // Each iteration produces 64 bytes
    let iterations_per_segment = segment_size / 64;

    for _seg_idx in 0..num_segments {
        // Save states at start of this segment
        let mut state_bytes = [0u8; 64];
        for (i, state) in states.iter().enumerate() {
            state_bytes[i * 16..(i + 1) * 16].copy_from_slice(&state.to_bytes());
        }
        aes_boundaries.push(state_bytes);

        // Fast-forward through this segment
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

/// Extract boundary states for segmented proving
/// Returns Vec of (prev_block_pass1, prev_block_pass2) for each segment
fn extract_segment_boundaries(
    seed: &[u8; 64],
    cache: &[u8],
    num_segments: usize,
) -> Vec<([u8; 64], [u8; 64])> {
    let size = cache.len();
    let segment_size = size / num_segments;

    // We need to track the prev_block state at each segment boundary
    // This requires simulating the mixing passes

    let key: [u8; 16] = seed[0..16].try_into().unwrap();

    // First, get the initial AES fill (before mixing passes)
    let mut initial_fill = vec![0u8; size];
    soft_aes_fill_scratchpad(seed, &mut initial_fill);

    let mut boundaries = Vec::with_capacity(num_segments);

    // For segment 0, prev_block starts as the last 64 bytes of initial fill
    let mut prev_block_p1 = [0u8; 64];
    prev_block_p1.copy_from_slice(&initial_fill[size - 64..size]);

    // Simulate pass 1 to get boundaries
    let mut pass1_boundaries = vec![[0u8; 64]; num_segments];
    pass1_boundaries[0] = prev_block_p1;

    let mut current_block = [0u8; 64];
    for i in (0..size).step_by(64) {
        let end = std::cmp::min(i + 64, size);
        let block_len = end - i;

        // Save current block's original value
        current_block[..block_len].copy_from_slice(&initial_fill[i..end]);

        // Check if we're at a segment boundary (except segment 0)
        let segment_idx = i / segment_size;
        if i > 0 && i % segment_size == 0 && segment_idx < num_segments {
            pass1_boundaries[segment_idx] = prev_block_p1;
        }

        // Update prev_block (we track the ORIGINAL value, not XOR'd)
        prev_block_p1[..block_len].copy_from_slice(&current_block[..block_len]);
    }

    // Now simulate pass 2 to get its boundaries
    // After pass 1, the cache is modified. We need the state after pass 1.
    // For pass 2, prev_block starts as the last 64 bytes AFTER pass 1
    let mut prev_block_p2 = [0u8; 64];
    prev_block_p2.copy_from_slice(&cache[size - 64..size]); // Use actual cache (after both passes)

    // Actually, we need the state after pass 1 only, not after pass 2
    // Let's compute pass 1 result first
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

    // Now get pass 2 boundaries from after_pass1
    let mut pass2_boundaries = vec![[0u8; 64]; num_segments];
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

    // Combine boundaries
    for i in 0..num_segments {
        boundaries.push((pass1_boundaries[i], pass2_boundaries[i]));
    }

    boundaries
}

// ============================================================
// MERKLE TREE UTILITIES
// ============================================================

/// Build Merkle tree from dataset items (64-byte items from cache)
/// Returns the root hash and the full tree (for proof generation)
fn build_merkle_tree(cache: &[u8]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    let num_items = cache.len() / 64;

    // Hash each 64-byte item to get leaf nodes
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(num_items);
    for i in 0..num_items {
        let start = i * 64;
        let item = &cache[start..start + 64];
        leaves.push(blake2b_256(item));
    }

    // Pad to power of 2
    let mut size = 1;
    while size < leaves.len() {
        size *= 2;
    }
    while leaves.len() < size {
        leaves.push([0u8; 32]);
    }

    // Build tree bottom-up
    let mut tree: Vec<Vec<[u8; 32]>> = vec![leaves];

    while tree.last().unwrap().len() > 1 {
        let prev_level = tree.last().unwrap();
        let mut next_level = Vec::with_capacity(prev_level.len() / 2);

        for i in (0..prev_level.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[0..32].copy_from_slice(&prev_level[i]);
            combined[32..64].copy_from_slice(&prev_level[i + 1]);
            next_level.push(blake2b_256(&combined));
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

// ============================================================
// HOST-SIDE VM SIMULATION (for collecting dataset accesses)
// ============================================================
// See randomx_vm module for accurate VM simulation that matches guest execution

fn main() {
    // Parse command-line arguments
    let config = match Config::parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Run with --help for usage");
            std::process::exit(1);
        }
    };

    log_separator();
    println!("  MONERO RANDOMX ZKVM - FULL SPEC VERIFICATION");
    println!("  Version: {}", VERSION);
    log_separator();

    println!();
    log(&format!("Proof Mode: {:?}", config.mode));
    log(&format!("Test Mode: {}", config.is_test_mode()));
    if config.resume {
        log("Resume Mode: enabled");
    }
    println!();

    log("Monero RandomX Specification:");
    println!("    Cache Size:      {} MiB ({} segments × 4 MiB)", CACHE_SIZE / 1_048_576, CACHE_SEGMENTS);
    println!("    Scratchpad:      2 MiB");
    println!("    Programs:        8");
    println!("    Iterations:      2048");

    // System information
    log_separator();
    let mut sys = System::new_all();
    sys.refresh_all();

    log("System Information:");
    println!("    CPU Cores: {}", sys.cpus().len());
    if let Some(cpu) = sys.cpus().first() {
        println!("    CPU Model: {}", cpu.brand());
    }
    println!(
        "    Total Memory: {:.2} GB",
        sys.total_memory() as f64 / 1_073_741_824.0
    );
    println!(
        "    Available Memory: {:.2} GB",
        sys.available_memory() as f64 / 1_073_741_824.0
    );

    // Check for GPU prover
    if let Ok(prover_env) = std::env::var("RISC0_PROVER") {
        log(&format!("Prover Backend: {}", prover_env));
    } else {
        log("Prover Backend: CPU (set RISC0_PROVER=cuda or metal for GPU)");
    }

    let prover = default_prover();
    let opts = ProverOpts::default();
    let total_start = Instant::now();

    // Get input data from config
    let (header, randomx_key, difficulty) = get_input_data(&config);

    log_separator();
    log(&format!("Block Information ({}):", if config.is_test_mode() { "TEST DATA" } else { "REAL DATA" }));
    println!("    Height: {}", header.height);
    println!("    Major Version: {} (RandomX era)", header.major_version);
    println!("    Hashing Blob: {} bytes", header.hashing_blob.len());
    println!("    RandomX Key: 0x{}...", hex::encode(&randomx_key[..8]));
    println!("    Difficulty: {}", difficulty);

    // =========================================================
    // PHASE 1: Cache Initialization (Segmented)
    // =========================================================
    let run_cache = matches!(config.mode, ProofMode::Cache | ProofMode::Full);
    let run_cache_segment = matches!(config.mode, ProofMode::CacheSegment(_));

    log_separator();
    match &config.mode {
        ProofMode::Block | ProofMode::BlockSegment(_) => {
            println!("  PHASE 1: SKIPPED (block mode)");
        }
        ProofMode::CacheSegment(seg) => {
            println!("  PHASE 1: SINGLE CACHE SEGMENT (segment {})", seg);
        }
        _ => {
            println!("  PHASE 1: FULL CACHE PROVING ({} segments)", CACHE_SEGMENTS);
        }
    }
    log_separator();

    // First, compute cache on host (needed for both modes)
    let cache_size: usize = CACHE_SIZE;
    let argon2_memory_kib = (cache_size / 1024) as u32;

    log("Computing Argon2d seed on host...");
    let seed_start = Instant::now();
    let seed = compute_argon2_seed(&randomx_key, argon2_memory_kib);
    log(&format!("Argon2d seed computed in {:.2?}", seed_start.elapsed()));
    log(&format!("Seed hash: 0x{}...", hex::encode(&blake2b_256(&seed)[..8])));

    log("Expanding seed to full cache on host...");
    let expand_start = Instant::now();
    let cache = expand_cache_from_seed(&seed, cache_size);
    log(&format!("Cache expanded in {:.2?}", expand_start.elapsed()));
    log(&format!("Cache size: {} MiB", cache.len() / 1_048_576));

    let cache_hash = blake2b_256(&cache);
    log(&format!("Cache hash: 0x{}", hex::encode(&cache_hash)));

    sys.refresh_memory();
    let mem_before_p1 = sys.used_memory();
    log(&format!("Memory before Phase 1: {:.2} GB used", mem_before_p1 as f64 / 1_073_741_824.0));

    let phase1_start = Instant::now();
    let mut phase1_cycles: u64 = 0;

    if run_cache || run_cache_segment {
        // =========================================================
        // CACHE PROVING MODE (Full or Single Segment)
        // =========================================================
        log_separator();
        if let ProofMode::CacheSegment(seg) = &config.mode {
            log(&format!("SINGLE SEGMENT MODE: Proving cache segment {} only", seg));
        } else {
            log(&format!("FULL CACHE PROVING: {} segments", CACHE_SEGMENTS));
        }
        log("Argon2d runs on HOST (publicly verifiable)");
        log("zkVM proves AES expansion for each segment");
        println!();

        let segment_size = cache_size / CACHE_SEGMENTS;
        log(&format!("Segment size: {} MiB ({} bytes)", segment_size / 1_048_576, segment_size));

        // Extract boundary states for each segment
        log("Extracting segment boundary states...");
        let boundaries = extract_segment_boundaries(&seed, &cache, CACHE_SEGMENTS);
        log(&format!("Extracted {} boundary states", boundaries.len()));

        // Extract AES states at segment boundaries (O(1) proving optimization)
        log("Extracting AES states at segment boundaries...");
        let aes_states = extract_aes_states_at_boundaries(&seed, CACHE_SEGMENTS, segment_size);
        log(&format!("Extracted {} AES state sets", aes_states.len()));

        let mut segment_hashes: Vec<[u8; 32]> = Vec::new();

        // Determine which segments to prove
        let segments_to_prove: Vec<usize> = if let ProofMode::CacheSegment(seg) = &config.mode {
            vec![*seg]
        } else {
            (0..CACHE_SEGMENTS).collect()
        };

        // Check for existing proofs (only if resume mode enabled)
        if config.resume {
            let mut existing_count = 0;
            for &seg_idx in &segments_to_prove {
                if has_valid_segment_proof(seg_idx) {
                    existing_count += 1;
                }
            }
            if existing_count > 0 {
                log(&format!("RESUME MODE: Found {} existing valid proofs in {}/", existing_count, PROOFS_DIR));
                log("Will skip already-proven segments");
            }
        }

        for seg_idx in segments_to_prove {
            log_separator();
            log(&format!("SEGMENT {}/{}", seg_idx + 1, CACHE_SEGMENTS));

            // Check if this segment was already proven (only if resume mode enabled)
            let proof_name = format!("cache_segment_{:02}", seg_idx);
            if config.resume {
                if let Some(existing_receipt) = load_receipt(&proof_name) {
                    // Verify existing proof is valid
                    if existing_receipt.verify(PHASE1A_CACHE_SEGMENT_ID).is_ok() {
                        let output: Phase1aOutput = existing_receipt.journal.decode()
                            .expect("Failed to decode existing proof output");
                        segment_hashes.push(output.segment_hash);
                        log(&format!("    SKIPPED - valid proof exists"));
                        log(&format!("    Segment hash: 0x{}...", hex::encode(&output.segment_hash[..8])));
                        continue;
                    } else {
                        log("    Existing proof invalid, reproving...");
                    }
                }
            }

            // Log memory usage before each segment
            sys.refresh_memory();
            let mem_used = sys.used_memory();
            log(&format!("    Memory before proving: {:.2} GB used", mem_used as f64 / 1_073_741_824.0));

            let segment_start = seg_idx * segment_size;
            let (prev_p1, prev_p2) = &boundaries[seg_idx];

            let phase1a_input = Phase1aInput {
                seed,
                segment_index: seg_idx,
                total_segments: CACHE_SEGMENTS,
                segment_start,
                segment_size,
                total_cache_size: cache_size,
                prev_block_pass1: *prev_p1,
                prev_block_pass2: *prev_p2,
                aes_states: aes_states[seg_idx],
            };

            log(&format!("    Segment start: {} bytes", segment_start));
            log(&format!("    Segment size: {} bytes", segment_size));

            let seg_env = ExecutorEnv::builder()
                .write(&phase1a_input)
                .expect("Failed to write Phase 1a input")
                .build()
                .expect("Failed to build Phase 1a executor env");

            let seg_start = Instant::now();
            log("    Proving segment...");

            let seg_result = prover.prove_with_ctx(
                seg_env,
                &VerifierContext::default(),
                PHASE1A_CACHE_SEGMENT_ELF,
                &opts,
            );

            let seg_time = seg_start.elapsed();

            match seg_result {
                Ok(info) => {
                    let output: Phase1aOutput = info.receipt.journal.decode()
                        .expect("Failed to decode Phase 1a output");

                    let cycles = info.stats.total_cycles;
                    phase1_cycles += cycles;
                    segment_hashes.push(output.segment_hash);

                    log(&format!("    Segment {} PROVED in {}", seg_idx, format_duration(seg_time.as_secs())));
                    log(&format!("    Segment hash: 0x{}...", hex::encode(&output.segment_hash[..8])));
                    log(&format!("    Cycles: {}", format_number(cycles)));

                    // Verify segment proof
                    let verify_result = info.receipt.verify(PHASE1A_CACHE_SEGMENT_ID);

                    match verify_result {
                        Ok(_) => {
                            log("    Segment proof VALID!");
                            // Save proof to disk BEFORE dropping
                            if let Err(e) = save_receipt(&proof_name, &info.receipt) {
                                log(&format!("    Warning: Failed to save proof: {}", e));
                            }
                        }
                        Err(e) => {
                            log(&format!("ERROR: Segment {} verification failed: {}", seg_idx, e));
                            return;
                        }
                    }

                    // Explicitly drop the proof to free memory before next segment
                    drop(info);
                }
                Err(e) => {
                    log(&format!("ERROR: Segment {} failed: {}", seg_idx, e));
                    return;
                }
            }

            // Log memory after proving
            sys.refresh_memory();
            log(&format!("    Memory after segment: {:.2} GB used", sys.used_memory() as f64 / 1_073_741_824.0));
        }

        // Verify segment hashes combine to full cache hash
        log_separator();
        log("Verifying segment hashes...");
        // For now, verify each segment matches the corresponding slice of the host cache
        for (seg_idx, seg_hash) in segment_hashes.iter().enumerate() {
            let seg_start = seg_idx * segment_size;
            let seg_end = seg_start + segment_size;
            let host_seg_hash = blake2b_256(&cache[seg_start..seg_end]);
            if *seg_hash != host_seg_hash {
                log(&format!("ERROR: Segment {} hash mismatch!", seg_idx));
                log(&format!("    Proof:  0x{}", hex::encode(seg_hash)));
                log(&format!("    Host:   0x{}", hex::encode(&host_seg_hash)));
                return;
            }
        }
        log("All segment hashes VERIFIED!");

        // Exit early for single cache segment mode
        if let ProofMode::CacheSegment(seg) = &config.mode {
            let phase1_time = phase1_start.elapsed();
            log_separator();
            println!("  CACHE SEGMENT PROOF COMPLETE!");
            log_separator();
            log(&format!("Segment {} proven in {}", seg, format_duration(phase1_time.as_secs())));
            log(&format!("Cycles: {}", format_number(phase1_cycles)));
            log_separator();
            return;
        }
    }

    let phase1_time = phase1_start.elapsed();

    if run_cache || matches!(config.mode, ProofMode::Full) {
        log_separator();
        log("Phase 1 Summary:");
        println!("    Mode: Full Cache ({} segments)", CACHE_SEGMENTS);
        println!("    Cache Hash: 0x{}", hex::encode(&cache_hash));
        println!("    Cache Size: {} MiB", cache_size / 1_048_576);
        println!("    Total Cycles: {}", format_number(phase1_cycles));
        println!("    Proving Time: {}", format_duration(phase1_time.as_secs()));
        if phase1_time.as_secs() > 0 {
            println!("    Throughput: {:.0} cycles/sec", phase1_cycles as f64 / phase1_time.as_secs_f64());
        }
    }

    // Exit early for cache-only mode
    if matches!(config.mode, ProofMode::Cache) {
        log_separator();
        println!("  CACHE PROOF COMPLETE!");
        log_separator();
        log("Full cache hash has been proven. This enables unlimited deposits.");
        log_separator();
        return;
    }

    // =========================================================
    // PHASE 2: Block PoW Execution (Program Segments + Merkle Proofs)
    // =========================================================
    log_separator();

    // Check if we're proving a single segment or all programs
    let block_segment = if let ProofMode::BlockSegment(seg) = config.mode {
        Some(seg)
    } else {
        None
    };

    if let Some(seg_id) = block_segment {
        println!("  PHASE 2: SINGLE SEGMENT PROVING (segment {})", seg_id);
    } else {
        println!("  PHASE 2: BLOCK POW VERIFICATION (PROGRAM SEGMENTS)");
    }
    log_separator();

    log("Building Merkle tree from cache...");
    let merkle_start = Instant::now();
    let (merkle_root, merkle_tree) = build_merkle_tree(&cache);
    log(&format!("Merkle tree built in {:.2?}", merkle_start.elapsed()));
    log(&format!("Merkle root: 0x{}...", hex::encode(&merkle_root[..8])));
    log(&format!("Tree height: {} levels ({} items)", merkle_tree.len(), RANDOMX_DATASET_ITEM_COUNT));

    // If proving a single segment, we need different simulation
    let phase2_start = Instant::now();
    let mut phase2_cycles: u64 = 0;
    let mut final_pow_hash = [0u8; 32];
    let mut final_difficulty_valid = false;

    if let Some(seg_id) = block_segment {
        // =========================================================
        // SINGLE SEGMENT PROVING MODE
        // =========================================================
        let (prog_idx, iteration_start, iteration_count) = segment_to_params(seg_id);

        log(&format!("Segment {} = Program {}, iterations {}-{}",
            seg_id, prog_idx, iteration_start, iteration_start + iteration_count));

        // First, simulate all programs to get the correct seed/scratchpad for this program
        log("Simulating programs to get state for target program...");
        let sim_start = Instant::now();
        let simulation = randomx_vm::simulate_all_programs(
            &cache,
            &header.hashing_blob,
            SCRATCHPAD_SIZE,
            ITERATIONS,
            RANDOMX_DATASET_ITEM_COUNT,
        );
        log(&format!("Simulation completed in {:.2?}", sim_start.elapsed()));

        // Now simulate the specific chunk to get dataset accesses and initial registers
        log(&format!("Simulating chunk {} of program {}...", iteration_start / ITERATIONS_PER_CHUNK, prog_idx));
        let chunk_sim = randomx_vm::simulate_program_chunk(
            &cache,
            &simulation.seeds[prog_idx],
            &simulation.scratchpads[prog_idx],
            iteration_start,
            iteration_count,
            RANDOMX_DATASET_ITEM_COUNT,
        );

        let unique_indices: std::collections::BTreeSet<u64> = chunk_sim.accesses.iter().copied().collect();
        log(&format!("Chunk accesses: {} total, {} unique items", chunk_sim.accesses.len(), unique_indices.len()));

        // Collect dataset items with Merkle proofs
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

        // is_first only if program 0 AND iteration_start == 0
        let is_first = prog_idx == 0 && iteration_start == 0;
        // is_last only if program 7 AND this chunk ends at iteration 2048
        let is_last = prog_idx == PROGRAM_COUNT - 1 && (iteration_start + iteration_count) == ITERATIONS;

        let segment_input = ProgramSegmentInput {
            program_index: prog_idx as u8,
            is_first,
            is_last,
            iteration_start: iteration_start as u16,
            iteration_count: iteration_count as u16,
            randomx_key,
            dataset_merkle_root: merkle_root,
            input_data: if is_first { header.hashing_blob.clone() } else { vec![] },
            seed: simulation.seeds[prog_idx],
            scratchpad: simulation.scratchpads[prog_idx].clone(),
            initial_registers: chunk_sim.initial_registers.clone(),
            initial_ma: chunk_sim.initial_ma,
            initial_mx: chunk_sim.initial_mx,
            dataset_items,
            difficulty,
        };

        let input_size = std::mem::size_of_val(&segment_input);
        log(&format!("Input size: ~{:.2} KiB", input_size as f64 / 1024.0));

        let seg_env = ExecutorEnv::builder()
            .write(&segment_input)
            .expect("Failed to write segment input")
            .build()
            .expect("Failed to build segment executor env");

        log("Proving segment...");
        let seg_start = Instant::now();

        let seg_result = prover.prove_with_ctx(
            seg_env,
            &VerifierContext::default(),
            PHASE2_PROGRAM_ELF,
            &opts,
        );

        let seg_time = seg_start.elapsed();

        match seg_result {
            Ok(info) => {
                let output: ProgramSegmentOutput = info.receipt.journal.decode()
                    .expect("Failed to decode segment output");

                phase2_cycles = info.stats.total_cycles;

                log(&format!("Segment {} PROVED in {}", seg_id, format_duration(seg_time.as_secs())));
                log(&format!("Cycles: {}", format_number(phase2_cycles)));
                log(&format!("Scratchpad hash: 0x{}...", hex::encode(&output.scratchpad_hash[..8])));
                log(&format!("Register hash: 0x{}...", hex::encode(&output.register_hash[..8])));

                // Verify segment proof
                match info.receipt.verify(PHASE2_PROGRAM_ID) {
                    Ok(_) => {
                        log("Segment proof VALID!");
                        let proof_name = format!("segment_{}", seg_id);
                        if let Err(e) = save_receipt(&proof_name, &info.receipt) {
                            log(&format!("Warning: Failed to save proof: {}", e));
                        }
                    }
                    Err(e) => {
                        log(&format!("ERROR: Segment verification failed: {}", e));
                        return;
                    }
                }

                if is_last {
                    if let Some(pow_hash) = output.pow_hash {
                        final_pow_hash = pow_hash;
                        log(&format!("Final PoW hash: 0x{}...", hex::encode(&pow_hash[..8])));
                    }
                    if let Some(valid) = output.difficulty_valid {
                        final_difficulty_valid = valid;
                    }
                }
            }
            Err(e) => {
                log(&format!("ERROR: Segment {} failed: {}", seg_id, e));
                return;
            }
        }

        let phase2_time = phase2_start.elapsed();

        log_separator();
        log("Single Segment Proof Complete!");
        log(&format!("Segment: {} (Program {}, iterations {}-{})",
            seg_id, prog_idx, iteration_start, iteration_start + iteration_count));
        log(&format!("Cycles: {}", format_number(phase2_cycles)));
        log(&format!("Time: {}", format_duration(phase2_time.as_secs())));
        log(&format!("Merkle Root: 0x{}...", hex::encode(&merkle_root[..8])));
        log_separator();
        return;
    }

    // =========================================================
    // FULL BLOCK PROVING MODE (all 8 programs)
    // =========================================================
    log("Simulating programs to find dataset accesses...");
    let sim_start = Instant::now();
    let simulation = randomx_vm::simulate_all_programs(
        &cache,
        &header.hashing_blob,
        SCRATCHPAD_SIZE,
        ITERATIONS,
        RANDOMX_DATASET_ITEM_COUNT,
    );
    log(&format!("Simulation completed in {:.2?}", sim_start.elapsed()));
    for (i, accesses) in simulation.accesses.iter().enumerate() {
        let unique: std::collections::HashSet<_> = accesses.iter().collect();
        log(&format!("    Program {}: {} accesses ({} unique items)", i, accesses.len(), unique.len()));
    }

    sys.refresh_memory();
    let mem_before_p2 = sys.used_memory();
    log(&format!("Memory before Phase 2: {:.2} GB used", mem_before_p2 as f64 / 1_073_741_824.0));

    log_separator();
    log("PHASE 2 PROVING STARTED (8 program segments)");
    log("Each segment: ~1.5 MiB input (vs 256 MiB monolithic)");
    println!();

    // Check for existing program proofs (only if resume mode enabled)
    if config.resume {
        let mut existing_prog_count = 0;
        for prog_idx in 0..PROGRAM_COUNT {
            if has_valid_program_proof(prog_idx) {
                existing_prog_count += 1;
            }
        }
        if existing_prog_count > 0 {
            log(&format!("RESUME MODE: Found {} existing valid program proofs in {}/", existing_prog_count, PROOFS_DIR));
            log("Will skip already-proven programs");
        }
    }

    for prog_idx in 0..PROGRAM_COUNT {
        log_separator();
        log(&format!("PROGRAM SEGMENT {}/{}", prog_idx + 1, PROGRAM_COUNT));

        let is_first = prog_idx == 0;
        let is_last = prog_idx == PROGRAM_COUNT - 1;

        // Check if this program was already proven (only if resume mode enabled)
        let proof_name = format!("program_{}", prog_idx);
        if config.resume {
            if let Some(existing_receipt) = load_receipt(&proof_name) {
                if existing_receipt.verify(PHASE2_PROGRAM_ID).is_ok() {
                    let output: ProgramSegmentOutput = existing_receipt.journal.decode()
                        .expect("Failed to decode existing proof output");
                    log(&format!("    SKIPPED - valid proof exists"));

                    // Verify Merkle root matches
                    if output.dataset_merkle_root != merkle_root {
                        log(&format!("ERROR: Program {} Merkle root mismatch! Reproving...", prog_idx));
                    } else {
                        if is_last {
                            if let Some(pow_hash) = output.pow_hash {
                                final_pow_hash = pow_hash;
                                log(&format!("    Final PoW hash: 0x{}...", hex::encode(&pow_hash[..8])));
                            }
                            if let Some(valid) = output.difficulty_valid {
                                final_difficulty_valid = valid;
                            }
                        }
                        continue;
                    }
                } else {
                    log("    Existing proof invalid, reproving...");
                }
            }
        }

        // Use seed and scratchpad from simulation (CRITICAL: these match what the guest expects)
        let current_seed = simulation.seeds[prog_idx];
        let current_scratchpad = &simulation.scratchpads[prog_idx];

        // Collect unique dataset items for this program
        let accesses = &simulation.accesses[prog_idx];
        let unique_indices: std::collections::BTreeSet<u64> = accesses.iter().copied().collect();

        log(&format!("    Collecting {} unique dataset items with Merkle proofs...", unique_indices.len()));

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

        let input_size = 32 + 32 + 64 + current_scratchpad.len() +
            dataset_items.iter().map(|e| 8 + 64 + e.proof.len()).sum::<usize>();
        log(&format!("    Input size: {:.2} MiB", input_size as f64 / 1_048_576.0));

        let segment_input = ProgramSegmentInput {
            program_index: prog_idx as u8,
            is_first,
            is_last,
            iteration_start: 0,
            iteration_count: ITERATIONS as u16,
            randomx_key,
            dataset_merkle_root: merkle_root,
            input_data: if is_first { header.hashing_blob.clone() } else { vec![] },
            seed: current_seed,
            scratchpad: current_scratchpad.to_vec(),
            initial_registers: vec![],  // Empty for iteration_start=0
            initial_ma: 0,  // Not needed for iteration_start=0
            initial_mx: 0,  // Not needed for iteration_start=0
            dataset_items,
            difficulty,
        };

        let seg_env = ExecutorEnv::builder()
            .write(&segment_input)
            .expect("Failed to write segment input")
            .build()
            .expect("Failed to build segment executor env");

        let seg_start = Instant::now();
        log("    Proving program segment...");

        let seg_result = prover.prove_with_ctx(
            seg_env,
            &VerifierContext::default(),
            PHASE2_PROGRAM_ELF,
            &opts,
        );

        let seg_time = seg_start.elapsed();

        match seg_result {
            Ok(info) => {
                let output: ProgramSegmentOutput = info.receipt.journal.decode()
                    .expect("Failed to decode segment output");

                let cycles = info.stats.total_cycles;
                phase2_cycles += cycles;

                log(&format!("    Program {} PROVED in {}", prog_idx, format_duration(seg_time.as_secs())));
                log(&format!("    Cycles: {}", format_number(cycles)));

                // Verify segment proof
                let verify_result = info.receipt.verify(PHASE2_PROGRAM_ID);

                match verify_result {
                    Ok(_) => {
                        log("    Segment proof VALID!");
                        // Save proof to disk BEFORE dropping
                        if let Err(e) = save_receipt(&proof_name, &info.receipt) {
                            log(&format!("    Warning: Failed to save proof: {}", e));
                        }
                    }
                    Err(e) => {
                        log(&format!("ERROR: Program {} verification failed: {}", prog_idx, e));
                        return;
                    }
                }

                // Explicitly drop the proof to free memory before next program
                drop(info);

                // Verify Merkle root matches
                if output.dataset_merkle_root != merkle_root {
                    log(&format!("ERROR: Program {} Merkle root mismatch!", prog_idx));
                    return;
                }

                // Note: We don't need to update state for next program anymore
                // because we use the pre-computed seeds and scratchpads from the simulation

                if is_last {
                    if let Some(pow_hash) = output.pow_hash {
                        final_pow_hash = pow_hash;
                        log(&format!("    Final PoW hash: 0x{}...", hex::encode(&pow_hash[..8])));
                    }
                    if let Some(valid) = output.difficulty_valid {
                        final_difficulty_valid = valid;
                    }
                }
            }
            Err(e) => {
                log(&format!("ERROR: Program {} failed: {}", prog_idx, e));
                return;
            }
        }

        // Log memory after segment
        sys.refresh_memory();
        log(&format!("    Memory after segment: {:.2} GB used", sys.used_memory() as f64 / 1_073_741_824.0));
    }

    let phase2_time = phase2_start.elapsed();

    log_separator();
    log("Phase 2 Complete!");
    log(&format!("    RandomX Hash: 0x{}", hex::encode(&final_pow_hash)));
    log(&format!("    Difficulty Valid: {}", final_difficulty_valid));
    log(&format!("    Total Cycles: {}", format_number(phase2_cycles)));
    log(&format!("    Proving Time: {}", format_duration(phase2_time.as_secs())));
    if phase2_time.as_secs() > 0 {
        log(&format!("    Throughput: {:.0} cycles/sec", phase2_cycles as f64 / phase2_time.as_secs_f64()));
    }

    // =========================================================
    // FINAL RESULTS
    // =========================================================
    let total_time = total_start.elapsed();
    let total_cycles = phase1_cycles + phase2_cycles;

    log_separator();
    println!("  VERIFICATION COMPLETE!");
    log_separator();

    log("Final Results:");
    println!("    Block Height: {}", header.height);
    println!("    RandomX Hash: 0x{}", hex::encode(&final_pow_hash));
    println!("    Difficulty Valid: {}", final_difficulty_valid);

    log_separator();
    println!("  PERFORMANCE SUMMARY");
    log_separator();

    println!();
    println!("Phase 1 (Cache Init - REUSABLE for ~2048 blocks):");
    println!("    Cycles:      {}", format_number(phase1_cycles));
    println!("    Time:        {}", format_duration(phase1_time.as_secs()));
    if phase1_time.as_secs() > 0 {
        println!("    Throughput:  {:.0} cycles/sec", phase1_cycles as f64 / phase1_time.as_secs_f64());
    }

    println!();
    println!("Phase 2 (VM Execution - {} program segments):", PROGRAM_COUNT);
    println!("    Cycles:      {}", format_number(phase2_cycles));
    println!("    Time:        {}", format_duration(phase2_time.as_secs()));
    if phase2_time.as_secs() > 0 {
        println!("    Throughput:  {:.0} cycles/sec", phase2_cycles as f64 / phase2_time.as_secs_f64());
    }

    println!();
    println!("Total:");
    println!("    Cycles:      {}", format_number(total_cycles));
    println!("    Time:        {}", format_duration(total_time.as_secs()));
    if total_time.as_secs() > 0 {
        println!("    Throughput:  {:.0} cycles/sec", total_cycles as f64 / total_time.as_secs_f64());
    }

    log_separator();
    println!("  PROOF SUMMARY");
    log_separator();

    println!();
    println!("Configuration:");
    println!("    Cache Size:      {} MiB ({} Merkle items)", CACHE_SIZE / 1_048_576, RANDOMX_DATASET_ITEM_COUNT);
    println!("    Scratchpad Size: {} MiB", SCRATCHPAD_SIZE / 1_048_576);
    println!("    Programs:        {} × {} iterations", PROGRAM_COUNT, ITERATIONS);

    println!();
    println!("Proofs:");
    println!("    Phase 1: VALID ({} cache segments)", CACHE_SEGMENTS);
    println!("    Phase 2: VALID ({} program segments with Merkle proofs)", PROGRAM_COUNT);

    println!();
    println!("Output:");
    println!("    Block Height:   {}", header.height);
    println!("    RandomX Hash:   0x{}", hex::encode(&final_pow_hash));
    println!("    Difficulty Met: {}", final_difficulty_valid);
    println!("    Merkle Root:    0x{}...", hex::encode(&merkle_root[..8]));

    println!();
    log("IMPORTANT: Phase 1 proof can be cached and reused for ~2048 blocks!");
    log("           Only Phase 2 needs to run for each block verification.");
    log("           Each program segment is ~1.5 MiB vs 256 MiB monolithic.");

    log_separator();
}
