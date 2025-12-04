//! Shared code for RandomX zkVM guests
//!
//! This library provides the RandomX implementation shared by all phase guests.

#![no_std]

extern crate alloc;

pub mod randomx;

// ============================================================
// MONERO RANDOMX SPECIFICATION
// ============================================================

/// Version string - UPDATE ALSO IN:
///   - Dockerfile.gpu-runtime (line ~74 and tag)
///   - deploy-akash-runtime.yaml (image tag)
///   - .github/workflows/docker-build-gpu-runtime.yml (tags)
pub const VERSION: &str = "v29";

// ----------------- FULL MONERO SPEC -----------------
// These are ALWAYS the full Monero spec values.

/// Cache size: 256 MiB
pub const CACHE_SIZE: usize = 268435456;
/// Segments: 64 × 4 MiB
pub const CACHE_SEGMENTS: usize = 64;
/// Scratchpad: 2 MiB
pub const SCRATCHPAD_SIZE: usize = 2097152;
/// Programs: 8
pub const PROGRAM_COUNT: usize = 8;
/// Iterations: 2048
pub const ITERATIONS: usize = 2048;

/// Dataset item count (for VM execution)
pub const RANDOMX_DATASET_ITEM_COUNT: usize = CACHE_SIZE / 64;

// ============================================================

// Re-export commonly used items
pub use randomx::aes::SoftAes;
pub use randomx::argon2::{
    init_cache, init_cache_with_size,
    compute_argon2_seed, expand_cache_segment, get_initial_fill_last_block,
};
pub use randomx::blake2b::{blake2b_256, blake2b_hash};
pub use randomx::config::*;
pub use randomx::program::{Program, SuperscalarProgram};
pub use randomx::scratchpad::{Cache, Scratchpad};
pub use randomx::vm::VmState;
pub use randomx::{randomx_hash, randomx_hash_minimal, verify_difficulty};
pub use randomx::merkle::{MerkleProof, DatasetItemWithProof, compute_merkle_root, verify_merkle_proof};
