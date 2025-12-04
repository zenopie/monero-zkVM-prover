//! Pure-Rust RandomX Implementation for zkVM
//!
//! This implements the RandomX proof-of-work algorithm in pure Rust,
//! suitable for compilation to RISC-V and execution in a zkVM.
//!
//! Reference: https://github.com/tevador/RandomX/blob/master/doc/specs.md

pub mod config;
pub mod aes;
pub mod argon2;
pub mod blake2b;
pub mod vm;
pub mod program;
pub mod scratchpad;
pub mod hash;
pub mod softfloat;
pub mod merkle;

pub use config::*;
pub use hash::{randomx_hash, randomx_hash_with_size, randomx_hash_with_cache_size, randomx_hash_minimal, verify_difficulty};
pub use merkle::{MerkleProof, DatasetItemWithProof, compute_merkle_root, verify_merkle_proof};
