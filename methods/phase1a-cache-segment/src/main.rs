//! Phase 1a: Cache Segment Expansion
//!
//! This guest program proves correct AES expansion of one cache segment.
//! Multiple segments can be proven in parallel or sequentially.
//!
//! Input: seed, segment boundaries, chain state
//! Output: segment hash, chain state for next segment

#![no_main]
#![no_std]

extern crate alloc;

use guest::{blake2b_256, expand_cache_segment};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Input to Phase 1a (Cache Segment)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase1aInput {
    /// The 64-byte Argon2d seed
    #[serde(with = "BigArray")]
    pub seed: [u8; 64],
    /// Which segment this is (0-indexed)
    pub segment_index: usize,
    /// Total number of segments
    pub total_segments: usize,
    /// Starting byte offset in the full cache
    pub segment_start: usize,
    /// Size of this segment in bytes
    pub segment_size: usize,
    /// Total cache size in bytes
    pub total_cache_size: usize,
    /// State at start of this segment for mixing pass 1
    #[serde(with = "BigArray")]
    pub prev_block_pass1: [u8; 64],
    /// State at start of this segment for mixing pass 2
    #[serde(with = "BigArray")]
    pub prev_block_pass2: [u8; 64],
    /// AES states at segment start (4 states × 16 bytes each)
    /// Pre-computed by host to avoid O(N) fast-forward in guest
    #[serde(with = "BigArray")]
    pub aes_states: [u8; 64],
}

/// Output from Phase 1a (Cache Segment)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase1aOutput {
    /// Blake2b hash of this segment after expansion
    pub segment_hash: [u8; 32],
    /// Which segment this is
    pub segment_index: usize,
    /// Total number of segments
    pub total_segments: usize,
    /// Starting byte offset
    pub segment_start: usize,
    /// Size of this segment
    pub segment_size: usize,
    /// Hash of the seed (commitment)
    pub seed_hash: [u8; 32],
    /// Final state after pass 1 (for chain verification)
    #[serde(with = "BigArray")]
    pub final_prev_block_pass1: [u8; 64],
    /// Final state after pass 2 (for chain verification)
    #[serde(with = "BigArray")]
    pub final_prev_block_pass2: [u8; 64],
}

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read input from host
    let input: Phase1aInput = env::read();

    // Compute seed hash for commitment
    let seed_hash = blake2b_256(&input.seed);

    // Expand this segment using pre-computed AES states
    let (segment_data, final_p1, final_p2) = expand_cache_segment(
        &input.seed,
        input.segment_start,
        input.segment_size,
        input.total_cache_size,
        &input.prev_block_pass1,
        &input.prev_block_pass2,
        &input.aes_states,
    );

    // Hash the segment for verification
    let segment_hash = blake2b_256(&segment_data);

    // Commit output
    let output = Phase1aOutput {
        segment_hash,
        segment_index: input.segment_index,
        total_segments: input.total_segments,
        segment_start: input.segment_start,
        segment_size: input.segment_size,
        seed_hash,
        final_prev_block_pass1: final_p1,
        final_prev_block_pass2: final_p2,
    };

    env::commit(&output);
}
