//! Merkle tree utilities for dataset item proofs
//!
//! Used to efficiently prove access to specific dataset items without
//! including the full 256 MiB cache in the proof.

use alloc::vec::Vec;
use super::blake2b::blake2b_256;

/// Merkle proof for a single dataset item
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// The dataset item index
    pub index: u64,
    /// The dataset item data (64 bytes)
    pub item: [u8; 64],
    /// Sibling hashes from leaf to root
    pub siblings: Vec<[u8; 32]>,
}

/// Compute the Merkle root from a list of dataset items
/// Items are 64 bytes each, hashed to 32 bytes for the tree
pub fn compute_merkle_root(items: &[[u8; 64]]) -> [u8; 32] {
    if items.is_empty() {
        return [0u8; 32];
    }

    // Hash each item to get leaf nodes
    let mut nodes: Vec<[u8; 32]> = items.iter().map(|item| blake2b_256(item)).collect();

    // Pad to power of 2
    let mut size = 1;
    while size < nodes.len() {
        size *= 2;
    }
    while nodes.len() < size {
        nodes.push([0u8; 32]);
    }

    // Build tree bottom-up
    while nodes.len() > 1 {
        let mut next_level = Vec::with_capacity(nodes.len() / 2);
        for i in (0..nodes.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[0..32].copy_from_slice(&nodes[i]);
            combined[32..64].copy_from_slice(&nodes[i + 1]);
            next_level.push(blake2b_256(&combined));
        }
        nodes = next_level;
    }

    nodes[0]
}

/// Verify a Merkle proof for a dataset item
pub fn verify_merkle_proof(
    root: &[u8; 32],
    proof: &MerkleProof,
    total_items: u64,
) -> bool {
    // Hash the item to get the leaf
    let mut current = blake2b_256(&proof.item);

    // Calculate tree height
    let height = (64 - (total_items - 1).leading_zeros()) as usize;

    if proof.siblings.len() != height {
        return false;
    }

    // Walk up the tree
    let mut index = proof.index;
    for sibling in &proof.siblings {
        let mut combined = [0u8; 64];
        if index % 2 == 0 {
            // Current is left child
            combined[0..32].copy_from_slice(&current);
            combined[32..64].copy_from_slice(sibling);
        } else {
            // Current is right child
            combined[0..32].copy_from_slice(sibling);
            combined[32..64].copy_from_slice(&current);
        }
        current = blake2b_256(&combined);
        index /= 2;
    }

    current == *root
}

/// Dataset item with its Merkle proof (for serialization)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DatasetItemWithProof {
    /// The dataset item index
    pub index: u64,
    /// The dataset item data (64 bytes)
    pub item: [u8; 64],
    /// Sibling hashes (flattened for easier serialization)
    /// Each hash is 32 bytes, tree height is ~22 for 4M items
    pub siblings: Vec<u8>,
}

impl DatasetItemWithProof {
    /// Get the sibling hashes as 32-byte arrays
    pub fn get_siblings(&self) -> Vec<[u8; 32]> {
        self.siblings
            .chunks(32)
            .map(|chunk| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk);
                arr
            })
            .collect()
    }

    /// Verify this item against a Merkle root
    pub fn verify(&self, root: &[u8; 32], total_items: u64) -> bool {
        let proof = MerkleProof {
            index: self.index,
            item: self.item,
            siblings: self.get_siblings(),
        };
        verify_merkle_proof(root, &proof, total_items)
    }
}
