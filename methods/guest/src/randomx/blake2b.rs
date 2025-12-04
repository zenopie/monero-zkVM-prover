//! Blake2b Generator for RandomX
//!
//! Provides a stateful generator that produces deterministic random bytes
//! using Blake2b hashing. Used for program generation.

use blake2::{Blake2b512, Digest};

/// Blake2b-based random generator
pub struct Blake2Generator {
    /// Current state (64 bytes)
    state: [u8; 64],
    /// Current position in state
    position: usize,
}

impl Blake2Generator {
    /// Create a new generator from seed
    pub fn new(seed: &[u8]) -> Self {
        let mut hasher = Blake2b512::new();
        hasher.update(seed);
        let state: [u8; 64] = hasher.finalize().into();
        Self { state, position: 0 }
    }

    /// Get next byte
    pub fn next_byte(&mut self) -> u8 {
        if self.position >= 64 {
            self.rehash();
        }
        let byte = self.state[self.position];
        self.position += 1;
        byte
    }

    /// Get next u32 (little-endian)
    pub fn next_u32(&mut self) -> u32 {
        let b0 = self.next_byte() as u32;
        let b1 = self.next_byte() as u32;
        let b2 = self.next_byte() as u32;
        let b3 = self.next_byte() as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    /// Get next u64 (little-endian)
    pub fn next_u64(&mut self) -> u64 {
        let lo = self.next_u32() as u64;
        let hi = self.next_u32() as u64;
        lo | (hi << 32)
    }

    /// Rehash state when exhausted
    fn rehash(&mut self) {
        let mut hasher = Blake2b512::new();
        hasher.update(&self.state);
        self.state = hasher.finalize().into();
        self.position = 0;
    }

    /// Fill buffer with random bytes
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next_byte();
        }
    }
}

/// Hash function for final result
pub fn blake2b_hash(data: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash with 256-bit output
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let full = blake2b_hash(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&full[..32]);
    result
}
