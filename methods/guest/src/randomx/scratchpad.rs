//! RandomX Scratchpad and Dataset Operations
//!
//! Light mode: Computes dataset items on-the-fly from cache
//! Fast mode: Uses precomputed 2GB dataset
//!
//! We implement light mode as it's more suitable for zkVM (less memory).

use crate::randomx::aes::SoftAes;
use crate::randomx::argon2::{init_cache, init_cache_with_size};
use crate::randomx::blake2b::blake2b_hash;
use crate::randomx::config::*;
use crate::randomx::program::SuperscalarProgram;
use alloc::vec::Vec;

/// RandomX Cache (light mode)
/// This is used to compute dataset items on-the-fly
pub struct Cache {
    /// Cache memory (256 MiB for full RandomX)
    pub memory: Vec<u8>,
    /// Superscalar programs for dataset generation
    pub programs: Vec<SuperscalarProgram>,
}

impl Cache {
    /// Initialize cache from key using Argon2d
    /// This is the full RandomX cache initialization with 256 MiB
    pub fn new(key: &[u8]) -> Self {
        // Initialize cache using Argon2d (256 MiB)
        let memory = init_cache(key);

        // Hash the key for program generation
        let key_hash = blake2b_hash(key);

        // Generate superscalar programs
        let mut programs = Vec::with_capacity(8);
        for i in 0..8 {
            let mut prog_seed = key_hash;
            prog_seed[0] ^= i as u8;
            programs.push(SuperscalarProgram::generate(&prog_seed));
        }

        Self { memory, programs }
    }

    /// Initialize cache with custom size (for testing)
    pub fn new_with_size(key: &[u8], size: usize) -> Self {
        // Initialize cache using Argon2d with custom size
        let memory = init_cache_with_size(key, size);

        // Hash the key for program generation
        let key_hash = blake2b_hash(key);

        // Generate superscalar programs
        let mut programs = Vec::with_capacity(8);
        for i in 0..8 {
            let mut prog_seed = key_hash;
            prog_seed[0] ^= i as u8;
            programs.push(SuperscalarProgram::generate(&prog_seed));
        }

        Self { memory, programs }
    }

    /// Get a cache line (64 bytes)
    pub fn get_line(&self, index: usize) -> [u8; 64] {
        let offset = (index * 64) % self.memory.len();
        let mut result = [0u8; 64];
        let end = core::cmp::min(offset + 64, self.memory.len());
        let len = end - offset;
        result[..len].copy_from_slice(&self.memory[offset..end]);
        result
    }

    /// Compute a dataset item (light mode)
    /// In light mode, dataset items are computed on-demand
    pub fn get_dataset_item(&self, item_index: u64) -> [u8; 64] {
        // Initialize register file from cache
        let cache_line_index = (item_index as usize) % (self.memory.len() / 64);
        let cache_line = self.get_line(cache_line_index);

        let mut regs = [0u64; 8];
        for i in 0..8 {
            regs[i] = u64::from_le_bytes([
                cache_line[i * 8],
                cache_line[i * 8 + 1],
                cache_line[i * 8 + 2],
                cache_line[i * 8 + 3],
                cache_line[i * 8 + 4],
                cache_line[i * 8 + 5],
                cache_line[i * 8 + 6],
                cache_line[i * 8 + 7],
            ]);
        }

        // Mix in item index
        regs[0] ^= item_index;

        // Execute superscalar programs
        for program in &self.programs {
            program.execute(&mut regs);

            // XOR with cache line after each program
            let cache_idx = (regs[0] as usize) % (self.memory.len() / 64);
            let line = self.get_line(cache_idx);
            for i in 0..8 {
                let val = u64::from_le_bytes([
                    line[i * 8],
                    line[i * 8 + 1],
                    line[i * 8 + 2],
                    line[i * 8 + 3],
                    line[i * 8 + 4],
                    line[i * 8 + 5],
                    line[i * 8 + 6],
                    line[i * 8 + 7],
                ]);
                regs[i] ^= val;
            }
        }

        // Convert registers back to bytes
        let mut result = [0u8; 64];
        for i in 0..8 {
            result[i * 8..(i + 1) * 8].copy_from_slice(&regs[i].to_le_bytes());
        }

        result
    }
}

/// Scratchpad manager
pub struct Scratchpad {
    /// Scratchpad memory
    pub memory: Vec<u8>,
    /// Size of scratchpad
    pub size: usize,
}

impl Scratchpad {
    /// Create a new scratchpad
    pub fn new(size: usize) -> Self {
        Self {
            memory: alloc::vec![0u8; size],
            size,
        }
    }

    /// Initialize scratchpad from seed
    pub fn init(&mut self, seed: &[u8; 64]) {
        SoftAes::fill_scratchpad(seed, &mut self.memory);
    }

    /// Read 64-bit value
    pub fn read_u64(&self, addr: usize) -> u64 {
        let addr = addr & (self.size - 8);
        u64::from_le_bytes([
            self.memory[addr],
            self.memory[addr + 1],
            self.memory[addr + 2],
            self.memory[addr + 3],
            self.memory[addr + 4],
            self.memory[addr + 5],
            self.memory[addr + 6],
            self.memory[addr + 7],
        ])
    }

    /// Write 64-bit value
    pub fn write_u64(&mut self, addr: usize, value: u64) {
        let addr = addr & (self.size - 8);
        self.memory[addr..addr + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Read 64-byte block
    pub fn read_block(&self, addr: usize) -> [u8; 64] {
        let addr = addr & (self.size - 64);
        let mut result = [0u8; 64];
        result.copy_from_slice(&self.memory[addr..addr + 64]);
        result
    }

    /// Write 64-byte block
    pub fn write_block(&mut self, addr: usize, data: &[u8; 64]) {
        let addr = addr & (self.size - 64);
        self.memory[addr..addr + 64].copy_from_slice(data);
    }

    /// XOR register file with scratchpad block
    pub fn mix_registers(&mut self, addr: usize, regs: &mut [u64; 8]) {
        let addr = addr & (self.size - 64);

        for i in 0..8 {
            let offset = addr + i * 8;
            let sp_val = u64::from_le_bytes([
                self.memory[offset],
                self.memory[offset + 1],
                self.memory[offset + 2],
                self.memory[offset + 3],
                self.memory[offset + 4],
                self.memory[offset + 5],
                self.memory[offset + 6],
                self.memory[offset + 7],
            ]);
            regs[i] ^= sp_val;
        }
    }

    /// Get scratchpad as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.memory
    }

    /// Get mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.memory
    }
}

/// Dataset reader (light mode)
/// Computes items on-demand using the cache
pub struct DatasetReader<'a> {
    cache: &'a Cache,
}

impl<'a> DatasetReader<'a> {
    pub fn new(cache: &'a Cache) -> Self {
        Self { cache }
    }

    /// Read a dataset item
    pub fn read(&self, index: u64) -> [u8; 64] {
        self.cache.get_dataset_item(index)
    }

    /// Prefetch dataset items for a memory access pattern
    /// In light mode, this computes items on-demand
    pub fn prefetch(&self, ma: u32, mx: u32, regs: &[u64; 8]) -> ([u8; 64], [u8; 64]) {
        // Calculate dataset indices
        let idx_a = ((ma as u64) ^ regs[self.read_reg(0)]) % RANDOMX_DATASET_ITEM_COUNT as u64;
        let idx_b = ((mx as u64) ^ regs[self.read_reg(1)]) % RANDOMX_DATASET_ITEM_COUNT as u64;

        (self.read(idx_a), self.read(idx_b))
    }

    fn read_reg(&self, idx: usize) -> usize {
        idx & 7
    }
}
