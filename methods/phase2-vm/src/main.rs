//! Phase 2: Scratchpad Fill + VM Execution
//!
//! This guest program handles:
//! 1. Verifying cache hash matches Phase 1
//! 2. Scratchpad initialization
//! 3. VM execution
//!
//! Receives the full cache as input from host.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use guest::randomx::aes::SoftAes;
use guest::randomx::blake2b::{blake2b_256, blake2b_hash};
use guest::randomx::program::{Program, SuperscalarProgram};
use guest::randomx::vm::VmState;
use guest::{RANDOMX_DATASET_ITEM_COUNT, SCRATCHPAD_SIZE, PROGRAM_COUNT, ITERATIONS};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

/// Input to Phase 2
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase2Input {
    /// The full cache data (128 MiB)
    pub cache: Vec<u8>,
    /// Expected cache hash from Phase 1
    pub expected_cache_hash: [u8; 32],
    /// The RandomX key (for superscalar program generation)
    pub randomx_key: [u8; 32],
    /// The input data (hashing blob)
    pub input_data: Vec<u8>,
    /// Target difficulty
    pub difficulty: u64,
}

/// Output from Phase 2
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase2Output {
    /// The computed RandomX hash
    pub pow_hash: [u8; 32],
    /// Whether the difficulty check passed
    pub difficulty_valid: bool,
    /// Cache size used
    pub cache_size: usize,
    /// Scratchpad size used
    pub scratchpad_size: usize,
}

/// Lightweight cache wrapper for dataset item computation
struct CacheReader {
    memory: Vec<u8>,
    programs: Vec<SuperscalarProgram>,
}

impl CacheReader {
    fn new(cache: Vec<u8>, key: &[u8]) -> Self {
        let key_hash = blake2b_hash(key);
        let mut programs = Vec::with_capacity(8);
        for i in 0..8 {
            let mut prog_seed = key_hash;
            prog_seed[0] ^= i as u8;
            programs.push(SuperscalarProgram::generate(&prog_seed));
        }
        Self {
            memory: cache,
            programs,
        }
    }

    fn get_line(&self, index: usize) -> [u8; 64] {
        let offset = (index * 64) % self.memory.len();
        let mut result = [0u8; 64];
        let end = core::cmp::min(offset + 64, self.memory.len());
        let len = end - offset;
        result[..len].copy_from_slice(&self.memory[offset..end]);
        result
    }

    fn get_dataset_item(&self, item_index: u64) -> [u8; 64] {
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

        regs[0] ^= item_index;

        for program in &self.programs {
            program.execute(&mut regs);
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

        let mut result = [0u8; 64];
        for i in 0..8 {
            result[i * 8..(i + 1) * 8].copy_from_slice(&regs[i].to_le_bytes());
        }
        result
    }
}

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read input from host
    let input: Phase2Input = env::read();

    // Step 1: Verify cache hash matches Phase 1's commitment
    let actual_cache_hash = blake2b_256(&input.cache);
    assert_eq!(
        actual_cache_hash, input.expected_cache_hash,
        "Cache hash mismatch! Phase 1 and Phase 2 cache must match."
    );

    let cache_size = input.cache.len();

    // Step 2: Create cache reader for dataset item computation
    let cache = CacheReader::new(input.cache, &input.randomx_key);

    // Step 3: Hash input to get 64-byte seed
    let seed_hash = blake2b_hash(&input.input_data);

    // Step 4: Initialize scratchpad from seed
    let mut scratchpad = alloc::vec![0u8; SCRATCHPAD_SIZE];
    SoftAes::fill_scratchpad(&seed_hash, &mut scratchpad);

    // Step 5: Initialize VM
    let mut vm = VmState::new(SCRATCHPAD_SIZE);
    vm.scratchpad = scratchpad.clone();

    // Step 6: Initialize registers from seed
    let mut reg_seed = seed_hash;

    // Step 7: Execute VM programs
    for program_idx in 0..PROGRAM_COUNT {
        let program = Program::generate(&reg_seed);
        vm.init(&reg_seed, &program.entropy);

        for _iter in 0..ITERATIONS {
            vm.execute_program(&program);

            // Dataset mixing (light mode)
            let item_idx = (vm.mem_config.mx as u64)
                .wrapping_mul(vm.int_regs.r[0])
                % (RANDOMX_DATASET_ITEM_COUNT as u64);

            let dataset_item = cache.get_dataset_item(item_idx);

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
                vm.int_regs.r[i] ^= val;
            }

            vm.mem_config.ma ^= vm.int_regs.r[0] as u32;
            vm.mem_config.mx ^= vm.int_regs.r[1] as u32;
        }

        scratchpad = vm.scratchpad.clone();

        if program_idx < PROGRAM_COUNT - 1 {
            reg_seed = aes_hash_register_file(&vm.get_register_file());
        }
    }

    // Step 8: Final hash
    let final_regs = vm.get_register_file();
    let mut sp_hash = [0u8; 64];
    for i in 0..64 {
        sp_hash[i] = scratchpad[i % scratchpad.len()];
    }
    let sp_aes = SoftAes::hash(&sp_hash);

    let mut final_input = [0u8; 256];
    final_input[0..64].copy_from_slice(&sp_aes);
    final_input[64..128].copy_from_slice(&final_regs[0..64]);
    final_input[128..192].copy_from_slice(&final_regs[64..128]);
    final_input[192..256].copy_from_slice(&final_regs[128..192]);

    let pow_hash = blake2b_256(&final_input);

    // Step 9: Verify difficulty
    let difficulty_valid = verify_difficulty(&pow_hash, input.difficulty);

    // Commit output
    let output = Phase2Output {
        pow_hash,
        difficulty_valid,
        cache_size,
        scratchpad_size: SCRATCHPAD_SIZE,
    };

    env::commit(&output);
}

/// AES hash of register file (for seed generation between programs)
fn aes_hash_register_file(regs: &[u8; 256]) -> [u8; 64] {
    let mut input = [0u8; 64];
    for i in 0..4 {
        for j in 0..64 {
            input[j] ^= regs[i * 64 + j];
        }
    }
    SoftAes::hash(&input)
}

/// Verify that a hash meets difficulty target
fn verify_difficulty(hash: &[u8; 32], difficulty: u64) -> bool {
    if difficulty == 0 {
        return false;
    }
    if difficulty == 1 {
        return true;
    }

    let mut leading_zeros = 0;
    for &byte in hash.iter() {
        if byte == 0 {
            leading_zeros += 1;
        } else {
            break;
        }
    }

    let difficulty_bits = 64 - difficulty.leading_zeros();
    let required_zero_bytes = difficulty_bits / 8;

    if leading_zeros as u32 > required_zero_bytes {
        return true;
    }
    if (leading_zeros as u32) < required_zero_bytes {
        return false;
    }

    true
}
