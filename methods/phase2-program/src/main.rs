//! Phase 2 Program Segment: Single program execution with Merkle proofs
//!
//! This guest executes a portion of a RandomX program using Merkle proofs
//! for dataset items instead of the full cache.
//!
//! Supports iteration ranges for finer-grained proving:
//! - Full program: iteration_start=0, iteration_count=2048
//! - Chunked: e.g., iteration_start=0, iteration_count=64 (32 chunks per program)
//!
//! With 8 programs × 32 chunks = 256 total segments for random sampling.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use guest::randomx::aes::SoftAes;
use guest::randomx::blake2b::{blake2b_256, blake2b_hash};
use guest::randomx::program::{Program, SuperscalarProgram};
use guest::randomx::vm::VmState;
use guest::{RANDOMX_DATASET_ITEM_COUNT, SCRATCHPAD_SIZE, ITERATIONS};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

/// Input to a single program segment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramSegmentInput {
    /// Which program (0-7)
    pub program_index: u8,
    /// Is this the first iteration of the first program?
    pub is_first: bool,
    /// Is this the last iteration of the last program? (outputs final hash)
    pub is_last: bool,
    /// Starting iteration within this program (0, 64, 128, ... for chunked mode)
    pub iteration_start: u16,
    /// Number of iterations to execute (2048 for full, 64 for chunked)
    pub iteration_count: u16,
    /// The RandomX key (for superscalar program generation)
    pub randomx_key: [u8; 32],
    /// Merkle root of the dataset (from cache proof)
    pub dataset_merkle_root: [u8; 32],
    /// For first program: the input data (hashing blob)
    /// For other programs: empty
    pub input_data: Vec<u8>,
    /// Seed for this program (64 bytes)
    #[serde(with = "serde_big_array::BigArray")]
    pub seed: [u8; 64],
    /// Input scratchpad (2 MiB)
    pub scratchpad: Vec<u8>,
    /// Initial register state (256 bytes) - for chunked mode mid-program
    /// Empty for iteration_start=0 (will be initialized from seed)
    pub initial_registers: Vec<u8>,
    /// Initial mem_config.ma - for chunked mode mid-program (0 for iteration_start=0)
    pub initial_ma: u32,
    /// Initial mem_config.mx - for chunked mode mid-program (0 for iteration_start=0)
    pub initial_mx: u32,
    /// Dataset items accessed by this chunk, with Merkle proofs
    pub dataset_items: Vec<DatasetItemEntry>,
    /// Target difficulty (only checked on last program)
    pub difficulty: u64,
}

/// A dataset item with its Merkle proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatasetItemEntry {
    pub index: u64,
    #[serde(with = "serde_big_array::BigArray")]
    pub item: [u8; 64],
    /// Flattened sibling hashes (each 32 bytes)
    pub proof: Vec<u8>,
}

/// Output from a program segment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramSegmentOutput {
    /// Program index that was executed
    pub program_index: u8,
    /// Iteration range that was executed
    pub iteration_start: u16,
    pub iteration_count: u16,
    /// For end of program: the seed for the next program
    /// For mid-program chunks: same as input seed
    #[serde(with = "serde_big_array::BigArray")]
    pub next_seed: [u8; 64],
    /// Hash of the output scratchpad
    pub scratchpad_hash: [u8; 32],
    /// Hash of output registers (for chaining chunks within a program)
    pub register_hash: [u8; 32],
    /// For last iteration of last program only: the final PoW hash
    pub pow_hash: Option<[u8; 32]>,
    /// For last program only: whether difficulty was met
    pub difficulty_valid: Option<bool>,
    /// Merkle root that was verified against
    pub dataset_merkle_root: [u8; 32],
}

/// Verify a Merkle proof
fn verify_merkle_proof(
    root: &[u8; 32],
    index: u64,
    item: &[u8; 64],
    siblings: &[u8],
    total_items: u64,
) -> bool {
    // Hash the item to get the leaf
    let mut current = blake2b_256(item);

    // Calculate expected tree height
    let height = 64 - (total_items - 1).leading_zeros();
    let expected_siblings = height as usize;

    if siblings.len() != expected_siblings * 32 {
        return false;
    }

    // Walk up the tree
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
        current = blake2b_256(&combined);
        idx /= 2;
    }

    current == *root
}

/// Verified dataset reader that checks Merkle proofs
struct VerifiedDataset {
    items: BTreeMap<u64, [u8; 64]>,
    merkle_root: [u8; 32],
    programs: Vec<SuperscalarProgram>,
}

impl VerifiedDataset {
    fn new(
        entries: &[DatasetItemEntry],
        merkle_root: [u8; 32],
        key: &[u8],
        total_items: u64,
    ) -> Self {
        let mut items = BTreeMap::new();

        // Verify each entry and build the lookup table
        for entry in entries {
            assert!(
                verify_merkle_proof(
                    &merkle_root,
                    entry.index,
                    &entry.item,
                    &entry.proof,
                    total_items
                ),
                "Invalid Merkle proof for dataset item {}", entry.index
            );
            items.insert(entry.index, entry.item);
        }

        // Generate superscalar programs
        let key_hash = blake2b_hash(key);
        let mut programs = Vec::with_capacity(8);
        for i in 0..8 {
            let mut prog_seed = key_hash;
            prog_seed[0] ^= i as u8;
            programs.push(SuperscalarProgram::generate(&prog_seed));
        }

        Self {
            items,
            merkle_root,
            programs,
        }
    }

    fn get_dataset_item(&self, item_index: u64) -> [u8; 64] {
        // Look up the pre-verified item
        *self.items.get(&item_index).expect("Dataset item not provided in input")
    }
}

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read input
    let input: ProgramSegmentInput = env::read();

    assert!(input.program_index < 8, "Invalid program index");
    assert_eq!(input.scratchpad.len(), SCRATCHPAD_SIZE, "Invalid scratchpad size");
    assert!(input.iteration_count > 0, "iteration_count must be > 0");
    assert!(
        (input.iteration_start as usize) + (input.iteration_count as usize) <= ITERATIONS,
        "Iteration range exceeds program length"
    );

    // Build verified dataset from provided items with proofs
    let dataset = VerifiedDataset::new(
        &input.dataset_items,
        input.dataset_merkle_root,
        &input.randomx_key,
        RANDOMX_DATASET_ITEM_COUNT as u64,
    );

    // Initialize VM
    let mut vm = VmState::new(SCRATCHPAD_SIZE);
    vm.scratchpad = input.scratchpad.clone();

    // Generate program from seed (same for all chunks within a program)
    let program = Program::generate(&input.seed);

    // Initialize VM state based on whether this is the start of a program
    if input.iteration_start == 0 {
        // First chunk: initialize from seed
        vm.init(&input.seed, &program.entropy);
    } else {
        // Mid-program chunk: restore registers and mem_config from input
        assert_eq!(input.initial_registers.len(), 256, "Must provide initial registers for mid-program chunk");
        restore_registers(&mut vm, &input.initial_registers);
        // Restore mem_config.ma and mem_config.mx for correct dataset index calculation
        vm.mem_config.ma = input.initial_ma;
        vm.mem_config.mx = input.initial_mx;
    }

    // Execute the specified iteration range
    let iteration_end = (input.iteration_start as usize) + (input.iteration_count as usize);
    for _iter in (input.iteration_start as usize)..iteration_end {
        vm.execute_program(&program);

        // Dataset mixing
        let item_idx = (vm.mem_config.mx as u64)
            .wrapping_mul(vm.int_regs.r[0])
            % (RANDOMX_DATASET_ITEM_COUNT as u64);

        let dataset_item = dataset.get_dataset_item(item_idx);

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

    let scratchpad = vm.scratchpad.clone();
    let scratchpad_hash = blake2b_256(&scratchpad);
    let final_regs = vm.get_register_file();
    let register_hash = blake2b_256(&final_regs);

    // Compute next seed only if we finished the entire program (iteration_end == 2048)
    let is_program_complete = iteration_end == ITERATIONS;
    let next_seed = if is_program_complete {
        aes_hash_register_file(&final_regs)
    } else {
        input.seed  // Same seed continues within a program
    };

    // For last iteration of last program, compute final hash
    let (pow_hash, difficulty_valid) = if input.is_last && is_program_complete {
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

        let hash = blake2b_256(&final_input);
        let valid = verify_difficulty(&hash, input.difficulty);

        (Some(hash), Some(valid))
    } else {
        (None, None)
    };

    // Commit output
    let output = ProgramSegmentOutput {
        program_index: input.program_index,
        iteration_start: input.iteration_start,
        iteration_count: input.iteration_count,
        next_seed,
        scratchpad_hash,
        register_hash,
        pow_hash,
        difficulty_valid,
        dataset_merkle_root: input.dataset_merkle_root,
    };

    env::commit(&output);
}

/// Restore VM registers from serialized form (256 bytes)
/// Layout: r[0..8] (64 bytes) | f[0..4] (64 bytes) | e[0..4] (64 bytes) | a[0..4] (64 bytes)
fn restore_registers(vm: &mut VmState, regs: &[u8]) {
    use guest::randomx::vm::FloatRegister;

    // Integer registers r[0..8] - 64 bytes
    for i in 0..8 {
        vm.int_regs.r[i] = u64::from_le_bytes([
            regs[i * 8], regs[i * 8 + 1], regs[i * 8 + 2], regs[i * 8 + 3],
            regs[i * 8 + 4], regs[i * 8 + 5], regs[i * 8 + 6], regs[i * 8 + 7],
        ]);
    }
    // Float registers f[0..4] - 64 bytes (starting at offset 64)
    // Each FloatRegister has lo and hi (16 bytes total)
    for i in 0..4 {
        let offset = 64 + i * 16;
        let lo = u64::from_le_bytes([
            regs[offset], regs[offset + 1], regs[offset + 2], regs[offset + 3],
            regs[offset + 4], regs[offset + 5], regs[offset + 6], regs[offset + 7],
        ]);
        let hi = u64::from_le_bytes([
            regs[offset + 8], regs[offset + 9], regs[offset + 10], regs[offset + 11],
            regs[offset + 12], regs[offset + 13], regs[offset + 14], regs[offset + 15],
        ]);
        vm.float_regs.f[i] = FloatRegister::from_u64(lo, hi);
    }
    // Float registers e[0..4] - 64 bytes (starting at offset 128)
    for i in 0..4 {
        let offset = 128 + i * 16;
        let lo = u64::from_le_bytes([
            regs[offset], regs[offset + 1], regs[offset + 2], regs[offset + 3],
            regs[offset + 4], regs[offset + 5], regs[offset + 6], regs[offset + 7],
        ]);
        let hi = u64::from_le_bytes([
            regs[offset + 8], regs[offset + 9], regs[offset + 10], regs[offset + 11],
            regs[offset + 12], regs[offset + 13], regs[offset + 14], regs[offset + 15],
        ]);
        vm.float_regs.e[i] = FloatRegister::from_u64(lo, hi);
    }
    // Float registers a[0..4] - 64 bytes (starting at offset 192)
    for i in 0..4 {
        let offset = 192 + i * 16;
        let lo = u64::from_le_bytes([
            regs[offset], regs[offset + 1], regs[offset + 2], regs[offset + 3],
            regs[offset + 4], regs[offset + 5], regs[offset + 6], regs[offset + 7],
        ]);
        let hi = u64::from_le_bytes([
            regs[offset + 8], regs[offset + 9], regs[offset + 10], regs[offset + 11],
            regs[offset + 12], regs[offset + 13], regs[offset + 14], regs[offset + 15],
        ]);
        vm.float_regs.a[i] = FloatRegister::from_u64(lo, hi);
    }
}

/// AES hash of register file
fn aes_hash_register_file(regs: &[u8; 256]) -> [u8; 64] {
    let mut input = [0u8; 64];
    for i in 0..4 {
        for j in 0..64 {
            input[j] ^= regs[i * 64 + j];
        }
    }
    SoftAes::hash(&input)
}

/// Verify difficulty
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
