//! RandomX VM Simulation for Host
//!
//! This module provides accurate VM simulation to predict which dataset items
//! the guest will access during block proof generation.
//!
//! This is a port of the guest's VM code to run on the host (std environment).
//! We only need the integer operations to predict dataset accesses - floating
//! point operations don't affect the dataset access pattern.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::{AesState, aes_round, blake2b_256};

// ============================================================
// CONFIGURATION CONSTANTS (must match guest)
// ============================================================

/// Scratchpad L3 size: 2 MiB
pub const RANDOMX_SCRATCHPAD_L3: usize = 2097152;
/// L2 cache size: 256 KiB
pub const RANDOMX_SCRATCHPAD_L2: usize = 262144;
/// L1 cache size: 16 KiB
pub const RANDOMX_SCRATCHPAD_L1: usize = 16384;

/// Program size in instructions
pub const RANDOMX_PROGRAM_SIZE: usize = 256;
/// Number of program iterations
pub const RANDOMX_PROGRAM_ITERATIONS: usize = 2048;
/// Number of programs per hash
pub const RANDOMX_PROGRAM_COUNT: usize = 8;

/// Condition mask for jumps
pub const RANDOMX_JUMP_BITS: u32 = 8;
pub const RANDOMX_JUMP_OFFSET: u32 = 8;

/// Scratchpad masks (for addressing)
pub const SCRATCHPAD_L1_MASK: usize = RANDOMX_SCRATCHPAD_L1 - 64;
pub const SCRATCHPAD_L2_MASK: usize = RANDOMX_SCRATCHPAD_L2 - 64;
pub const SCRATCHPAD_L3_MASK: usize = RANDOMX_SCRATCHPAD_L3 - 64;

/// Float constants
pub const MANTISSA_SIZE: u32 = 52;
pub const MANTISSA_MASK: u64 = (1u64 << MANTISSA_SIZE) - 1;
pub const EXPONENT_BIAS: u64 = 1023;
pub const DYNAMIC_EXPONENT_BITS: u32 = 4;
pub const STATIC_EXPONENT: u64 = EXPONENT_BIAS + MANTISSA_SIZE as u64;
pub const DYNAMIC_MANTISSA_MASK: u64 = (1u64 << (MANTISSA_SIZE + DYNAMIC_EXPONENT_BITS)) - 1;
pub const SCALE_MASK: u64 = 0x80F0000000000000;

// ============================================================
// OPCODES
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    IADD_RS = 0,
    IADD_M = 1,
    ISUB_R = 2,
    ISUB_M = 3,
    IMUL_R = 4,
    IMUL_M = 5,
    IMULH_R = 6,
    IMULH_M = 7,
    ISMULH_R = 8,
    ISMULH_M = 9,
    IMUL_RCP = 10,
    INEG_R = 11,
    IXOR_R = 12,
    IXOR_M = 13,
    IROR_R = 14,
    IROL_R = 15,
    ISWAP_R = 16,
    FSWAP_R = 17,
    FADD_R = 18,
    FADD_M = 19,
    FSUB_R = 20,
    FSUB_M = 21,
    FSCAL_R = 22,
    FMUL_R = 23,
    FDIV_M = 24,
    FSQRT_R = 25,
    CBRANCH = 26,
    CFROUND = 27,
    ISTORE = 28,
    NOP = 29,
}

/// Instruction frequency table for opcode mapping
const INSTRUCTION_FREQUENCIES: [(u8, u8, Opcode); 30] = [
    (0, 15, Opcode::IADD_RS),
    (16, 22, Opcode::IADD_M),
    (23, 38, Opcode::ISUB_R),
    (39, 45, Opcode::ISUB_M),
    (46, 61, Opcode::IMUL_R),
    (62, 65, Opcode::IMUL_M),
    (66, 69, Opcode::IMULH_R),
    (70, 70, Opcode::IMULH_M),
    (71, 74, Opcode::ISMULH_R),
    (75, 75, Opcode::ISMULH_M),
    (76, 83, Opcode::IMUL_RCP),
    (84, 85, Opcode::INEG_R),
    (86, 101, Opcode::IXOR_R),
    (102, 105, Opcode::IXOR_M),
    (106, 115, Opcode::IROR_R),
    (116, 125, Opcode::IROL_R),
    (126, 129, Opcode::ISWAP_R),
    (130, 137, Opcode::FSWAP_R),
    (138, 153, Opcode::FADD_R),
    (154, 158, Opcode::FADD_M),
    (159, 174, Opcode::FSUB_R),
    (175, 179, Opcode::FSUB_M),
    (180, 185, Opcode::FSCAL_R),
    (186, 217, Opcode::FMUL_R),
    (218, 221, Opcode::FDIV_M),
    (222, 227, Opcode::FSQRT_R),
    (228, 252, Opcode::CBRANCH),
    (253, 253, Opcode::CFROUND),
    (254, 255, Opcode::ISTORE),
    (255, 255, Opcode::NOP),
];

fn opcode_from_byte(byte: u8) -> Opcode {
    for &(start, end, opcode) in INSTRUCTION_FREQUENCIES.iter() {
        if byte >= start && byte <= end {
            return opcode;
        }
    }
    Opcode::NOP
}

// ============================================================
// INSTRUCTION
// ============================================================

#[derive(Clone, Debug)]
pub struct Instruction {
    pub opcode: Opcode,
    pub dst: u8,
    pub src: u8,
    pub mod_val: u8,
    pub imm: i32,
    pub target: i32,
}

impl Instruction {
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        let opcode_byte = bytes[0];
        let dst = bytes[1] & 0x07;
        let src = bytes[2] & 0x07;
        let mod_val = bytes[3];
        let imm = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let opcode = opcode_from_byte(opcode_byte);

        Self {
            opcode,
            dst,
            src,
            mod_val,
            imm,
            target: 0,
        }
    }

    pub fn nop() -> Self {
        Self {
            opcode: Opcode::NOP,
            dst: 0,
            src: 0,
            mod_val: 0,
            imm: 0,
            target: 0,
        }
    }
}

// ============================================================
// PROGRAM
// ============================================================

#[derive(Clone)]
pub struct Program {
    pub instructions: [Instruction; RANDOMX_PROGRAM_SIZE],
    pub entropy: [u64; 16],
}

/// AES generator for program randomization
struct AesGenerator {
    state: [AesState; 4],
    keys: [[u8; 16]; 4],
}

impl AesGenerator {
    fn new(seed: &[u8; 64]) -> Self {
        let state = [
            AesState::from_bytes(&seed[0..16]),
            AesState::from_bytes(&seed[16..32]),
            AesState::from_bytes(&seed[32..48]),
            AesState::from_bytes(&seed[48..64]),
        ];

        let keys: [[u8; 16]; 4] = [
            [0x06, 0x3c, 0xf1, 0x71, 0x7d, 0x2f, 0xa4, 0x08, 0x3b, 0x78, 0x88, 0xfe, 0x98, 0x5c, 0xf0, 0x67],
            [0x35, 0x5d, 0x29, 0x1d, 0x9a, 0xe5, 0xa3, 0x28, 0x46, 0xbf, 0x8e, 0x48, 0x29, 0xc1, 0xbc, 0x2a],
            [0x2a, 0xe9, 0x90, 0x27, 0x4f, 0x65, 0xd7, 0x43, 0xdb, 0xdd, 0x65, 0x03, 0xad, 0xf9, 0x95, 0x69],
            [0x8c, 0x18, 0x6b, 0x43, 0xa0, 0x49, 0xe9, 0x22, 0x0d, 0x8d, 0x7e, 0x52, 0x95, 0x08, 0xbf, 0xe6],
        ];

        Self { state, keys }
    }

    fn next_block(&mut self) -> [u8; 64] {
        for (state, key) in self.state.iter_mut().zip(self.keys.iter()) {
            aes_round(state, key);
        }

        let mut output = [0u8; 64];
        for (i, state) in self.state.iter().enumerate() {
            output[i * 16..(i + 1) * 16].copy_from_slice(&state.to_bytes());
        }
        output
    }
}

impl Program {
    pub fn generate(seed: &[u8; 64]) -> Self {
        let mut gen = AesGenerator::new(seed);

        // Generate entropy first (128 bytes = 16 x u64)
        let mut entropy = [0u64; 16];
        for e in entropy.iter_mut() {
            let block = gen.next_block();
            *e = u64::from_le_bytes([
                block[0], block[1], block[2], block[3],
                block[4], block[5], block[6], block[7],
            ]);
        }

        // Generate instructions (256 x 8 bytes)
        let mut instructions: [Instruction; RANDOMX_PROGRAM_SIZE] =
            std::array::from_fn(|_| Instruction::nop());

        let mut branch_count = 0;

        for i in 0..RANDOMX_PROGRAM_SIZE {
            let block = gen.next_block();
            let mut instr = Instruction::from_bytes(&[
                block[0], block[1], block[2], block[3],
                block[4], block[5], block[6], block[7],
            ]);

            // Handle CBRANCH target calculation
            if instr.opcode == Opcode::CBRANCH {
                let target_offset = (instr.mod_val as i32) - 128;
                let target = (i as i32 + target_offset).max(0) as i32;
                instr.target = target.min(i as i32);
                branch_count += 1;

                if branch_count > 8 {
                    instr.opcode = Opcode::NOP;
                }
            }

            instructions[i] = instr;
        }

        Self { instructions, entropy }
    }
}

// ============================================================
// VM STATE
// ============================================================

/// Floating point register (128-bit = 2 x 64-bit)
/// For simulation, we only need the bit representation
#[derive(Clone, Copy, Debug)]
pub struct FloatRegister {
    pub lo: u64,
    pub hi: u64,
}

impl FloatRegister {
    pub fn new() -> Self {
        Self { lo: 0, hi: 0 }
    }

    pub fn from_u64(lo: u64, hi: u64) -> Self {
        Self { lo, hi }
    }
}

/// Memory address configuration
#[derive(Clone, Debug)]
pub struct MemoryConfig {
    pub ma: u32,
    pub mx: u32,
}

impl MemoryConfig {
    pub fn new(entropy: &[u64; 4]) -> Self {
        Self {
            ma: (entropy[0] & 0xFFFFFFFF) as u32,
            mx: (entropy[0] >> 32) as u32,
        }
    }
}

/// E register configuration
#[derive(Clone, Debug)]
pub struct ERegisterConfig {
    pub mask: [u64; 2],
}

impl ERegisterConfig {
    pub fn new(entropy: &[u64; 4]) -> Self {
        let mut mask = [0u64; 2];
        for i in 0..2 {
            let tmp = entropy[i];
            let exp = ((tmp >> 59) & 0xF) as u32;
            mask[i] = (exp as u64 + EXPONENT_BIAS) << MANTISSA_SIZE;
            mask[i] |= SCALE_MASK;
        }
        Self { mask }
    }
}

/// Full VM state for simulation
pub struct VmState {
    /// Integer registers
    pub int_regs: [u64; 8],
    /// F registers (for float ops - only bit representation needed)
    pub f_regs: [FloatRegister; 4],
    /// E registers
    pub e_regs: [FloatRegister; 4],
    /// A registers (read-only after init)
    pub a_regs: [FloatRegister; 4],
    /// E register configuration
    pub e_config: ERegisterConfig,
    /// Memory configuration
    pub mem_config: MemoryConfig,
    /// Scratchpad memory
    pub scratchpad: Vec<u8>,
    /// Rounding mode (for CFROUND)
    pub rounding_mode: u8,
    /// Program counter
    pub pc: usize,
}

impl VmState {
    pub fn new(scratchpad_size: usize) -> Self {
        Self {
            int_regs: [0u64; 8],
            f_regs: [FloatRegister::new(); 4],
            e_regs: [FloatRegister::new(); 4],
            a_regs: [FloatRegister::new(); 4],
            e_config: ERegisterConfig { mask: [0; 2] },
            mem_config: MemoryConfig { ma: 0, mx: 0 },
            scratchpad: vec![0u8; scratchpad_size],
            rounding_mode: 0,
            pc: 0,
        }
    }

    /// Initialize VM state from seed and program entropy
    pub fn init(&mut self, seed: &[u8; 64], entropy: &[u64; 16]) {
        // Initialize integer registers from first 64 bytes
        for i in 0..8 {
            let offset = i * 8;
            self.int_regs[i] = u64::from_le_bytes([
                seed[offset], seed[offset + 1], seed[offset + 2], seed[offset + 3],
                seed[offset + 4], seed[offset + 5], seed[offset + 6], seed[offset + 7],
            ]);
        }

        // Initialize A registers (small positive floats)
        for i in 0..4 {
            let offset = i * 16;
            let lo = u64::from_le_bytes([
                seed[offset], seed[offset + 1], seed[offset + 2], seed[offset + 3],
                seed[offset + 4], seed[offset + 5], seed[offset + 6], seed[offset + 7],
            ]);
            let hi = u64::from_le_bytes([
                seed[offset + 8], seed[offset + 9], seed[offset + 10], seed[offset + 11],
                seed[offset + 12], seed[offset + 13], seed[offset + 14], seed[offset + 15],
            ]);
            // Convert to small positive float for A registers
            let mask = MANTISSA_MASK;
            let exp = STATIC_EXPONENT << MANTISSA_SIZE;
            self.a_regs[i] = FloatRegister {
                lo: (lo & mask) | exp,
                hi: (hi & mask) | exp,
            };
        }

        // Configure E registers
        self.e_config = ERegisterConfig::new(&[entropy[0], entropy[1], entropy[2], entropy[3]]);

        // Configure memory
        self.mem_config = MemoryConfig::new(&[entropy[4], entropy[5], entropy[6], entropy[7]]);

        // Reset counters
        self.pc = 0;
        self.rounding_mode = 0;
    }

    /// Read 64-bit value from scratchpad
    fn read_u64(&self, addr: usize) -> u64 {
        let addr = addr & (self.scratchpad.len() - 8);
        u64::from_le_bytes([
            self.scratchpad[addr],
            self.scratchpad[addr + 1],
            self.scratchpad[addr + 2],
            self.scratchpad[addr + 3],
            self.scratchpad[addr + 4],
            self.scratchpad[addr + 5],
            self.scratchpad[addr + 6],
            self.scratchpad[addr + 7],
        ])
    }

    /// Write 64-bit value to scratchpad
    fn write_u64(&mut self, addr: usize, value: u64) {
        let addr = addr & (self.scratchpad.len() - 8);
        let bytes = value.to_le_bytes();
        self.scratchpad[addr..addr + 8].copy_from_slice(&bytes);
    }

    /// Read 128-bit value as float register from scratchpad
    fn read_float(&self, addr: usize) -> FloatRegister {
        let addr = addr & (self.scratchpad.len() - 16);
        let lo = self.read_u64(addr);
        let hi = self.read_u64(addr + 8);
        FloatRegister::from_u64(lo, hi)
    }

    /// Get scratchpad L3 address
    fn l3_addr(&self, offset: u32, reg_value: u64) -> usize {
        let addr = (reg_value as u32).wrapping_add(offset);
        (addr as usize) & SCRATCHPAD_L3_MASK
    }

    /// Execute a single program
    pub fn execute_program(&mut self, program: &Program) {
        self.pc = 0;

        for _ in 0..RANDOMX_PROGRAM_SIZE {
            if self.pc >= RANDOMX_PROGRAM_SIZE {
                break;
            }

            let instr = &program.instructions[self.pc];
            self.pc += 1;

            self.execute_instruction(instr);
        }
    }

    /// Execute a single instruction
    fn execute_instruction(&mut self, instr: &Instruction) {
        use Opcode::*;

        let dst = instr.dst as usize;
        let src = instr.src as usize;
        let imm = instr.imm;
        let mod_val = instr.mod_val;

        match instr.opcode {
            IADD_RS => {
                let shift = (mod_val >> 2) & 3;
                let src_val = if src == dst {
                    imm as u64
                } else {
                    self.int_regs[src]
                };
                self.int_regs[dst] = self.int_regs[dst].wrapping_add(src_val << shift);
            }

            IADD_M => {
                let addr = self.l3_addr(imm as u32, self.int_regs[src]);
                let mem_val = self.read_u64(addr);
                self.int_regs[dst] = self.int_regs[dst].wrapping_add(mem_val);
            }

            ISUB_R => {
                let src_val = if src == dst {
                    imm as u64
                } else {
                    self.int_regs[src]
                };
                self.int_regs[dst] = self.int_regs[dst].wrapping_sub(src_val);
            }

            ISUB_M => {
                let addr = self.l3_addr(imm as u32, self.int_regs[src]);
                let mem_val = self.read_u64(addr);
                self.int_regs[dst] = self.int_regs[dst].wrapping_sub(mem_val);
            }

            IMUL_R => {
                let src_val = if src == dst {
                    imm as u64
                } else {
                    self.int_regs[src]
                };
                self.int_regs[dst] = self.int_regs[dst].wrapping_mul(src_val);
            }

            IMUL_M => {
                let addr = self.l3_addr(imm as u32, self.int_regs[src]);
                let mem_val = self.read_u64(addr);
                self.int_regs[dst] = self.int_regs[dst].wrapping_mul(mem_val);
            }

            IMULH_R => {
                let a = self.int_regs[dst] as u128;
                let b = self.int_regs[src] as u128;
                self.int_regs[dst] = ((a * b) >> 64) as u64;
            }

            IMULH_M => {
                let addr = self.l3_addr(imm as u32, self.int_regs[src]);
                let mem_val = self.read_u64(addr);
                let a = self.int_regs[dst] as u128;
                let b = mem_val as u128;
                self.int_regs[dst] = ((a * b) >> 64) as u64;
            }

            ISMULH_R => {
                let a = self.int_regs[dst] as i64 as i128;
                let b = self.int_regs[src] as i64 as i128;
                self.int_regs[dst] = ((a * b) >> 64) as u64;
            }

            ISMULH_M => {
                let addr = self.l3_addr(imm as u32, self.int_regs[src]);
                let mem_val = self.read_u64(addr) as i64;
                let a = self.int_regs[dst] as i64 as i128;
                let b = mem_val as i128;
                self.int_regs[dst] = ((a * b) >> 64) as u64;
            }

            IMUL_RCP => {
                let imm_u64 = imm as u64;
                if imm != 0 && !imm_u64.is_power_of_two() {
                    let rcp = reciprocal(imm_u64);
                    self.int_regs[dst] = self.int_regs[dst].wrapping_mul(rcp);
                }
            }

            INEG_R => {
                self.int_regs[dst] = (-(self.int_regs[dst] as i64)) as u64;
            }

            IXOR_R => {
                let src_val = if src == dst {
                    imm as u64
                } else {
                    self.int_regs[src]
                };
                self.int_regs[dst] ^= src_val;
            }

            IXOR_M => {
                let addr = self.l3_addr(imm as u32, self.int_regs[src]);
                let mem_val = self.read_u64(addr);
                self.int_regs[dst] ^= mem_val;
            }

            IROR_R => {
                let src_val = if src == dst { imm as u64 } else { self.int_regs[src] };
                let shift = (src_val & 63) as u32;
                self.int_regs[dst] = self.int_regs[dst].rotate_right(shift);
            }

            IROL_R => {
                let src_val = if src == dst { imm as u64 } else { self.int_regs[src] };
                let shift = (src_val & 63) as u32;
                self.int_regs[dst] = self.int_regs[dst].rotate_left(shift);
            }

            ISWAP_R => {
                if dst != src {
                    let tmp = self.int_regs[dst];
                    self.int_regs[dst] = self.int_regs[src];
                    self.int_regs[src] = tmp;
                }
            }

            FSWAP_R => {
                // Swap lo and hi of F or E register
                let reg_idx = dst & 3;
                if dst < 4 {
                    let tmp = self.f_regs[reg_idx].lo;
                    self.f_regs[reg_idx].lo = self.f_regs[reg_idx].hi;
                    self.f_regs[reg_idx].hi = tmp;
                } else {
                    let tmp = self.e_regs[reg_idx].lo;
                    self.e_regs[reg_idx].lo = self.e_regs[reg_idx].hi;
                    self.e_regs[reg_idx].hi = tmp;
                }
            }

            FADD_R => {
                // F[dst] = F[dst] + A[src] (bit-level simulation, not real float)
                // For dataset access prediction, we don't need accurate float ops
                let dst_idx = dst & 3;
                let src_idx = src & 3;
                // Simple XOR simulation (doesn't affect dataset access pattern)
                self.f_regs[dst_idx].lo ^= self.a_regs[src_idx].lo;
                self.f_regs[dst_idx].hi ^= self.a_regs[src_idx].hi;
            }

            FADD_M => {
                let dst_idx = dst & 3;
                let addr = self.l3_addr(imm as u32, self.int_regs[src]);
                let mem_float = self.read_float(addr);
                self.f_regs[dst_idx].lo ^= mem_float.lo;
                self.f_regs[dst_idx].hi ^= mem_float.hi;
            }

            FSUB_R => {
                let dst_idx = dst & 3;
                let src_idx = src & 3;
                self.f_regs[dst_idx].lo ^= self.a_regs[src_idx].lo;
                self.f_regs[dst_idx].hi ^= self.a_regs[src_idx].hi;
            }

            FSUB_M => {
                let dst_idx = dst & 3;
                let addr = self.l3_addr(imm as u32, self.int_regs[src]);
                let mem_float = self.read_float(addr);
                self.f_regs[dst_idx].lo ^= mem_float.lo;
                self.f_regs[dst_idx].hi ^= mem_float.hi;
            }

            FSCAL_R => {
                let dst_idx = dst & 3;
                self.f_regs[dst_idx].lo ^= SCALE_MASK;
                self.f_regs[dst_idx].hi ^= SCALE_MASK;
            }

            FMUL_R => {
                let dst_idx = dst & 3;
                let src_idx = src & 3;
                self.e_regs[dst_idx].lo ^= self.a_regs[src_idx].lo;
                self.e_regs[dst_idx].hi ^= self.a_regs[src_idx].hi;
            }

            FDIV_M => {
                let dst_idx = dst & 3;
                let addr = self.l3_addr(imm as u32, self.int_regs[src]);
                let mem_float = self.read_float(addr);
                self.e_regs[dst_idx].lo ^= mem_float.lo;
                self.e_regs[dst_idx].hi ^= mem_float.hi;
            }

            FSQRT_R => {
                let dst_idx = dst & 3;
                // No-op for simulation (doesn't affect dataset access)
                let _ = dst_idx;
            }

            CBRANCH => {
                let condition_mask = (1u64 << RANDOMX_JUMP_BITS) - 1;
                let condition_shift = RANDOMX_JUMP_OFFSET;

                self.int_regs[dst] = self.int_regs[dst].wrapping_add(imm as u64);

                if (self.int_regs[dst] >> condition_shift) & condition_mask == 0 {
                    let target = instr.target as usize;
                    if target < self.pc {
                        self.pc = target;
                    }
                }
            }

            CFROUND => {
                let src_val = self.int_regs[src];
                let shift = (imm & 63) as u32;
                self.rounding_mode = ((src_val >> shift) & 3) as u8;
            }

            ISTORE => {
                let addr = self.l3_addr(imm as u32, self.int_regs[dst]);
                self.write_u64(addr, self.int_regs[src]);
            }

            NOP => {}
        }
    }

    /// Get register file as bytes
    pub fn get_register_file(&self) -> [u8; 256] {
        let mut result = [0u8; 256];

        // Integer registers (64 bytes)
        for i in 0..8 {
            let offset = i * 8;
            result[offset..offset + 8].copy_from_slice(&self.int_regs[i].to_le_bytes());
        }

        // F registers (64 bytes)
        for i in 0..4 {
            let offset = 64 + i * 16;
            result[offset..offset + 8].copy_from_slice(&self.f_regs[i].lo.to_le_bytes());
            result[offset + 8..offset + 16].copy_from_slice(&self.f_regs[i].hi.to_le_bytes());
        }

        // E registers (64 bytes)
        for i in 0..4 {
            let offset = 128 + i * 16;
            result[offset..offset + 8].copy_from_slice(&self.e_regs[i].lo.to_le_bytes());
            result[offset + 8..offset + 16].copy_from_slice(&self.e_regs[i].hi.to_le_bytes());
        }

        // A registers (64 bytes)
        for i in 0..4 {
            let offset = 192 + i * 16;
            result[offset..offset + 8].copy_from_slice(&self.a_regs[i].lo.to_le_bytes());
            result[offset + 8..offset + 16].copy_from_slice(&self.a_regs[i].hi.to_le_bytes());
        }

        result
    }
}

/// Compute modular multiplicative inverse for IMUL_RCP
fn reciprocal(divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }

    let p2exp63: u128 = 1u128 << 63;
    let mut quotient: u128 = p2exp63 / divisor as u128;
    let mut remainder: u128 = p2exp63 % divisor as u128;

    let mut bit_shift: u32 = 0;
    while remainder != 0 && bit_shift < 63 {
        let prev_remainder = remainder;
        remainder <<= 1;
        if remainder >= divisor as u128 {
            remainder -= divisor as u128;
            quotient <<= 1;
            quotient |= 1;
        } else {
            quotient <<= 1;
        }
        if prev_remainder == remainder {
            break;
        }
        bit_shift += 1;
    }

    quotient as u64
}

// ============================================================
// PUBLIC API FOR HOST
// ============================================================

/// Result of simulating all programs
pub struct SimulationResult {
    /// Dataset accesses for each program (8 programs × 2048 accesses)
    pub accesses: Vec<Vec<u64>>,
    /// Seed at the START of each program (8 × 64 bytes)
    pub seeds: Vec<[u8; 64]>,
    /// Scratchpad at the START of each program (8 × 2 MiB)
    pub scratchpads: Vec<Vec<u8>>,
}

/// Simulate all 8 programs and return dataset accesses, seeds, and scratchpads for each
/// This must match the guest's execution exactly to predict dataset accesses
pub fn simulate_all_programs(
    cache: &[u8],
    input_data: &[u8],
    scratchpad_size: usize,
    iterations: usize,
    num_items: usize,
) -> SimulationResult {
    let mut all_accesses = Vec::new();
    let mut all_seeds = Vec::new();
    let mut all_scratchpads = Vec::new();

    // Initial seed from input data (matches guest)
    let mut seed = [0u8; 64];
    let hash = blake2b_256(input_data);
    seed[..32].copy_from_slice(&hash);
    seed[32..].copy_from_slice(&hash);

    // Fill initial scratchpad using host's soft_aes_fill_scratchpad
    let mut scratchpad = vec![0u8; scratchpad_size];
    crate::soft_aes_fill_scratchpad(&seed, &mut scratchpad);

    for _prog_idx in 0..RANDOMX_PROGRAM_COUNT {
        // Save seed and scratchpad at START of this program
        all_seeds.push(seed);
        all_scratchpads.push(scratchpad.clone());

        // Generate program from seed (matches guest)
        let program = Program::generate(&seed);

        // Create VM and initialize
        let mut vm = VmState::new(scratchpad_size);
        vm.scratchpad = scratchpad.clone();
        vm.init(&seed, &program.entropy);

        let mut accesses = Vec::new();

        // Execute iterations (matches guest's main loop)
        for _iter in 0..iterations {
            // Execute program
            vm.execute_program(&program);

            // Calculate dataset item index (matches guest exactly)
            let item_idx = (vm.mem_config.mx as u64)
                .wrapping_mul(vm.int_regs[0])
                % (num_items as u64);

            accesses.push(item_idx);

            // Get dataset item and mix into registers (matches guest)
            let item_start = (item_idx as usize) * 64;
            let dataset_item = &cache[item_start..item_start + 64];

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
                vm.int_regs[i] ^= val;
            }

            // Update memory registers (matches guest)
            vm.mem_config.ma ^= vm.int_regs[0] as u32;
            vm.mem_config.mx ^= vm.int_regs[1] as u32;
        }

        all_accesses.push(accesses);

        // Compute next seed using AES hash of register file (matches guest)
        seed = aes_hash_register_file(&vm.get_register_file());

        // Update scratchpad for next program (CRITICAL: carry over modified scratchpad)
        scratchpad = vm.scratchpad;
    }

    SimulationResult {
        accesses: all_accesses,
        seeds: all_seeds,
        scratchpads: all_scratchpads,
    }
}

/// Result of simulating a single chunk (iteration range)
pub struct ChunkSimulationResult {
    /// Dataset accesses for this chunk
    pub accesses: Vec<u64>,
    /// Initial register state (256 bytes) - empty for iteration_start=0
    pub initial_registers: Vec<u8>,
    /// Initial mem_config.ma value - needed for mid-program chunks
    pub initial_ma: u32,
    /// Initial mem_config.mx value - needed for mid-program chunks
    pub initial_mx: u32,
    /// Final register state (256 bytes)
    pub final_registers: [u8; 256],
    /// Scratchpad at the end of this chunk
    pub final_scratchpad: Vec<u8>,
}

/// Simulate a specific chunk (iteration range) within a program
/// Returns dataset accesses and register states needed for proving
pub fn simulate_program_chunk(
    cache: &[u8],
    seed: &[u8; 64],
    scratchpad: &[u8],
    iteration_start: usize,
    iteration_count: usize,
    num_items: usize,
) -> ChunkSimulationResult {
    let scratchpad_size = scratchpad.len();

    // Generate program from seed (same for all chunks within a program)
    let program = Program::generate(seed);

    // Create VM and initialize
    let mut vm = VmState::new(scratchpad_size);
    vm.scratchpad = scratchpad.to_vec();
    vm.init(seed, &program.entropy);

    // If this is a mid-program chunk, we need to run preceding iterations first
    // to get the correct register and mem_config state
    let (initial_registers, initial_ma, initial_mx) = if iteration_start > 0 {
        // Run iterations 0 to iteration_start to get the state
        for _iter in 0..iteration_start {
            vm.execute_program(&program);

            // Dataset mixing
            let item_idx = (vm.mem_config.mx as u64)
                .wrapping_mul(vm.int_regs[0])
                % (num_items as u64);

            let item_start = (item_idx as usize) * 64;
            let dataset_item = &cache[item_start..item_start + 64];

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
                vm.int_regs[i] ^= val;
            }

            vm.mem_config.ma ^= vm.int_regs[0] as u32;
            vm.mem_config.mx ^= vm.int_regs[1] as u32;
        }

        // Capture register state AND mem_config BEFORE running the target chunk
        (vm.get_register_file().to_vec(), vm.mem_config.ma, vm.mem_config.mx)
    } else {
        (vec![], 0, 0)
    };

    // Now run the target iteration range and collect accesses
    let mut accesses = Vec::new();
    let iteration_end = iteration_start + iteration_count;

    for _iter in iteration_start..iteration_end {
        vm.execute_program(&program);

        // Calculate dataset item index
        let item_idx = (vm.mem_config.mx as u64)
            .wrapping_mul(vm.int_regs[0])
            % (num_items as u64);

        accesses.push(item_idx);

        // Get dataset item and mix into registers
        let item_start = (item_idx as usize) * 64;
        let dataset_item = &cache[item_start..item_start + 64];

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
            vm.int_regs[i] ^= val;
        }

        vm.mem_config.ma ^= vm.int_regs[0] as u32;
        vm.mem_config.mx ^= vm.int_regs[1] as u32;
    }

    ChunkSimulationResult {
        accesses,
        initial_registers,
        initial_ma,
        initial_mx,
        final_registers: vm.get_register_file(),
        final_scratchpad: vm.scratchpad,
    }
}

/// AES hash of register file (matches guest)
fn aes_hash_register_file(regs: &[u8; 256]) -> [u8; 64] {
    // XOR all 4 64-byte chunks together
    let mut input = [0u8; 64];
    for i in 0..4 {
        for j in 0..64 {
            input[j] ^= regs[i * 64 + j];
        }
    }

    // Apply AES hash
    let mut states = [
        AesState::from_bytes(&input[0..16]),
        AesState::from_bytes(&input[16..32]),
        AesState::from_bytes(&input[32..48]),
        AesState::from_bytes(&input[48..64]),
    ];

    let keys: [[u8; 16]; 4] = [
        [0x35, 0x53, 0x45, 0x41, 0x88, 0x75, 0x4f, 0x8b, 0xca, 0xf5, 0xd4, 0x09, 0x8d, 0x93, 0x74, 0xd0],
        [0x07, 0xa4, 0x79, 0x25, 0x40, 0xc5, 0x23, 0x75, 0xe2, 0x18, 0xa1, 0xaa, 0x0f, 0xa0, 0xf0, 0xa5],
        [0xe8, 0xda, 0xf9, 0xac, 0x71, 0x9e, 0x77, 0xa0, 0x00, 0xc1, 0xd2, 0xae, 0x3e, 0xf4, 0x66, 0x81],
        [0x4c, 0x77, 0xd8, 0x36, 0xbb, 0xa3, 0xf6, 0x05, 0x88, 0x4a, 0x01, 0xdc, 0x8a, 0xa7, 0x14, 0xd9],
    ];

    for _ in 0..4 {
        for (i, state) in states.iter_mut().enumerate() {
            aes_round(state, &keys[i]);
        }
    }

    let mut output = [0u8; 64];
    for (i, state) in states.iter().enumerate() {
        output[i * 16..(i + 1) * 16].copy_from_slice(&state.to_bytes());
    }
    output
}
