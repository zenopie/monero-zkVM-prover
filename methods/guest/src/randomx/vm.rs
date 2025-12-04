//! RandomX Virtual Machine
//!
//! The RandomX VM has:
//! - 8 integer registers (r0-r7)
//! - 4 floating point register pairs (f0-f3, e0-e3)
//! - A scratchpad (256 MiB in light mode)
//! - Memory address registers (ma, mx)
//!
//! The VM executes randomly generated programs.
//!
//! NOTE: All floating point operations use soft-float for deterministic
//! execution across platforms (required for zkVM).

use crate::randomx::config::*;
use crate::randomx::program::Program;
use crate::randomx::softfloat::{SoftFloat, RoundingMode};

/// Integer register file (8 x 64-bit)
#[derive(Clone, Debug)]
pub struct IntRegisters {
    pub r: [u64; RANDOMX_INT_REGISTER_COUNT],
}

impl IntRegisters {
    pub fn new() -> Self {
        Self { r: [0u64; 8] }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut r = [0u64; 8];
        for i in 0..8 {
            let offset = i * 8;
            r[i] = u64::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
        }
        Self { r }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        for i in 0..8 {
            let offset = i * 8;
            bytes[offset..offset + 8].copy_from_slice(&self.r[i].to_le_bytes());
        }
        bytes
    }
}

/// Floating point register (128-bit = 2 x 64-bit doubles)
/// Uses soft-float for deterministic zkVM execution
#[derive(Clone, Copy, Debug)]
pub struct FloatRegister {
    pub lo: SoftFloat,
    pub hi: SoftFloat,
}

impl FloatRegister {
    pub fn new() -> Self {
        Self {
            lo: SoftFloat::zero(),
            hi: SoftFloat::zero(),
        }
    }

    pub fn from_u64(lo: u64, hi: u64) -> Self {
        Self {
            lo: SoftFloat::from_bits(lo),
            hi: SoftFloat::from_bits(hi),
        }
    }

    pub fn to_u64(&self) -> (u64, u64) {
        (self.lo.to_bits(), self.hi.to_bits())
    }

    pub fn xor(&mut self, other: &FloatRegister) {
        self.lo = SoftFloat::from_bits(self.lo.to_bits() ^ other.lo.to_bits());
        self.hi = SoftFloat::from_bits(self.hi.to_bits() ^ other.hi.to_bits());
    }

    pub fn swap(&mut self) {
        core::mem::swap(&mut self.lo, &mut self.hi);
    }

    /// Add with rounding mode
    pub fn add(&mut self, other: &FloatRegister, rm: RoundingMode) {
        self.lo = self.lo.add(other.lo, rm);
        self.hi = self.hi.add(other.hi, rm);
    }

    /// Subtract with rounding mode
    pub fn sub(&mut self, other: &FloatRegister, rm: RoundingMode) {
        self.lo = self.lo.sub(other.lo, rm);
        self.hi = self.hi.sub(other.hi, rm);
    }

    /// Multiply with rounding mode
    pub fn mul(&mut self, other: &FloatRegister, rm: RoundingMode) {
        self.lo = self.lo.mul(other.lo, rm);
        self.hi = self.hi.mul(other.hi, rm);
    }

    /// Divide with rounding mode
    pub fn div(&mut self, other: &FloatRegister, rm: RoundingMode) {
        self.lo = self.lo.div(other.lo, rm);
        self.hi = self.hi.div(other.hi, rm);
    }

    /// Square root with rounding mode (takes abs first)
    pub fn sqrt(&mut self, rm: RoundingMode) {
        self.lo = self.lo.abs().sqrt(rm);
        self.hi = self.hi.abs().sqrt(rm);
    }
}

/// Floating point register file
#[derive(Clone, Debug)]
pub struct FloatRegisters {
    /// F registers (for additive operations)
    pub f: [FloatRegister; RANDOMX_FLOAT_REGISTER_COUNT],
    /// E registers (for multiplicative operations, with dynamic exponent)
    pub e: [FloatRegister; RANDOMX_FLOAT_REGISTER_COUNT],
    /// A registers (read-only, initialized from input)
    pub a: [FloatRegister; RANDOMX_FLOAT_REGISTER_COUNT],
}

impl FloatRegisters {
    pub fn new() -> Self {
        Self {
            f: [FloatRegister::new(); 4],
            e: [FloatRegister::new(); 4],
            a: [FloatRegister::new(); 4],
        }
    }

    /// Initialize A registers from input data
    pub fn init_a(&mut self, data: &[u8; 64]) {
        for i in 0..4 {
            let offset = i * 16;
            let lo = u64::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let hi = u64::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);

            // Convert to valid floating point (small magnitude)
            self.a[i] = self.to_small_positive_float(lo, hi);
        }
    }

    /// Convert integer to small positive float for A registers
    fn to_small_positive_float(&self, lo: u64, hi: u64) -> FloatRegister {
        // Mantissa only, exponent set to create small numbers
        let mask = MANTISSA_MASK;
        let exp = STATIC_EXPONENT << MANTISSA_SIZE;

        FloatRegister {
            lo: SoftFloat::from_bits((lo & mask) | exp),
            hi: SoftFloat::from_bits((hi & mask) | exp),
        }
    }
}

/// Configuration for E register exponents
#[derive(Clone, Debug)]
pub struct ERegisterConfig {
    pub mask: [u64; 2],
}

impl ERegisterConfig {
    pub fn new(entropy: &[u64; 4]) -> Self {
        let mut mask = [0u64; 2];

        // Configure E register masks from entropy
        // These control the dynamic exponent range
        for i in 0..2 {
            let tmp = entropy[i];
            // Extract exponent configuration
            let exp = ((tmp >> 59) & 0xF) as u32; // 4 bits for exponent
            mask[i] = (exp as u64 + EXPONENT_BIAS) << MANTISSA_SIZE;
            mask[i] |= SCALE_MASK;
        }

        Self { mask }
    }
}

/// Memory address configuration
#[derive(Clone, Debug)]
pub struct MemoryConfig {
    /// Memory address register A
    pub ma: u32,
    /// Memory address register X
    pub mx: u32,
    /// Read address mask for L1
    pub read_reg_0: usize,
    /// Read address mask for L2
    pub read_reg_1: usize,
    /// Read address mask for L3
    pub read_reg_2: usize,
    pub read_reg_3: usize,
    /// Address mask for dataset reads
    pub dataset_offset: usize,
}

impl MemoryConfig {
    pub fn new(entropy: &[u64; 4]) -> Self {
        Self {
            ma: (entropy[0] & 0xFFFFFFFF) as u32,
            mx: (entropy[0] >> 32) as u32,
            read_reg_0: ((entropy[2] >> 0) & 0x3) as usize,
            read_reg_1: ((entropy[2] >> 2) & 0x3) as usize,
            read_reg_2: ((entropy[2] >> 4) & 0x3) as usize,
            read_reg_3: ((entropy[2] >> 6) & 0x3) as usize,
            dataset_offset: 0,
        }
    }
}

/// Full VM state
pub struct VmState {
    /// Integer registers
    pub int_regs: IntRegisters,
    /// Floating point registers
    pub float_regs: FloatRegisters,
    /// E register configuration
    pub e_config: ERegisterConfig,
    /// Memory configuration
    pub mem_config: MemoryConfig,
    /// Scratchpad memory
    pub scratchpad: alloc::vec::Vec<u8>,
    /// Current rounding mode (0-3)
    pub rounding_mode: u8,
    /// Instruction counter
    pub ic: usize,
    /// Program counter for CBRANCH
    pub pc: usize,
}

impl VmState {
    pub fn new(scratchpad_size: usize) -> Self {
        Self {
            int_regs: IntRegisters::new(),
            float_regs: FloatRegisters::new(),
            e_config: ERegisterConfig { mask: [0; 2] },
            mem_config: MemoryConfig {
                ma: 0,
                mx: 0,
                read_reg_0: 0,
                read_reg_1: 0,
                read_reg_2: 0,
                read_reg_3: 0,
                dataset_offset: 0,
            },
            scratchpad: alloc::vec![0u8; scratchpad_size],
            rounding_mode: 0,
            ic: 0,
            pc: 0,
        }
    }

    /// Initialize VM state from seed and program entropy
    pub fn init(&mut self, seed: &[u8; 64], entropy: &[u64; 16]) {
        // Initialize integer registers from first 64 bytes
        self.int_regs = IntRegisters::from_bytes(seed);

        // Initialize A registers
        self.float_regs.init_a(seed);

        // Configure E registers
        self.e_config = ERegisterConfig::new(&[entropy[0], entropy[1], entropy[2], entropy[3]]);

        // Configure memory
        self.mem_config = MemoryConfig::new(&[entropy[4], entropy[5], entropy[6], entropy[7]]);

        // Reset counters
        self.ic = 0;
        self.pc = 0;
        self.rounding_mode = 0;
    }

    /// Read 64-bit value from scratchpad
    pub fn read_u64(&self, addr: usize) -> u64 {
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
    pub fn write_u64(&mut self, addr: usize, value: u64) {
        let addr = addr & (self.scratchpad.len() - 8);
        let bytes = value.to_le_bytes();
        self.scratchpad[addr..addr + 8].copy_from_slice(&bytes);
    }

    /// Read 128-bit value as float register from scratchpad
    pub fn read_float(&self, addr: usize) -> FloatRegister {
        let addr = addr & (self.scratchpad.len() - 16);
        let lo = self.read_u64(addr);
        let hi = self.read_u64(addr + 8);
        FloatRegister::from_u64(lo, hi)
    }

    /// Get scratchpad L1 address
    pub fn l1_addr(&self, offset: u32, reg_value: u64) -> usize {
        let addr = (reg_value as u32).wrapping_add(offset);
        (addr as usize) & SCRATCHPAD_L1_MASK
    }

    /// Get scratchpad L2 address
    pub fn l2_addr(&self, offset: u32, reg_value: u64) -> usize {
        let addr = (reg_value as u32).wrapping_add(offset);
        (addr as usize) & SCRATCHPAD_L2_MASK
    }

    /// Get scratchpad L3 address
    pub fn l3_addr(&self, offset: u32, reg_value: u64) -> usize {
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
    fn execute_instruction(&mut self, instr: &crate::randomx::program::Instruction) {
        use crate::randomx::config::Opcode::*;

        let dst = instr.dst as usize;
        let src = instr.src as usize;
        let imm = instr.imm;
        let mod_val = instr.mod_val;

        match instr.opcode {
            IADD_RS => {
                // dst = dst + (src << shift)
                let shift = (mod_val >> 2) & 3;
                let src_val = if src == dst {
                    imm as u64
                } else {
                    self.int_regs.r[src]
                };
                self.int_regs.r[dst] = self.int_regs.r[dst].wrapping_add(src_val << shift);
            }

            IADD_M => {
                // dst = dst + [mem]
                let addr = self.l3_addr(imm as u32, self.int_regs.r[src]);
                let mem_val = self.read_u64(addr);
                self.int_regs.r[dst] = self.int_regs.r[dst].wrapping_add(mem_val);
            }

            ISUB_R => {
                // dst = dst - src
                let src_val = if src == dst {
                    imm as u64
                } else {
                    self.int_regs.r[src]
                };
                self.int_regs.r[dst] = self.int_regs.r[dst].wrapping_sub(src_val);
            }

            ISUB_M => {
                // dst = dst - [mem]
                let addr = self.l3_addr(imm as u32, self.int_regs.r[src]);
                let mem_val = self.read_u64(addr);
                self.int_regs.r[dst] = self.int_regs.r[dst].wrapping_sub(mem_val);
            }

            IMUL_R => {
                // dst = dst * src
                let src_val = if src == dst {
                    imm as u64
                } else {
                    self.int_regs.r[src]
                };
                self.int_regs.r[dst] = self.int_regs.r[dst].wrapping_mul(src_val);
            }

            IMUL_M => {
                // dst = dst * [mem]
                let addr = self.l3_addr(imm as u32, self.int_regs.r[src]);
                let mem_val = self.read_u64(addr);
                self.int_regs.r[dst] = self.int_regs.r[dst].wrapping_mul(mem_val);
            }

            IMULH_R => {
                // dst = (dst * src) >> 64 (unsigned)
                let a = self.int_regs.r[dst] as u128;
                let b = self.int_regs.r[src] as u128;
                self.int_regs.r[dst] = ((a * b) >> 64) as u64;
            }

            IMULH_M => {
                // dst = (dst * [mem]) >> 64 (unsigned)
                let addr = self.l3_addr(imm as u32, self.int_regs.r[src]);
                let mem_val = self.read_u64(addr);
                let a = self.int_regs.r[dst] as u128;
                let b = mem_val as u128;
                self.int_regs.r[dst] = ((a * b) >> 64) as u64;
            }

            ISMULH_R => {
                // dst = (dst * src) >> 64 (signed)
                let a = self.int_regs.r[dst] as i64 as i128;
                let b = self.int_regs.r[src] as i64 as i128;
                self.int_regs.r[dst] = ((a * b) >> 64) as u64;
            }

            ISMULH_M => {
                // dst = (dst * [mem]) >> 64 (signed)
                let addr = self.l3_addr(imm as u32, self.int_regs.r[src]);
                let mem_val = self.read_u64(addr) as i64;
                let a = self.int_regs.r[dst] as i64 as i128;
                let b = mem_val as i128;
                self.int_regs.r[dst] = ((a * b) >> 64) as u64;
            }

            IMUL_RCP => {
                // dst = dst * reciprocal(imm)
                let imm_u64 = imm as u64;
                if imm != 0 && !imm_u64.is_power_of_two() {
                    let rcp = reciprocal(imm_u64);
                    self.int_regs.r[dst] = self.int_regs.r[dst].wrapping_mul(rcp);
                }
            }

            INEG_R => {
                // dst = -dst
                self.int_regs.r[dst] = (-(self.int_regs.r[dst] as i64)) as u64;
            }

            IXOR_R => {
                // dst = dst ^ src
                let src_val = if src == dst {
                    imm as u64
                } else {
                    self.int_regs.r[src]
                };
                self.int_regs.r[dst] ^= src_val;
            }

            IXOR_M => {
                // dst = dst ^ [mem]
                let addr = self.l3_addr(imm as u32, self.int_regs.r[src]);
                let mem_val = self.read_u64(addr);
                self.int_regs.r[dst] ^= mem_val;
            }

            IROR_R => {
                // dst = dst >>> (src & 63)
                let src_val = if src == dst { imm as u64 } else { self.int_regs.r[src] };
                let shift = (src_val & 63) as u32;
                self.int_regs.r[dst] = self.int_regs.r[dst].rotate_right(shift);
            }

            IROL_R => {
                // dst = dst <<< (src & 63)
                let src_val = if src == dst { imm as u64 } else { self.int_regs.r[src] };
                let shift = (src_val & 63) as u32;
                self.int_regs.r[dst] = self.int_regs.r[dst].rotate_left(shift);
            }

            ISWAP_R => {
                // swap dst and src
                if dst != src {
                    let tmp = self.int_regs.r[dst];
                    self.int_regs.r[dst] = self.int_regs.r[src];
                    self.int_regs.r[src] = tmp;
                }
            }

            FSWAP_R => {
                // swap lo and hi of F or E register
                let reg_idx = dst & 3;
                if dst < 4 {
                    self.float_regs.f[reg_idx].swap();
                } else {
                    self.float_regs.e[reg_idx].swap();
                }
            }

            FADD_R => {
                // F[dst] = F[dst] + A[src] (using soft-float with rounding mode)
                let dst_idx = dst & 3;
                let src_idx = src & 3;
                let rm = RoundingMode::from(self.rounding_mode);
                let src_reg = self.float_regs.a[src_idx];
                self.float_regs.f[dst_idx].add(&src_reg, rm);
            }

            FADD_M => {
                // F[dst] = F[dst] + [mem] (using soft-float with rounding mode)
                let dst_idx = dst & 3;
                let addr = self.l3_addr(imm as u32, self.int_regs.r[src]);
                let mem_float = self.read_float(addr);
                let rm = RoundingMode::from(self.rounding_mode);
                self.float_regs.f[dst_idx].add(&mem_float, rm);
            }

            FSUB_R => {
                // F[dst] = F[dst] - A[src] (using soft-float with rounding mode)
                let dst_idx = dst & 3;
                let src_idx = src & 3;
                let rm = RoundingMode::from(self.rounding_mode);
                let src_reg = self.float_regs.a[src_idx];
                self.float_regs.f[dst_idx].sub(&src_reg, rm);
            }

            FSUB_M => {
                // F[dst] = F[dst] - [mem] (using soft-float with rounding mode)
                let dst_idx = dst & 3;
                let addr = self.l3_addr(imm as u32, self.int_regs.r[src]);
                let mem_float = self.read_float(addr);
                let rm = RoundingMode::from(self.rounding_mode);
                self.float_regs.f[dst_idx].sub(&mem_float, rm);
            }

            FSCAL_R => {
                // Scale F register by negating exponent bits (bit manipulation, no FPU needed)
                let dst_idx = dst & 3;
                self.float_regs.f[dst_idx].lo =
                    SoftFloat::from_bits(self.float_regs.f[dst_idx].lo.to_bits() ^ SCALE_MASK);
                self.float_regs.f[dst_idx].hi =
                    SoftFloat::from_bits(self.float_regs.f[dst_idx].hi.to_bits() ^ SCALE_MASK);
            }

            FMUL_R => {
                // E[dst] = E[dst] * A[src] (using soft-float with rounding mode)
                let dst_idx = dst & 3;
                let src_idx = src & 3;
                let rm = RoundingMode::from(self.rounding_mode);
                let src_reg = self.float_regs.a[src_idx];
                self.float_regs.e[dst_idx].mul(&src_reg, rm);
            }

            FDIV_M => {
                // E[dst] = E[dst] / [mem] (using soft-float with rounding mode)
                let dst_idx = dst & 3;
                let addr = self.l3_addr(imm as u32, self.int_regs.r[src]);
                let mem_float = self.read_float(addr);
                // Apply E register mask to ensure valid divisor
                let mask_idx = dst_idx & 1;
                let divisor = FloatRegister {
                    lo: SoftFloat::from_bits((mem_float.lo.to_bits() & DYNAMIC_MANTISSA_MASK) | self.e_config.mask[mask_idx]),
                    hi: SoftFloat::from_bits((mem_float.hi.to_bits() & DYNAMIC_MANTISSA_MASK) | self.e_config.mask[mask_idx]),
                };
                let rm = RoundingMode::from(self.rounding_mode);
                self.float_regs.e[dst_idx].div(&divisor, rm);
            }

            FSQRT_R => {
                // E[dst] = sqrt(abs(E[dst])) (using soft-float with rounding mode)
                let dst_idx = dst & 3;
                let rm = RoundingMode::from(self.rounding_mode);
                self.float_regs.e[dst_idx].sqrt(rm);
            }

            CBRANCH => {
                // Conditional branch
                let condition_mask = (1u64 << RANDOMX_JUMP_BITS) - 1;
                let condition_shift = RANDOMX_JUMP_OFFSET;

                self.int_regs.r[dst] = self.int_regs.r[dst].wrapping_add(imm as u64);

                if (self.int_regs.r[dst] >> condition_shift) & condition_mask == 0 {
                    // Branch taken - jump backwards
                    let target = instr.target as usize;
                    if target < self.pc {
                        self.pc = target;
                    }
                }
            }

            CFROUND => {
                // Set rounding mode
                let src_val = self.int_regs.r[src];
                let shift = (imm & 63) as u32;
                self.rounding_mode = ((src_val >> shift) & 3) as u8;
            }

            ISTORE => {
                // [mem] = src
                let addr = self.l3_addr(imm as u32, self.int_regs.r[dst]);
                self.write_u64(addr, self.int_regs.r[src]);
            }

            NOP => {
                // No operation
            }
        }
    }

    /// Get register file as bytes for hashing
    pub fn get_register_file(&self) -> [u8; 256] {
        let mut result = [0u8; 256];

        // Integer registers (64 bytes)
        result[0..64].copy_from_slice(&self.int_regs.to_bytes());

        // F registers (64 bytes)
        for i in 0..4 {
            let offset = 64 + i * 16;
            let (lo, hi) = self.float_regs.f[i].to_u64();
            result[offset..offset + 8].copy_from_slice(&lo.to_le_bytes());
            result[offset + 8..offset + 16].copy_from_slice(&hi.to_le_bytes());
        }

        // E registers (64 bytes)
        for i in 0..4 {
            let offset = 128 + i * 16;
            let (lo, hi) = self.float_regs.e[i].to_u64();
            result[offset..offset + 8].copy_from_slice(&lo.to_le_bytes());
            result[offset + 8..offset + 16].copy_from_slice(&hi.to_le_bytes());
        }

        // A registers (64 bytes)
        for i in 0..4 {
            let offset = 192 + i * 16;
            let (lo, hi) = self.float_regs.a[i].to_u64();
            result[offset..offset + 8].copy_from_slice(&lo.to_le_bytes());
            result[offset + 8..offset + 16].copy_from_slice(&hi.to_le_bytes());
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

extern crate alloc;
