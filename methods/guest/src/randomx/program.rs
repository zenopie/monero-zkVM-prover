//! RandomX Program Generation
//!
//! RandomX programs are generated from a seed using AES.
//! Each program consists of 256 instructions.

use crate::randomx::aes::AesGenerator;
use crate::randomx::config::*;

/// A single RandomX instruction
#[derive(Clone, Debug)]
pub struct Instruction {
    /// Opcode
    pub opcode: Opcode,
    /// Destination register (0-7 for int, 0-3 for float)
    pub dst: u8,
    /// Source register
    pub src: u8,
    /// Modifier value (for shifts, etc.)
    pub mod_val: u8,
    /// 32-bit immediate value
    pub imm: i32,
    /// Branch target (for CBRANCH)
    pub target: i32,
}

impl Instruction {
    /// Create a new instruction from raw bytes
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        let opcode_byte = bytes[0];
        let dst = bytes[1] & 0x07; // 3 bits
        let src = bytes[2] & 0x07; // 3 bits
        let mod_val = bytes[3];
        let imm = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let opcode = opcode_from_byte(opcode_byte);

        Self {
            opcode,
            dst,
            src,
            mod_val,
            imm,
            target: 0, // Set later for CBRANCH
        }
    }

    /// Create a NOP instruction
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

/// A complete RandomX program (256 instructions)
#[derive(Clone)]
pub struct Program {
    pub instructions: [Instruction; RANDOMX_PROGRAM_SIZE],
    /// Program entropy (16 x 64-bit values)
    pub entropy: [u64; 16],
}

impl Program {
    /// Generate a program from a seed
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

        // Generate instructions (256 x 8 bytes = 2048 bytes)
        let mut instructions: [Instruction; RANDOMX_PROGRAM_SIZE] =
            core::array::from_fn(|_| Instruction::nop());

        let mut branch_count = 0;

        for i in 0..RANDOMX_PROGRAM_SIZE {
            let block = gen.next_block();
            let mut instr = Instruction::from_bytes(&[
                block[0], block[1], block[2], block[3],
                block[4], block[5], block[6], block[7],
            ]);

            // Handle CBRANCH target calculation
            if instr.opcode == Opcode::CBRANCH {
                // Calculate branch target (backwards only)
                let target_offset = (instr.mod_val as i32) - 128; // -128 to +127
                let target = (i as i32 + target_offset).max(0) as i32;
                instr.target = target.min(i as i32) as i32;
                branch_count += 1;

                // Limit number of branches
                if branch_count > 8 {
                    instr.opcode = Opcode::NOP;
                }
            }

            instructions[i] = instr;
        }

        Self {
            instructions,
            entropy,
        }
    }

    /// Get entropy as bytes
    pub fn entropy_bytes(&self) -> [u8; 128] {
        let mut result = [0u8; 128];
        for (i, &e) in self.entropy.iter().enumerate() {
            result[i * 8..(i + 1) * 8].copy_from_slice(&e.to_le_bytes());
        }
        result
    }
}

/// Superscalar program for dataset generation
/// This is a simplified version - full implementation would need
/// dependency tracking for optimal scheduling
#[derive(Clone)]
pub struct SuperscalarProgram {
    pub instructions: alloc::vec::Vec<SuperscalarInstruction>,
}

#[derive(Clone, Debug)]
pub struct SuperscalarInstruction {
    pub opcode: SuperscalarOpcode,
    pub dst: u8,
    pub src: u8,
    pub imm: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuperscalarOpcode {
    ISUB_R,
    IXOR_R,
    IADD_RS,
    IMUL_R,
    IROR_C,
    IADD_C,
    IXOR_C,
    IMULH_R,
    ISMULH_R,
    IMUL_RCP,
}

impl SuperscalarProgram {
    /// Generate a superscalar program for dataset item generation
    pub fn generate(seed: &[u8]) -> Self {
        use crate::randomx::blake2b::Blake2Generator;

        let mut gen = Blake2Generator::new(seed);
        let mut instructions = alloc::vec::Vec::with_capacity(SUPERSCALAR_LATENCY);

        // Generate instructions until we reach target latency
        let mut total_latency = 0;

        while total_latency < SUPERSCALAR_LATENCY && instructions.len() < 256 {
            let opcode_byte = gen.next_byte();
            let (opcode, latency) = match opcode_byte % 10 {
                0 => (SuperscalarOpcode::ISUB_R, 1),
                1 => (SuperscalarOpcode::IXOR_R, 1),
                2 => (SuperscalarOpcode::IADD_RS, 1),
                3 => (SuperscalarOpcode::IMUL_R, 3),
                4 => (SuperscalarOpcode::IROR_C, 1),
                5 => (SuperscalarOpcode::IADD_C, 1),
                6 => (SuperscalarOpcode::IXOR_C, 1),
                7 => (SuperscalarOpcode::IMULH_R, 4),
                8 => (SuperscalarOpcode::ISMULH_R, 4),
                _ => (SuperscalarOpcode::IMUL_RCP, 4),
            };

            let dst = gen.next_byte() & 0x07;
            let src = gen.next_byte() & 0x07;
            let imm = gen.next_u64();

            instructions.push(SuperscalarInstruction {
                opcode,
                dst,
                src,
                imm,
            });

            total_latency += latency;
        }

        Self { instructions }
    }

    /// Execute superscalar program on register file
    pub fn execute(&self, regs: &mut [u64; 8]) {
        for instr in &self.instructions {
            let dst = instr.dst as usize;
            let src = instr.src as usize;

            match instr.opcode {
                SuperscalarOpcode::ISUB_R => {
                    regs[dst] = regs[dst].wrapping_sub(regs[src]);
                }
                SuperscalarOpcode::IXOR_R => {
                    regs[dst] ^= regs[src];
                }
                SuperscalarOpcode::IADD_RS => {
                    let shift = ((instr.imm >> 32) & 3) as u32;
                    regs[dst] = regs[dst].wrapping_add(regs[src] << shift);
                }
                SuperscalarOpcode::IMUL_R => {
                    regs[dst] = regs[dst].wrapping_mul(regs[src]);
                }
                SuperscalarOpcode::IROR_C => {
                    let shift = (instr.imm & 63) as u32;
                    regs[dst] = regs[dst].rotate_right(shift);
                }
                SuperscalarOpcode::IADD_C => {
                    regs[dst] = regs[dst].wrapping_add(instr.imm);
                }
                SuperscalarOpcode::IXOR_C => {
                    regs[dst] ^= instr.imm;
                }
                SuperscalarOpcode::IMULH_R => {
                    let a = regs[dst] as u128;
                    let b = regs[src] as u128;
                    regs[dst] = ((a * b) >> 64) as u64;
                }
                SuperscalarOpcode::ISMULH_R => {
                    let a = regs[dst] as i64 as i128;
                    let b = regs[src] as i64 as i128;
                    regs[dst] = ((a * b) >> 64) as u64;
                }
                SuperscalarOpcode::IMUL_RCP => {
                    if instr.imm != 0 && !instr.imm.is_power_of_two() {
                        let rcp = reciprocal(instr.imm);
                        regs[dst] = regs[dst].wrapping_mul(rcp);
                    }
                }
            }
        }
    }
}

/// Compute modular multiplicative inverse
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
