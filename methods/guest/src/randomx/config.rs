//! RandomX Configuration Constants
//!
//! These values are from the official RandomX specification.
//! Monero uses the default configuration.

/// Scratchpad L3 size: 2 MiB (this is the correct value for RandomX light mode)
/// Note: The 256 MiB refers to the CACHE size, not scratchpad
pub const RANDOMX_SCRATCHPAD_L3: usize = 2097152; // 2 MiB - correct for RandomX
/// L2 cache size: 256 KiB
pub const RANDOMX_SCRATCHPAD_L2: usize = 262144;
/// L1 cache size: 16 KiB
pub const RANDOMX_SCRATCHPAD_L1: usize = 16384;

/// Reduced scratchpad for testing
pub const RANDOMX_SCRATCHPAD_L3_REDUCED: usize = 65536; // 64 KiB for quick testing

/// Dataset base size: 2 GiB (fast mode only)
pub const RANDOMX_DATASET_BASE_SIZE: usize = 2147483648;
/// Dataset extra size
pub const RANDOMX_DATASET_EXTRA_SIZE: usize = 33554368;

/// Number of dataset items
pub const RANDOMX_DATASET_ITEM_COUNT: usize = 34078719;
/// Cache size: 256 MiB
pub const RANDOMX_CACHE_SIZE: usize = 268435456;

/// Program size in instructions
pub const RANDOMX_PROGRAM_SIZE: usize = 256;
/// Number of program iterations
pub const RANDOMX_PROGRAM_ITERATIONS: usize = 2048;
/// Number of programs per hash
pub const RANDOMX_PROGRAM_COUNT: usize = 8;

/// Number of integer registers
pub const RANDOMX_INT_REGISTER_COUNT: usize = 8;
/// Number of floating point registers
pub const RANDOMX_FLOAT_REGISTER_COUNT: usize = 4;

/// Condition mask for jumps
pub const RANDOMX_JUMP_BITS: u32 = 8;
pub const RANDOMX_JUMP_OFFSET: u32 = 8;

/// Scratchpad L1 mask (for addressing)
pub const SCRATCHPAD_L1_MASK: usize = RANDOMX_SCRATCHPAD_L1 - 64;
/// Scratchpad L2 mask
pub const SCRATCHPAD_L2_MASK: usize = RANDOMX_SCRATCHPAD_L2 - 64;
/// Scratchpad L3 mask
pub const SCRATCHPAD_L3_MASK: usize = RANDOMX_SCRATCHPAD_L3 - 64;

/// Register file size in bytes
pub const REGISTER_FILE_SIZE: usize = 256;

/// AES block size
pub const AES_BLOCK_SIZE: usize = 16;
/// AES hash state size (4 blocks)
pub const AES_HASH_STATE_SIZE: usize = 64;

/// Mantissa size for float operations
pub const MANTISSA_SIZE: u32 = 52;
/// Mantissa mask
pub const MANTISSA_MASK: u64 = (1u64 << MANTISSA_SIZE) - 1;
/// Exponent size
pub const EXPONENT_SIZE: u32 = 11;
/// Exponent bias
pub const EXPONENT_BIAS: u64 = 1023;
/// Dynamic exponent bits
pub const DYNAMIC_EXPONENT_BITS: u32 = 4;
/// Static exponent
pub const STATIC_EXPONENT: u64 = EXPONENT_BIAS + MANTISSA_SIZE as u64;
/// Dynamic mantissa mask
pub const DYNAMIC_MANTISSA_MASK: u64 = (1u64 << (MANTISSA_SIZE + DYNAMIC_EXPONENT_BITS)) - 1;

/// Scale mask for E registers
pub const SCALE_MASK: u64 = 0x80F0000000000000;

/// Cache line size
pub const CACHE_LINE_SIZE: usize = 64;
/// Cache line align mask
pub const CACHE_LINE_ALIGN_MASK: usize = !(CACHE_LINE_SIZE - 1);

/// Superscalar latency
pub const SUPERSCALAR_LATENCY: usize = 170;

/// Argon2 parameters for cache initialization
pub const ARGON2_MEMORY: u32 = 262144; // 256 MiB in 1 KiB blocks
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_LANES: u32 = 1;
pub const ARGON2_SALT: &[u8] = b"RandomX\x03";

/// Instruction opcodes
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

impl From<u8> for Opcode {
    fn from(val: u8) -> Self {
        match val {
            0 => Opcode::IADD_RS,
            1 => Opcode::IADD_M,
            2 => Opcode::ISUB_R,
            3 => Opcode::ISUB_M,
            4 => Opcode::IMUL_R,
            5 => Opcode::IMUL_M,
            6 => Opcode::IMULH_R,
            7 => Opcode::IMULH_M,
            8 => Opcode::ISMULH_R,
            9 => Opcode::ISMULH_M,
            10 => Opcode::IMUL_RCP,
            11 => Opcode::INEG_R,
            12 => Opcode::IXOR_R,
            13 => Opcode::IXOR_M,
            14 => Opcode::IROR_R,
            15 => Opcode::IROL_R,
            16 => Opcode::ISWAP_R,
            17 => Opcode::FSWAP_R,
            18 => Opcode::FADD_R,
            19 => Opcode::FADD_M,
            20 => Opcode::FSUB_R,
            21 => Opcode::FSUB_M,
            22 => Opcode::FSCAL_R,
            23 => Opcode::FMUL_R,
            24 => Opcode::FDIV_M,
            25 => Opcode::FSQRT_R,
            26 => Opcode::CBRANCH,
            27 => Opcode::CFROUND,
            28 => Opcode::ISTORE,
            _ => Opcode::NOP,
        }
    }
}

/// Instruction frequency table (for program generation)
/// Maps byte ranges to opcodes based on frequency
pub const INSTRUCTION_FREQUENCIES: [(u8, u8, Opcode); 30] = [
    (0, 15, Opcode::IADD_RS),      // 16
    (16, 22, Opcode::IADD_M),      // 7
    (23, 38, Opcode::ISUB_R),      // 16
    (39, 45, Opcode::ISUB_M),      // 7
    (46, 61, Opcode::IMUL_R),      // 16
    (62, 65, Opcode::IMUL_M),      // 4
    (66, 69, Opcode::IMULH_R),     // 4
    (70, 70, Opcode::IMULH_M),     // 1
    (71, 74, Opcode::ISMULH_R),    // 4
    (75, 75, Opcode::ISMULH_M),    // 1
    (76, 83, Opcode::IMUL_RCP),    // 8
    (84, 85, Opcode::INEG_R),      // 2
    (86, 101, Opcode::IXOR_R),     // 16
    (102, 105, Opcode::IXOR_M),    // 4
    (106, 115, Opcode::IROR_R),    // 10
    (116, 125, Opcode::IROL_R),    // 10
    (126, 129, Opcode::ISWAP_R),   // 4
    (130, 137, Opcode::FSWAP_R),   // 8
    (138, 153, Opcode::FADD_R),    // 16
    (154, 158, Opcode::FADD_M),    // 5
    (159, 174, Opcode::FSUB_R),    // 16
    (175, 179, Opcode::FSUB_M),    // 5
    (180, 185, Opcode::FSCAL_R),   // 6
    (186, 217, Opcode::FMUL_R),    // 32
    (218, 221, Opcode::FDIV_M),    // 4
    (222, 227, Opcode::FSQRT_R),   // 6
    (228, 252, Opcode::CBRANCH),   // 25
    (253, 253, Opcode::CFROUND),   // 1
    (254, 255, Opcode::ISTORE),    // 2
    (255, 255, Opcode::NOP),       // placeholder
];

/// Get opcode from frequency byte
pub fn opcode_from_byte(byte: u8) -> Opcode {
    for &(start, end, opcode) in INSTRUCTION_FREQUENCIES.iter() {
        if byte >= start && byte <= end {
            return opcode;
        }
    }
    Opcode::NOP
}
