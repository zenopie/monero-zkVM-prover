//! Soft-float wrapper using native Rust f64
//!
//! Uses native Rust f64 which compiles to LLVM's soft-float on rv32im.
//! This is deterministic and IEEE 754 compliant.
//! Currently uses round-to-nearest-even for all operations (rounding modes ignored).

use libm;

/// Rounding modes (IEEE 754) - matches RandomX CFROUND instruction
/// NOTE: Currently ignored - all ops use round-to-nearest-even
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum RoundingMode {
    /// Round to nearest, ties to even (default)
    NearestEven = 0,
    /// Round toward zero (truncate)
    TowardZero = 1,
    /// Round toward positive infinity (ceiling)
    TowardPositive = 2,
    /// Round toward negative infinity (floor)
    TowardNegative = 3,
}

impl From<u8> for RoundingMode {
    fn from(val: u8) -> Self {
        match val & 3 {
            0 => RoundingMode::NearestEven,
            1 => RoundingMode::TowardZero,
            2 => RoundingMode::TowardPositive,
            3 => RoundingMode::TowardNegative,
            _ => unreachable!(),
        }
    }
}

/// Soft-float double precision number wrapper using native f64
#[derive(Clone, Copy, Debug)]
pub struct SoftFloat {
    inner: f64,
}

impl SoftFloat {
    /// Create from raw bits
    #[inline]
    pub fn from_bits(bits: u64) -> Self {
        Self {
            inner: f64::from_bits(bits),
        }
    }

    /// Get raw bits
    #[inline]
    pub fn to_bits(self) -> u64 {
        self.inner.to_bits()
    }

    /// Create zero
    #[inline]
    pub fn zero() -> Self {
        Self { inner: 0.0 }
    }

    /// Absolute value (clear sign bit)
    #[inline]
    pub fn abs(self) -> Self {
        Self {
            inner: libm::fabs(self.inner),
        }
    }

    /// Addition (rounding mode ignored - uses round-to-nearest-even)
    #[inline]
    pub fn add(self, other: Self, _rm: RoundingMode) -> Self {
        Self {
            inner: self.inner + other.inner,
        }
    }

    /// Subtraction (rounding mode ignored - uses round-to-nearest-even)
    #[inline]
    pub fn sub(self, other: Self, _rm: RoundingMode) -> Self {
        Self {
            inner: self.inner - other.inner,
        }
    }

    /// Multiplication (rounding mode ignored - uses round-to-nearest-even)
    #[inline]
    pub fn mul(self, other: Self, _rm: RoundingMode) -> Self {
        Self {
            inner: self.inner * other.inner,
        }
    }

    /// Division (rounding mode ignored - uses round-to-nearest-even)
    #[inline]
    pub fn div(self, other: Self, _rm: RoundingMode) -> Self {
        Self {
            inner: self.inner / other.inner,
        }
    }

    /// Square root (rounding mode ignored - uses round-to-nearest-even)
    #[inline]
    pub fn sqrt(self, _rm: RoundingMode) -> Self {
        Self {
            inner: libm::sqrt(self.inner),
        }
    }
}
