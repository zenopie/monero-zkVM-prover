//! Python bindings for Monero RandomX zkVM Prover

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use host::{
    ProverConfig as RustProverConfig,
    ProofMode as RustProofMode,
    ProofResult as RustProofResult,
    PrepCache as RustPrepCache,
};
use std::sync::Arc;

/// Result of a proving operation
#[pyclass]
#[derive(Clone)]
pub struct ProofResult {
    #[pyo3(get)]
    pub success: bool,
    #[pyo3(get)]
    pub pow_hash: Option<String>,
    #[pyo3(get)]
    pub difficulty_valid: Option<bool>,
    #[pyo3(get)]
    pub merkle_root: Option<String>,
    #[pyo3(get)]
    pub cache_hash: Option<String>,
    #[pyo3(get)]
    pub total_cycles: u64,
    #[pyo3(get)]
    pub proving_time_secs: u64,
    #[pyo3(get)]
    pub error: Option<String>,
}

impl From<RustProofResult> for ProofResult {
    fn from(r: RustProofResult) -> Self {
        ProofResult {
            success: r.success,
            pow_hash: r.pow_hash.map(|h| hex::encode(h)),
            difficulty_valid: r.difficulty_valid,
            merkle_root: r.merkle_root.map(|h| hex::encode(h)),
            cache_hash: r.cache_hash.map(|h| hex::encode(h)),
            total_cycles: r.total_cycles,
            proving_time_secs: r.proving_time_secs,
            error: r.error,
        }
    }
}

#[pymethods]
impl ProofResult {
    fn __repr__(&self) -> String {
        if self.success {
            format!(
                "ProofResult(success=True, cycles={}, time={}s)",
                self.total_cycles, self.proving_time_secs
            )
        } else {
            format!(
                "ProofResult(success=False, error={:?})",
                self.error
            )
        }
    }
}

/// Cached prep data for fast segment proving
/// Expensive to build (~10 mins), but reusable for ~2048 blocks with same RandomX key
#[pyclass]
pub struct PrepCache {
    inner: Arc<RustPrepCache>,
}

#[pymethods]
impl PrepCache {
    /// Build prep cache from RandomX key (SLOW - ~10 mins)
    #[staticmethod]
    fn build(randomx_key: &str) -> PyResult<Self> {
        let key = parse_hex_key(randomx_key)?;
        let inner = RustPrepCache::build(key);
        Ok(Self { inner: Arc::new(inner) })
    }

    /// Load prep cache from disk (FAST)
    #[staticmethod]
    fn load(randomx_key: &str) -> PyResult<Option<Self>> {
        let key = parse_hex_key(randomx_key)?;
        Ok(RustPrepCache::load(&key).map(|p| Self { inner: Arc::new(p) }))
    }

    /// Load from disk or build if not cached
    #[staticmethod]
    fn load_or_build(randomx_key: &str) -> PyResult<Self> {
        let key = parse_hex_key(randomx_key)?;
        let inner = RustPrepCache::load_or_build(key);
        Ok(Self { inner: Arc::new(inner) })
    }

    /// Save prep cache to disk
    fn save(&self) -> PyResult<()> {
        self.inner.save()
            .map_err(|e| PyValueError::new_err(format!("Failed to save cache: {}", e)))
    }

    /// Get the RandomX key this cache was built for
    fn randomx_key(&self) -> String {
        hex::encode(self.inner.randomx_key)
    }

    /// Get the merkle root
    fn merkle_root(&self) -> String {
        hex::encode(self.inner.merkle_root)
    }

    fn __repr__(&self) -> String {
        format!("PrepCache(key={}...)", &hex::encode(&self.inner.randomx_key[..8]))
    }
}

fn parse_hex_key(s: &str) -> PyResult<[u8; 32]> {
    let bytes = hex::decode(s)
        .map_err(|e| PyValueError::new_err(format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "randomx_key must be 32 bytes, got {}", bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex_blob(s: &str) -> PyResult<Vec<u8>> {
    let bytes = hex::decode(s)
        .map_err(|e| PyValueError::new_err(format!("Invalid hex: {}", e)))?;
    if bytes.len() < 43 {
        return Err(PyValueError::new_err(format!(
            "hashing_blob must be at least 43 bytes, got {}", bytes.len()
        )));
    }
    Ok(bytes)
}

/// Prove a single block segment using cached prep data (FAST - for production)
///
/// Args:
///     prep: PrepCache object (build once, reuse for ~2048 blocks)
///     hashing_blob: Block hashing blob as hex string
///     difficulty: Target difficulty
///     segment: Segment index (0-255)
///
/// Returns:
///     ProofResult
#[pyfunction]
fn prove_segment(
    prep: &PrepCache,
    hashing_blob: &str,
    difficulty: u64,
    segment: usize,
) -> PyResult<ProofResult> {
    let blob = parse_hex_blob(hashing_blob)?;
    Ok(host::prove_block_segment_cached(&prep.inner, &blob, difficulty, segment).into())
}

/// Prove full cache (64 segments)
#[pyfunction]
#[pyo3(signature = (randomx_key, resume=false))]
fn prove_cache(randomx_key: &str, resume: bool) -> PyResult<ProofResult> {
    let config = RustProverConfig::new(
        parse_hex_key(randomx_key)?,
        vec![],
        1,
    ).with_mode(RustProofMode::Cache)
     .with_resume(resume);

    Ok(host::prove_cache(&config).into())
}

/// Prove block PoW (8 programs)
#[pyfunction]
#[pyo3(signature = (randomx_key, hashing_blob, difficulty, resume=false))]
fn prove_block(
    randomx_key: &str,
    hashing_blob: &str,
    difficulty: u64,
    resume: bool,
) -> PyResult<ProofResult> {
    let config = RustProverConfig::new(
        parse_hex_key(randomx_key)?,
        parse_hex_blob(hashing_blob)?,
        difficulty,
    ).with_mode(RustProofMode::Block)
     .with_resume(resume);

    Ok(host::prove_block(&config).into())
}

/// Prove full (cache + block)
#[pyfunction]
#[pyo3(signature = (randomx_key, hashing_blob, difficulty, resume=false))]
fn prove_full(
    randomx_key: &str,
    hashing_blob: &str,
    difficulty: u64,
    resume: bool,
) -> PyResult<ProofResult> {
    let config = RustProverConfig::new(
        parse_hex_key(randomx_key)?,
        parse_hex_blob(hashing_blob)?,
        difficulty,
    ).with_mode(RustProofMode::Full)
     .with_resume(resume);

    Ok(host::prove_full(&config).into())
}

/// Get the library version
#[pyfunction]
fn version() -> &'static str {
    host::VERSION
}

#[pymodule]
fn monero_zkvm_prover(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ProofResult>()?;
    m.add_class::<PrepCache>()?;
    m.add_function(wrap_pyfunction!(prove_segment, m)?)?;
    m.add_function(wrap_pyfunction!(prove_cache, m)?)?;
    m.add_function(wrap_pyfunction!(prove_block, m)?)?;
    m.add_function(wrap_pyfunction!(prove_full, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;

    // Monero RandomX constants
    m.add("CACHE_SIZE", host::CACHE_SIZE)?;
    m.add("CACHE_SEGMENTS", host::CACHE_SEGMENTS)?;
    m.add("SCRATCHPAD_SIZE", host::SCRATCHPAD_SIZE)?;
    m.add("PROGRAM_COUNT", host::PROGRAM_COUNT)?;
    m.add("ITERATIONS", host::ITERATIONS)?;
    m.add("BLOCK_SEGMENTS", 256)?;  // 8 programs × 32 chunks

    Ok(())
}
