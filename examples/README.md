# Monero zkVM Prover - Python Examples

## Installation

First, build and install the Python module:

```bash
# From the repository root
cd /path/to/monero-zkvm-prover

# Install maturin if not already installed
pip install maturin

# Build and install the module
maturin develop --release
```

## Examples

### basic_usage.py

Shows the basic API functions:
- `prove_cache()` - Prove cache initialization (Phase 1)
- `prove_block()` - Prove block PoW (Phase 2)
- `prove_full()` - Prove both phases

```bash
python examples/basic_usage.py
```

### segment_proving.py

**Recommended for production** - Shows the fast segment-based workflow:
1. Build `PrepCache` once per RandomX key (~10 mins)
2. Use `prove_segment()` for fast proofs (<2 mins)

```bash
python examples/segment_proving.py
```

## API Reference

### Constants

```python
import monero_zkvm_prover as prover

prover.CACHE_SIZE        # 268435456 (256 MiB)
prover.CACHE_SEGMENTS    # 64
prover.SCRATCHPAD_SIZE   # 2097152 (2 MiB)
prover.PROGRAM_COUNT     # 8
prover.ITERATIONS        # 2048
prover.BLOCK_SEGMENTS    # 256 (8 programs × 32 chunks)
```

### Functions

```python
# Get library version
prover.version() -> str

# Prove cache hash (Phase 1) - ~10 mins
prover.prove_cache(randomx_key: str, resume: bool = False) -> ProofResult

# Prove block PoW (Phase 2) - ~20 mins
prover.prove_block(randomx_key: str, hashing_blob: str, difficulty: int, resume: bool = False) -> ProofResult

# Prove both phases - ~30 mins
prover.prove_full(randomx_key: str, hashing_blob: str, difficulty: int, resume: bool = False) -> ProofResult

# Fast segment proof using cached prep data - <2 mins
prover.prove_segment(prep: PrepCache, hashing_blob: str, difficulty: int, segment: int) -> ProofResult
```

### PrepCache Class

```python
# Build cache from RandomX key (SLOW - ~10 mins)
prep = prover.PrepCache.build(randomx_key: str) -> PrepCache

# Load cache from disk (FAST)
prep = prover.PrepCache.load(randomx_key: str) -> Optional[PrepCache]

# Load or build if not cached
prep = prover.PrepCache.load_or_build(randomx_key: str) -> PrepCache

# Save cache to disk
prep.save() -> None

# Get the RandomX key
prep.randomx_key() -> str

# Get the merkle root
prep.merkle_root() -> str
```

### ProofResult Class

```python
result.success           # bool - True if proof succeeded
result.pow_hash          # Optional[str] - Final PoW hash (hex)
result.difficulty_valid  # Optional[bool] - True if difficulty met
result.merkle_root       # Optional[str] - Dataset merkle root (hex)
result.cache_hash        # Optional[str] - Cache hash (hex)
result.total_cycles      # int - Total RISC0 cycles
result.proving_time_secs # int - Proving time in seconds
result.error             # Optional[str] - Error message if failed
```

## Production Workflow

```python
import monero_zkvm_prover as prover

# 1. Get block data from Monero node
randomx_key = get_randomx_key_for_height(height)  # From blockchain
hashing_blob = get_block_hashing_blob(block)       # From block template
difficulty = get_block_difficulty(block)

# 2. Load or build PrepCache (reusable for ~2048 blocks)
prep = prover.PrepCache.load_or_build(randomx_key)

# 3. Prove random segment(s)
import random
segment = random.randint(0, 255)
result = prover.prove_segment(prep, hashing_blob, difficulty, segment)

# 4. Verify result
if result.success:
    print(f"Proof valid! Cycles: {result.total_cycles}")
else:
    print(f"Proof failed: {result.error}")
```

## Environment Variables

```bash
# Use GPU prover (faster)
export RISC0_PROVER=cuda   # NVIDIA
export RISC0_PROVER=metal  # Apple Silicon
```
