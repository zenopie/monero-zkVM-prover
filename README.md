# Monero RandomX zkVM Verification

**Version: v27** | Zero-knowledge proof system for Monero block verification

## Overview

This project enables trustless verification of Monero proof-of-work by generating ZK proofs of RandomX hash computation using RISC Zero zkVM. Designed for an optimistic bridge architecture:

- **Normal tier**: Bonded deposits with challenge period (no proof upfront)
- **Pro tier**: Full ZK proof for instant finality

## Architecture

### Two-Phase Proof System

```
Phase 1: Cache Initialization          Phase 2: Block PoW
(reusable ~2048 blocks)                (per block)
┌─────────────────────────┐            ┌─────────────────────────┐
│  64 segments × 4 MiB    │            │  8 programs × 32 chunks │
│  = 256 MiB total cache  │───────────▶│  = 256 block segments   │
│                         │   Merkle   │  with Merkle proofs     │
│  Argon2d + AES expand   │    Root    │  RandomX VM execution   │
└─────────────────────────┘            └─────────────────────────┘
```

**Phase 1**: Proves correct cache generation from RandomX key
- 64 segments × 4 MiB = 256 MiB cache
- Argon2d seed → AES expansion
- Reusable for ~2048 blocks (~3 days)

**Phase 2**: Proves RandomX VM execution with Merkle proofs
- 8 programs × 32 chunks = 256 block segments
- Each chunk = 64 iterations with ~64 dataset accesses
- Merkle proofs verify items against Phase 1 root

## Quick Start

### Prerequisites

```bash
# Install Risc0 toolchain
curl -L https://risczero.com/install | bash
rzup install
```

### Build & Run

```bash
# Full proof with test data
cargo run -r -p host

# Specific modes
cargo run -r -p host -- cache              # Full cache (64 segments)
cargo run -r -p host -- block              # Full block (8 programs)
cargo run -r -p host -- cache-segment 5    # Single cache segment
cargo run -r -p host -- block-segment 42   # Single block segment

# With GPU acceleration (recommended)
RISC0_PROVER=cuda cargo run -r -p host -- block
```

### Docker (GPU Runtime)

```bash
# Build image
docker build -f Dockerfile.gpu-runtime -t randomx-zkvm-gpu .

# Run with GPU (drops to shell with prover CLI)
docker run -it --gpus all randomx-zkvm-gpu

# Inside container:
prover --help
prover block-segment 42
prover cache
```

## CLI Usage

```
Usage: prover <mode> [options]

Modes:
  cache               Prove full cache hash (64 segments)
  cache-segment <N>   Prove single cache segment (0-63)
  block               Prove full block PoW (8 programs)
  block-segment <N>   Prove single block segment (0-255)
  full                Prove cache + block (default)

Options:
  --randomx-key <HEX>   32-byte RandomX key (uses test key if omitted)
  --hashing-blob <HEX>  Block hashing blob (uses test blob if omitted)
  --difficulty <N>      Target difficulty (default: 1)
  --resume              Skip segments with existing valid proofs
  --help, -h            Show this help

Examples:
  prover full                           # Full proof with test data
  prover cache-segment 5                # Prove cache segment 5
  prover block-segment 42               # Prove block segment 42
  prover block --randomx-key abc123...  # Full block with real key
```

### Segment IDs

**Cache segments (Phase 1)**: 0-63 (4 MiB each)

**Block segments (Phase 2)**: 0-255
- Segments 0-31 = Program 0, chunks 0-31
- Segments 32-63 = Program 1, chunks 0-31
- ...
- Segments 224-255 = Program 7, chunks 0-31

### Monero Specification

| Parameter | Value |
|-----------|-------|
| Cache Size | 256 MiB (64 × 4 MiB segments) |
| Scratchpad | 2 MiB |
| Programs | 8 × 2048 iterations |
| Chunks per Program | 32 × 64 iterations |
| Dataset Items | ~4.2M (64 bytes each) |

## Project Structure

```
├── host/                        # Host-side prover
│   └── src/
│       ├── main.rs             # CLI, Merkle tree, proving
│       └── randomx_vm.rs       # VM simulation for pre-execution
├── methods/
│   ├── guest/                  # Shared RandomX library
│   │   └── src/
│   │       ├── lib.rs          # Config & re-exports
│   │       └── randomx/
│   │           ├── aes.rs      # Software AES
│   │           ├── argon2.rs   # Cache initialization
│   │           ├── blake2b.rs  # Hashing
│   │           ├── merkle.rs   # Merkle tree proofs
│   │           ├── program.rs  # RandomX programs
│   │           ├── vm.rs       # VM execution
│   │           └── ...
│   ├── phase1a-cache-segment/  # Cache segment guest
│   └── phase2-program/         # Program segment guest
├── Dockerfile.gpu-runtime
└── deploy-akash-runtime.yaml
```

## RandomX Implementation

### Components

| Component | Status |
|-----------|--------|
| Argon2d cache (256 MiB) | Complete |
| AES scratchpad fill | Complete |
| All 30 instructions | Complete |
| Program generation | Complete |
| Superscalar programs | Complete |
| Light mode dataset | Complete |
| Difficulty verification | Complete |
| Merkle proofs | Complete |
| Chunked proving (256 segments) | Complete |

### All 30 RandomX Instructions

**Integer**: `IADD_RS`, `IADD_M`, `ISUB_R`, `ISUB_M`, `IMUL_R`, `IMUL_M`, `IMULH_R`, `IMULH_M`, `ISMULH_R`, `ISMULH_M`, `IMUL_RCP`, `INEG_R`, `IXOR_R`, `IXOR_M`, `IROR_R`, `IROL_R`, `ISWAP_R`

**Floating Point**: `FSWAP_R`, `FADD_R`, `FADD_M`, `FSUB_R`, `FSUB_M`, `FSCAL_R`, `FMUL_R`, `FDIV_M`, `FSQRT_R`

**Control**: `CBRANCH`, `CFROUND`, `ISTORE`, `NOP`

## Performance

### GPU Acceleration (Required for Practical Use)

| GPU | Relative Speed |
|-----|----------------|
| CPU | 1× baseline |
| Metal (M1/M2) | 10-30× |
| CUDA (RTX 4090) | 80-100× |
| CUDA (H100) | 150-200× |

### Estimated Times (H100)

| Phase | Segments | Est. Time |
|-------|----------|-----------|
| Phase 1 (cache) | 64 | 4-8 hours |
| Phase 2 (block) | 8 programs | 1-2 hours |
| Single segment | 1 | 10-20 min |

Phase 1 cache proof reusable for ~2048 blocks (~3 days).

## Security Model

1. **Cache Commitment**: Phase 1 proves correct cache from RandomX key
2. **Merkle Binding**: Program segments verify items against committed root
3. **Chained Execution**: Program outputs chain to next program inputs
4. **Final Hash**: Last program outputs verified PoW hash

## Deployment

### Akash (Decentralized GPU Cloud)

```bash
# Deploy with SDL
akash tx deployment create deploy-akash-runtime.yaml
```

### Other GPU Clouds

```bash
# Build and push
docker build -f Dockerfile.gpu-runtime -t ghcr.io/USER/randomx-zkvm:gpu-runtime-v27 .
docker push ghcr.io/USER/randomx-zkvm:gpu-runtime-v27

# Run on Vast.ai, RunPod, Lambda, etc.
docker run -it --gpus all ghcr.io/USER/randomx-zkvm:gpu-runtime-v27
```

## References

- [RandomX Specification](https://github.com/tevador/RandomX/blob/master/doc/specs.md)
- [RISC Zero Documentation](https://dev.risczero.com/)
- [Monero Research Lab](https://www.getmonero.org/resources/research-lab/)

## License

MIT
