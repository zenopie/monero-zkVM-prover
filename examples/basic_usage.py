#!/usr/bin/env python3
"""
Basic usage example for monero-zkvm-prover

This example shows how to use the prover's main functions.
"""

import monero_zkvm_prover as prover

def main():
    # Print version and constants
    print(f"Prover version: {prover.version()}")
    print(f"Cache size: {prover.CACHE_SIZE / 1024 / 1024} MiB")
    print(f"Cache segments: {prover.CACHE_SEGMENTS}")
    print(f"Scratchpad size: {prover.SCRATCHPAD_SIZE / 1024 / 1024} MiB")
    print(f"Program count: {prover.PROGRAM_COUNT}")
    print(f"Iterations per program: {prover.ITERATIONS}")
    print(f"Block segments: {prover.BLOCK_SEGMENTS}")
    print()

    # Example data (these would come from the Monero blockchain)
    # RandomX key: hash of block at height (current_height - 2048 + 1) & ~2047
    randomx_key = "0" * 64  # 32 bytes as hex

    # Hashing blob: constructed from block template
    # Format: block_header + merkle_root + tx_count (varint)
    hashing_blob = "0" * 86  # Minimum 43 bytes as hex

    # Difficulty: target difficulty for PoW
    difficulty = 1

    print("=" * 60)
    print("Example: Prove cache hash (Phase 1)")
    print("=" * 60)
    print("This proves the 256 MiB RandomX cache was correctly")
    print("computed from the RandomX key using Argon2d + AES.")
    print()
    print("NOTE: This takes ~10-20 minutes on first run.")
    print("      The cache proof can be reused for ~2048 blocks.")
    print()

    # Uncomment to run:
    # result = prover.prove_cache(randomx_key)
    # print(f"Result: {result}")
    # if result.success:
    #     print(f"  Merkle root: {result.merkle_root}")
    #     print(f"  Cache hash: {result.cache_hash}")
    #     print(f"  Cycles: {result.total_cycles}")
    #     print(f"  Time: {result.proving_time_secs}s")

    print("=" * 60)
    print("Example: Prove block PoW (Phase 2)")
    print("=" * 60)
    print("This proves a block's RandomX hash meets the difficulty.")
    print("Executes 8 programs × 2048 iterations = 16,384 VM steps.")
    print()

    # Uncomment to run:
    # result = prover.prove_block(randomx_key, hashing_blob, difficulty)
    # print(f"Result: {result}")
    # if result.success:
    #     print(f"  PoW hash: {result.pow_hash}")
    #     print(f"  Difficulty valid: {result.difficulty_valid}")
    #     print(f"  Cycles: {result.total_cycles}")
    #     print(f"  Time: {result.proving_time_secs}s")

    print("=" * 60)
    print("Example: Full proof (Phase 1 + Phase 2)")
    print("=" * 60)
    print("This proves both cache initialization AND block PoW.")
    print()

    # Uncomment to run:
    # result = prover.prove_full(randomx_key, hashing_blob, difficulty)
    # print(f"Result: {result}")

    print("See segment_proving.py for the fast segment-based workflow.")

if __name__ == "__main__":
    main()
