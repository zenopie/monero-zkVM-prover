#!/usr/bin/env python3
"""
Segment-based proving example for monero-zkvm-prover

This is the RECOMMENDED workflow for production use:
1. Build PrepCache once per RandomX key (~10 mins, reusable for ~2048 blocks)
2. Prove random segments per block (<2 mins each)

This approach enables proving within Monero's 2-minute block time.
"""

import monero_zkvm_prover as prover
import random
import time

def main():
    print("=" * 60)
    print("Segment-Based Proving Workflow")
    print("=" * 60)
    print()

    # Example RandomX key (would come from blockchain)
    # This is the hash of the block at height (current_height - 2048 + 1) & ~2047
    randomx_key = "a" * 64  # 32 bytes as hex string

    # Example hashing blob (would come from block template)
    # Minimum 43 bytes: block_header + merkle_root + tx_count
    hashing_blob = "b" * 100  # 50 bytes as hex string

    difficulty = 1

    # =========================================================
    # STEP 1: Build or load PrepCache (one-time per RandomX key)
    # =========================================================
    print("Step 1: PrepCache Setup")
    print("-" * 40)
    print(f"RandomX key: {randomx_key[:16]}...")
    print()

    # Try to load existing cache first (fast)
    prep = prover.PrepCache.load(randomx_key)

    if prep is not None:
        print(f"Loaded existing cache from disk!")
        print(f"  Merkle root: {prep.merkle_root()[:16]}...")
    else:
        print("No cached prep found. Building new cache...")
        print("This takes ~10 minutes (Argon2d + AES expansion + Merkle tree)")
        print()

        start = time.time()
        prep = prover.PrepCache.build(randomx_key)
        elapsed = time.time() - start

        print(f"Cache built in {elapsed:.1f}s")
        print(f"  Merkle root: {prep.merkle_root()[:16]}...")

        # Save for future use
        prep.save()
        print("Cache saved to disk for future use")

    print()

    # =========================================================
    # STEP 2: Prove random segment(s) for each block
    # =========================================================
    print("Step 2: Segment Proving")
    print("-" * 40)
    print(f"Total segments: {prover.BLOCK_SEGMENTS}")
    print(f"Segments per program: 32 (64 iterations each)")
    print()

    # Pick a random segment (0-255)
    segment = random.randint(0, prover.BLOCK_SEGMENTS - 1)
    program = segment // 32
    chunk = segment % 32
    iter_start = chunk * 64
    iter_end = iter_start + 64

    print(f"Proving segment {segment}:")
    print(f"  Program: {program}")
    print(f"  Iterations: {iter_start}-{iter_end-1}")
    print()

    print("Starting proof generation...")
    start = time.time()

    result = prover.prove_segment(prep, hashing_blob, difficulty, segment)

    elapsed = time.time() - start
    print(f"Proof completed in {elapsed:.1f}s")
    print()

    print(f"Result: {result}")
    if result.success:
        print(f"  Total cycles: {result.total_cycles:,}")
        print(f"  Merkle root verified: {result.merkle_root[:16]}...")
        if result.pow_hash:
            print(f"  PoW hash: {result.pow_hash}")
            print(f"  Difficulty met: {result.difficulty_valid}")
    else:
        print(f"  Error: {result.error}")

    print()
    print("=" * 60)
    print("Production Usage Notes")
    print("=" * 60)
    print("""
1. PrepCache is tied to the RandomX key, which changes every 2048 blocks
   - Build/save cache when key changes
   - Load cache for subsequent blocks

2. For full verification, prove all 256 segments (or a statistical sample)
   - Each segment proves 64 iterations of one program
   - Proving 8 random segments gives ~97% confidence

3. Segment proofs are independent and can be parallelized
   - Run multiple prove_segment() calls concurrently
   - Use GPU prover (RISC0_PROVER=cuda) for faster proving

4. Combine with cache proofs for full RandomX verification:
   - Phase 1: prove_cache() - proves 256 MiB cache initialization
   - Phase 2: prove_segment() × N - proves block PoW execution
""")

if __name__ == "__main__":
    main()
