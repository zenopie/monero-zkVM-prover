#!/usr/bin/env python3
"""
Integration example showing how a Monero client might use the prover.

This simulates the workflow of:
1. Receiving new blocks from the network
2. Verifying PoW using zkVM proofs
3. Caching prep data across blocks
"""

import monero_zkvm_prover as prover
import hashlib
import time

class MoneroZkVerifier:
    """
    Example verifier that uses zkVM proofs for Monero PoW verification.
    """

    def __init__(self):
        self.prep_cache = {}  # randomx_key -> PrepCache
        self.current_key = None

    def get_randomx_key_block(self, height: int) -> int:
        """
        Calculate which block's hash is used as the RandomX key.
        RandomX key changes every 2048 blocks.
        """
        return (height - 1) & ~2047

    def ensure_prep_cache(self, randomx_key: str) -> 'prover.PrepCache':
        """
        Get or build the PrepCache for a RandomX key.
        """
        if randomx_key in self.prep_cache:
            return self.prep_cache[randomx_key]

        print(f"Loading/building PrepCache for key {randomx_key[:16]}...")

        # Try to load from disk first
        prep = prover.PrepCache.load(randomx_key)
        if prep is None:
            print("  Building new cache (this takes ~10 minutes)...")
            start = time.time()
            prep = prover.PrepCache.build(randomx_key)
            prep.save()
            print(f"  Cache built and saved in {time.time() - start:.1f}s")
        else:
            print("  Loaded from disk")

        self.prep_cache[randomx_key] = prep

        # Clean old caches (keep last 2 keys)
        if len(self.prep_cache) > 2:
            oldest_key = list(self.prep_cache.keys())[0]
            del self.prep_cache[oldest_key]
            print(f"  Cleaned old cache for key {oldest_key[:16]}...")

        return prep

    def verify_block_pow(
        self,
        randomx_key: str,
        hashing_blob: str,
        difficulty: int,
        num_segments: int = 8
    ) -> dict:
        """
        Verify a block's PoW by proving random segments.

        Args:
            randomx_key: 32-byte RandomX key as hex
            hashing_blob: Block hashing blob as hex
            difficulty: Target difficulty
            num_segments: Number of random segments to prove (more = higher confidence)

        Returns:
            dict with verification results
        """
        import random

        # Get or build prep cache
        prep = self.ensure_prep_cache(randomx_key)

        # Select random segments to prove
        segments = random.sample(range(prover.BLOCK_SEGMENTS), num_segments)
        segments.sort()

        results = []
        total_cycles = 0
        all_passed = True

        print(f"Verifying {num_segments} random segments: {segments}")

        for i, segment in enumerate(segments):
            program = segment // 32
            chunk = segment % 32

            print(f"  [{i+1}/{num_segments}] Segment {segment} (program {program}, chunk {chunk})...", end=" ", flush=True)

            start = time.time()
            result = prover.prove_segment(prep, hashing_blob, difficulty, segment)
            elapsed = time.time() - start

            if result.success:
                print(f"OK ({elapsed:.1f}s, {result.total_cycles:,} cycles)")
                total_cycles += result.total_cycles
                results.append({
                    "segment": segment,
                    "success": True,
                    "cycles": result.total_cycles,
                    "time": elapsed
                })
            else:
                print(f"FAILED: {result.error}")
                all_passed = False
                results.append({
                    "segment": segment,
                    "success": False,
                    "error": result.error
                })

        return {
            "valid": all_passed,
            "segments_proved": len(results),
            "segments_passed": sum(1 for r in results if r["success"]),
            "total_cycles": total_cycles,
            "confidence": len([r for r in results if r["success"]]) / prover.BLOCK_SEGMENTS,
            "results": results
        }


def simulate_block_stream():
    """
    Simulate receiving blocks from the network.
    """
    # Simulated block data
    blocks = [
        {
            "height": 3000000,
            "randomx_key": "a" * 64,
            "hashing_blob": "b" * 100,
            "difficulty": 1
        },
        {
            "height": 3000001,
            "randomx_key": "a" * 64,  # Same key (within 2048 block window)
            "hashing_blob": "c" * 100,
            "difficulty": 1
        },
        {
            "height": 3002048,
            "randomx_key": "d" * 64,  # New key (new 2048 block window)
            "hashing_blob": "e" * 100,
            "difficulty": 1
        },
    ]
    return blocks


def main():
    print("=" * 60)
    print("Monero zkVM Verifier - Integration Example")
    print("=" * 60)
    print()

    verifier = MoneroZkVerifier()

    # Simulate receiving blocks
    blocks = simulate_block_stream()

    for block in blocks:
        print(f"\n{'='*60}")
        print(f"Block {block['height']}")
        print(f"{'='*60}")
        print(f"RandomX key: {block['randomx_key'][:16]}...")
        print(f"Hashing blob: {block['hashing_blob'][:16]}...")
        print(f"Difficulty: {block['difficulty']}")
        print()

        # Verify with 4 random segments (~1.6% coverage, quick demo)
        result = verifier.verify_block_pow(
            randomx_key=block["randomx_key"],
            hashing_blob=block["hashing_blob"],
            difficulty=block["difficulty"],
            num_segments=4  # Use 8-16 for production
        )

        print()
        print(f"Verification result:")
        print(f"  Valid: {result['valid']}")
        print(f"  Segments: {result['segments_passed']}/{result['segments_proved']} passed")
        print(f"  Total cycles: {result['total_cycles']:,}")
        print(f"  Coverage: {result['confidence']*100:.1f}%")


if __name__ == "__main__":
    main()
