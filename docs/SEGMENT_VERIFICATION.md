# Random Segment Sampling: On-Chain Verification Model

## Overview

Full RandomX proof generation takes too long for per-block verification. Instead, we use **random segment sampling** with a commit-then-challenge model:

1. **Prover commits** to their full computation state
2. **Contract challenges** a random segment (after commitment)
3. **Prover proves** just that segment was computed correctly
4. **Contract verifies** the segment proof matches the commitment

## Segment Structure

RandomX execution consists of:
- **8 programs** (program_index: 0-7)
- **2048 iterations** per program
- **32 chunks** per program (64 iterations each)

Total: **256 segments** (8 programs × 32 chunks)

```
Segment ID = program_index * 32 + chunk_index
```

| Segment ID | Program | Chunk | Iterations    |
|------------|---------|-------|---------------|
| 0          | 0       | 0     | 0-63          |
| 1          | 0       | 1     | 64-127        |
| ...        | ...     | ...   | ...           |
| 31         | 0       | 31    | 1984-2047     |
| 32         | 1       | 0     | 0-63          |
| ...        | ...     | ...   | ...           |
| 255        | 7       | 31    | 1984-2047     |

## Commitment Structure

Before any segment is challenged, the prover must commit to the **full execution state**. This commitment should include:

### State Tree (Merkle Tree of 256 entries)

For each segment `i` (0-255), store:

```rust
struct SegmentCommitment {
    segment_id: u16,
    input_seed: [u8; 64],       // Seed entering this segment
    scratchpad_hash: [u8; 32],  // SHA256(2 MiB scratchpad)
    program_hash: [u8; 32],     // SHA256(program instructions)
    initial_state_hash: [u8; 32], // SHA256(registers + ma + mx) for mid-program
}
```

The prover computes all 256 segment commitments and publishes the **Merkle root** on-chain.

## Challenge-Response Protocol

### Step 1: Prover Submits Commitment

```
On-Chain State:
- commitment_root: bytes32 (Merkle root of 256 segment commitments)
- dataset_merkle_root: bytes32 (from cache proof)
- block_hash: bytes32 (the block being proven)
- timestamp: uint256 (when commitment was made)
```

### Step 2: Contract Generates Challenge

After commitment (e.g., next block), the contract generates a random segment ID:

```solidity
// Example: use future block hash as randomness source
uint8 challengedSegment = uint8(
    uint256(blockhash(block.number)) % 256
);
```

This ensures the prover cannot know which segment will be challenged when committing.

### Step 3: Prover Submits Segment Proof

The prover generates a zkVM proof for the challenged segment and submits:

```rust
struct SegmentProof {
    // The RISC0 proof itself
    receipt: Receipt,

    // Merkle proof that this segment's commitment is in the tree
    commitment_proof: Vec<[u8; 32]>,
}
```

### Step 4: Contract Verifies

The contract verifies:

1. **Proof is valid**: RISC0 receipt verifies correctly

2. **Segment ID matches**: `output.segment_id == challengedSegment`

3. **Input seed is in commitment**:
   ```
   verify_merkle_proof(
       commitment_root,
       segment_id,
       hash(output.input_seed, output.scratchpad_hash, output.program_hash, ...),
       commitment_proof
   )
   ```

4. **Dataset matches**: `output.dataset_merkle_root == committed_dataset_root`

5. **Derived values are correct**: Contract can independently verify:
   - `scratchpad_hash` is correct derivation from `input_seed` (via AES)
   - `program_hash` is correct derivation from `input_seed` (via AES)
   - For segment 0: `input_seed` derives from `block_hash`

## zkVM Output Structure

The guest program outputs:

```rust
pub struct ProgramSegmentOutput {
    /// Segment ID (0-255): program_index * 32 + chunk_index
    pub segment_id: u16,

    /// The seed this segment started with
    pub input_seed: [u8; 64],

    /// The seed after execution (for chaining)
    pub output_seed: [u8; 64],

    /// SHA256 hash of 2 MiB input scratchpad
    pub scratchpad_hash: [u8; 32],

    /// SHA256 hash of program instructions
    pub program_hash: [u8; 32],

    /// Hash of initial registers (for mid-program chunks)
    pub initial_state_hash: [u8; 32],

    /// Dataset Merkle root that was verified against
    pub dataset_merkle_root: [u8; 32],

    /// Final PoW hash (only for segment 255)
    pub pow_hash: Option<[u8; 32]>,

    /// Difficulty check result (only for segment 255)
    pub difficulty_valid: Option<bool>,
}
```

## Security Analysis

### What the prover commits to

By committing `input_seed`, `scratchpad_hash`, and `program_hash` for each segment:

- **Seed chain is fixed**: Each segment's input_seed must match previous segment's output_seed
- **Scratchpad is fixed**: The hash commits to the exact 2 MiB state
- **Program is fixed**: Cannot use different program instructions

### What the proof guarantees

For the challenged segment, the zkVM proof ensures:

1. **Correct execution**: VM followed RandomX specification
2. **Correct dataset reads**: Each dataset item has valid Merkle proof
3. **Correct state transitions**: Registers, scratchpad modified correctly
4. **Output seed computed correctly**: From execution result

### Why cheating is infeasible

If prover cheats on **any** segment:
- Wrong input_seed → won't match commitment
- Wrong scratchpad → hash won't match commitment
- Wrong program → hash won't match commitment
- Wrong execution → output_seed won't match next segment's input_seed

With 256 segments and random challenge:
- Cheating on 1 segment: 1/256 (0.39%) chance of being caught per challenge
- Cheating on k segments: k/256 chance of being caught per challenge

After N challenges without detection, probability of honest execution:
- 1 - (255/256)^N for single-segment cheating
- For practical security: ~600 challenges = 99% detection rate for any cheating

## Implementation Notes

### On-Chain Contract Requirements

```solidity
interface IRandomXVerifier {
    // Prover commits to full execution
    function commit(
        bytes32 commitmentRoot,    // Merkle root of 256 segment commitments
        bytes32 datasetRoot,       // From cache proof
        bytes32 blockHash,         // Block being proven
        uint64 difficulty          // Target difficulty
    ) external;

    // Contract generates challenge (can be called by anyone after delay)
    function challenge(uint256 commitmentId) external returns (uint8 segmentId);

    // Prover responds with segment proof
    function respond(
        uint256 commitmentId,
        bytes calldata receipt,           // RISC0 proof
        bytes32[] calldata merkleProof    // Proof of commitment inclusion
    ) external returns (bool valid);
}
```

### Optimizations

1. **Multiple challenges per commitment**: Require M challenges for higher security
2. **Batch verification**: Accumulate proofs, verify periodically
3. **Economic incentives**: Stake slashing for invalid proofs
4. **Progressive security**: Increase required proofs for larger values

### Gas Considerations

- RISC0 proof verification: ~300k-500k gas (with Groth16)
- Merkle proof verification: ~10k gas per proof
- State storage: ~20k gas per commitment

## Appendix: Seed Derivation

For reference, how seeds chain between programs:

```
block_hash (input)
    ↓ blake2b
initial_seed (64 bytes)
    ↓ program 0 execution
output_seed_0 = aes_hash(registers)
    ↓ becomes input for program 1
output_seed_1 = aes_hash(registers)
    ↓ ...
output_seed_7 = aes_hash(registers)
    ↓ blake2b
final_pow_hash (32 bytes)
```

Within a program, chunks share the same seed until the program completes.
