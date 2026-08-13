# halo2-shielded-pool

Halo2 shielded asset pool using Poseidon and Merkle proofs.

## Protocol

```text
commitment     = Poseidon(nullifier, secret, value)
nullifier_hash = Poseidon(nullifier)
```

Commitments are Merkle leaves. Nullifier hashes prevent replay without revealing the spent commitment.

## Proof

```text
commitment_i = Poseidon(nullifier_i, secret_i, value_i)
commitment_i is included in root
nullifier_hash_i = Poseidon(nullifier_i)

input_value_1 + input_value_2
    = output_value_1 + output_value_2 + withdrawn
```

The circuit range-checks values to 64 bits, computes output commitments, and binds the recipient.

Public inputs:

```text
root
nullifier_hash_1
nullifier_hash_2
output_commitment_1
output_commitment_2
withdrawn
recipient
```

The contract checks the root and nullifiers, verifies the proof, updates pool state, and pays the recipient.

## Invariants

- Every advice cell is constrained.
- One nullifier cell feeds both hashes.
- Merkle path bits are Boolean; digests are copy-constrained between levels.
- Values are range-checked before balance arithmetic.
- The recipient is bound to the proof.
- Roots must be known and nullifiers unused.

## Commands

```sh
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```
