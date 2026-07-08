# halo2-shielded-pool

A Tornado-style shielded pool in halo2 (PSE fork). Deposit a note, withdraw it later from a different address; a zero-knowledge proof shows the note is in the pool without revealing which one.

## Architecture

Three layers:

- `src/primitives.rs` — plain-Rust domain logic: notes, Poseidon commitments, nullifier hashes, incremental Merkle tree. No circuit code. Everything the circuits prove is computed and tested here first.
- Circuits — Merkle inclusion chip, commitment and nullifier sub-circuits, composed into a withdraw circuit. Public inputs: root and nullifier hash.
- Contracts (final stage) — generated Solidity verifier plus a minimal pool contract: on-chain commitment tree, nullifier set, recent-root history.

## Build stages

- v0 — Poseidon spike: dependency resolution, chip API, in-circuit digest agrees with off-circuit reference
- v1 — fixed-denomination pool, MockProver only
- v2 — variable amounts: join-split, value balance, 64-bit range checks via lookups
- v3 — real KZG proofs, Solidity verifier, end-to-end on anvil

## Security model

- Every advice cell is pinned by a constraint; no assigned-but-unconstrained witnesses.
- Merkle path bits are boolean-constrained; digests are copy-constrained between levels.
- Values are range-checked before balance arithmetic, since unchecked field arithmetic allows minting via overflow.
- The recipient is bound into the proven statement, so a relayer cannot redirect a withdrawal.

## Build & test

```
cargo test
```

MockProver-based tests throughout v1–v2; real proof generation and foundry tests arrive in v3.

## Status

Pre-v0. Scaffold only.
