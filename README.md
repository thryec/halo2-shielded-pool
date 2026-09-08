# halo2-shielded-pool

Minimal Halo2 shielded pool prototype with Poseidon commitments, Merkle membership proofs, and nullifiers.

**v0.5.0, steps 1–2:** the root crate now uses BN254 and generates KZG proofs
that Rust and a generated Solidity verifier accept. Withdrawals bind a recipient
and protocol domain. Pool contracts, transfers, and the local chain flow remain
unfinished. This is unaudited learning code, not intended for production use.

## Protocol

A note contains a private nullifier and secret:

```text
commitment     = H2(nullifier, secret)
nullifier_hash = H1(nullifier)
```

The commitment becomes a Merkle leaf. When the note is spent, its nullifier hash becomes public so the pool can reject another spend without revealing which leaf was spent.

`H1` and `H2` mean one and two inputs to original Circom Poseidon, not the
newer Poseidon2 permutation. Both use `light-poseidon 0.4.0` parameters and
exponent 5, start with zero capacity, and return state word zero. One input
uses width 2 with 8 full and 56 partial rounds; two inputs use width 3 with
8 full and 57 partial rounds. Empty Merkle leaves are zero; each parent is
`H2(left, right)`.

## Circuit

### Statement

`WithdrawCircuit` constrains the following relation:

```text
private: nullifier, secret, siblings[8], path_bits[8]
public:  root, nullifier_hash, recipient, domain, binding

commitment     = H2(nullifier, secret)
root           = MerkleRoot(commitment, siblings, path_bits)
nullifier_hash = H1(nullifier)
binding        = H2(H2(nullifier, recipient), domain)
```

The note and Merkle path remain private. The recipient must fit in 160 bits.

Public instance layout:

```text
instance[0] = root
instance[1] = nullifier_hash
instance[2] = recipient
instance[3] = domain
instance[4] = binding
```

### Domain and encoding

The native domain helper uses the full 256-bit chain ID, pool address, asset
address (zero for native ETH), and 64-bit protocol version. Addresses are
unsigned 160-bit integers. Chain ID limbs hold exactly 128 bits each, with
no field reduction.

```text
chain  = H2(chain_id_low, chain_id_high)
target = H2(pool_address, asset_address)
body   = H2(H2(chain, target), version)
domain = H2(0x485350, body)                 // HSP protocol tag
```

The future pool contract must compute its expected domain from its actual
chain, address, asset, and version and compare it with the public domain.
The circuit binds the domain but cannot know which chain executes a call.
Someone who knows the note can create a new proof for a new recipient or
domain; changing an existing proof's public values invalidates that proof.

Calldata is exactly five canonical 32-byte big-endian field words in the order
above, followed by proof bytes, with no ABI selector. Rust and Solidity reject
wrong lengths and noncanonical scalars in public inputs and proof evaluations.
The generated verifier checks scalar reads before the SDK can reduce them
modulo the field.

### Note hash gadget

`NoteChip` assigns the nullifier once. Copy constraints reuse that cell for
the commitment, nullifier hash, and withdrawal binding. It returns constrained
commitment and nullifier-hash cells.

### Merkle gadget

`MerkleChip` accepts the commitment cell, eight private siblings, and eight private path bits. Boolean and ordering constraints select each hash input, while copy constraints link the eight tree levels.

Path bit `false` places the current node on the left; `true` places it on the right.

### Proof boundary

`TestKeys::setup` creates local KZG parameters and reusable keys from an empty
circuit. `prove` takes a private witness; `verify` uses only verifier parameters,
the verification key, public inputs, and proof bytes. Proofs use SHPLONK and
the pinned Keccak-based EVM transcript. Tests reuse one key pair for different
withdrawals.

## State model

`Pool` models contract state checks in native Rust. Deposits append commitments
and record roots. Withdrawal records require a known root and an unused nullifier
hash. This simulation does not itself verify proofs or transfer funds. Foundry
contracts test hashes and proof verification; no pool contract exists yet.

**Do not use the local setup or this unaudited code for real funds.**

## Dependency note

The root package keeps the name `halo2-shielded-pool`. Its manifest pins
`halo2-axiom = 0.5.3` under the import name `halo2_proofs`, `snark-verifier = 0.2.7`,
`snark-verifier-sdk = 0.2.7`, and `light-poseidon = 0.4.0`. `Cargo.lock` fixes
the full dependency graph. Verification requires exactly one Halo2 backend.

Rust is pinned to 1.97.1, Forge to 1.5.1, and Solidity to 0.8.19 with Paris,
optimizer off, and `via_ir` off. Compiler changes require proof-verification
tests, since successful compilation alone did not ensure a working verifier
in the [compatibility spike](spikes/bn254-kzg-evm/README.md).

The owner requested this root migration after the
[backend review](docs/backend-decision.md). Its three transitive maintenance
warnings and audit limits still apply. The earlier Pallas/PSE source remains
in Git history at `fbec5f1`; prior stage results remain in
[the build log](docs/build-log.md). Old Pallas notes, roots, keys, and proofs
are incompatible with this field and hash specification.

Generated hash constants retain Light Protocol's attribution and
[Apache license](LICENSES/light-poseidon-APACHE-2.0.txt).

## Testing

Put Cargo and Forge 1.5.1 on `PATH`. Run from the repository root:

```sh
cargo test --locked
cargo run --locked --release
forge test -vv
```

CI checks formatting, Clippy, dependency uniqueness, Rust tests, and Foundry
tests directly. Locally, run `cargo run` before `forge test` to generate matching
proofs and verifier files under `artifacts/` and `contracts/generated/`;
Git ignores those test outputs.

Tests cover native/circuit/Solidity hash parity, membership and copy constraints,
recipient range and domain binding, pool state checks, reusable proof keys,
changed public inputs, corrupt proof bytes, and malformed scalar encodings.
Real Rust proof tests live in `tests/bn254_kzg_proof.rs`; the native pool flow
remains in `tests/withdrawal_flow.rs`.

## Roadmap status

See [the build plan](docs/PLAN.md) for each verify gate.

- [x] **pre-v0.1.0:** Match native and in-circuit Poseidon hashes.
- [x] **v0.1.0:** Complete the fixed-denomination Pallas pool relation under `MockProver`.
- [x] **v0.2.0:** Generate and verify real Pallas/IPA proofs in Rust.
- [x] **v0.3.0:** Prove a minimal BN254/KZG circuit through a Solidity verifier.
- [ ] **v0.4.0:** Backend review complete; explicit acceptance of maintenance warnings remains open.
- [ ] **v0.5.0:** BN254 primitives and withdrawal proofs complete; pool contracts and local chain flow remain.
- [ ] **v0.6.0:** Add variable-value notes, ownership, range checks, and value conservation.
- [ ] **v0.7.0:** Freeze a versioned proof and calldata boundary.
- [ ] **v0.8.0:** Complete outside review, record benchmarks, and publish a reproducible release.
- [ ] **v0.9.0:** Compare one frozen pool rule with an AIR/STARK implementation.
