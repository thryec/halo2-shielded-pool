# halo2-shielded-pool

Halo2 shielded asset pool using Poseidon and Merkle proofs.

## Protocol

A note contains a private nullifier and secret:

```text
commitment     = Poseidon(nullifier, secret)
nullifier_hash = Poseidon(nullifier)
```

The commitment becomes a Merkle leaf. The nullifier hash identifies a spend without revealing which commitment it spends.

## Circuit components

### Note hash gadget

`NoteHashChip` assigns the nullifier once and feeds the same cell into both Poseidon hashes. It returns constrained commitment and nullifier-hash cells.

### Merkle gadget

`MerkleChip` accepts the commitment cell, eight private siblings, and eight private path bits. Boolean and ordering constraints select each hash input, while copy constraints link the eight tree levels.

### Withdraw circuit

`WithdrawCircuit` feeds the commitment into the Merkle gadget, then binds the computed root and nullifier hash to public inputs.

```text
private: nullifier, secret, siblings[8], path_bits[8]
public:  root, nullifier_hash

private note -> commitment -> Merkle path -> public root
nullifier   -> nullifier hash             -> public input
```

Public instance layout:

```text
instance[0] = root
instance[1] = nullifier_hash
```

## State checks

The circuit proves note membership and derives the nullifier hash. The native pool simulation checks that the root is known and the nullifier hash is unused. Deposits store commitments without storing private note data.

## Dependency note

This project pins the PSE Halo2 fork at `v0.3.0` to match `halo2_poseidon v0.2.0`. Both dependencies resolve to one `halo2_proofs` version, avoiding incompatible circuit types.

The PSE fork is now archived. The Pallas v1 circuit and v2 Rust proof stage remain pinned as a reproducible learning artifact. Before any BN254 pool port, the plan requires an isolated EVM spike and an explicit move to a maintained backend.

## Testing

`MockProver` accepts an honest note and path. Negative tests cover a wrong root, wrong nullifier hash, absent note, changed secret, and altered Merkle path.

```sh
cargo test
cargo test withdraw
```

## Future work

- [ ] Generate and verify real Pallas/IPA proofs in Rust.
- [ ] Prove a minimal BN254/KZG circuit through a Solidity verifier.
- [ ] Select and pin a maintained Halo2, Poseidon, transcript, and verifier stack.
- [ ] Port the fixed-denomination pool to BN254 and bind recipient plus protocol domain.
- [ ] Run deposit → prove → withdraw against a local EVM contract.
- [ ] Add variable-value notes, ownership, range checks, and value conservation.
- [ ] Freeze a versioned proof/calldata boundary, complete outside review, and publish benchmarks.
- [ ] Compare one frozen pool rule with an AIR/STARK implementation.
