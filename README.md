# halo2-shielded-pool

Minimal Halo2 shielded pool prototype with Poseidon commitments, Merkle membership proofs, and nullifiers.

**v0.1** uses `MockProver` to test circuit constraints. It does not yet generate cryptographic proofs, verify proofs on-chain, represent note values, or bind withdrawals to recipients. It is unaudited and not intended for production use.

## Protocol

A note currently contains a private nullifier and secret:

```text
commitment     = Poseidon(nullifier, secret)
nullifier_hash = Poseidon(nullifier)
```

The commitment becomes a Merkle leaf. When the note is spent, its nullifier hash becomes public so the pool can reject another spend without revealing which leaf was spent.

## Circuit

### Statement

`WithdrawCircuit` constrains the following relation:

```text
private: nullifier, secret, siblings[8], path_bits[8]
public:  root, nullifier_hash

commitment     = Poseidon(nullifier, secret)
root           = MerkleRoot(commitment, siblings, path_bits)
nullifier_hash = Poseidon(nullifier)
```

The root and nullifier hash are public. The note and Merkle path remain private.

Public instance layout:

```text
instance[0] = root
instance[1] = nullifier_hash
```

### Note hash gadget

`NoteHashChip` assigns the nullifier once and feeds the same cell into both Poseidon hashes. It returns constrained commitment and nullifier-hash cells.

### Merkle gadget

`MerkleChip` accepts the commitment cell, eight private siblings, and eight private path bits. Boolean and ordering constraints select each hash input, while copy constraints link the eight tree levels.

## State model

`Pool` models the state checks expected of an on-chain contract. Deposits append commitments and record new roots. Withdrawals require a known root and an unused nullifier hash. The simulation does not verify a Halo2 proof; circuit verification and pool state are not yet connected.

## Dependency note

This project pins the PSE Halo2 fork at `v0.3.0` to match `halo2_poseidon v0.2.0`. Both dependencies resolve to one `halo2_proofs` version, avoiding incompatible circuit types.

## Testing

`MockProver` and native tests cover:

- agreement between native and circuit note hashes and Merkle paths;
- an honest note and membership path;
- wrong roots, nullifier hashes, leaves, siblings, and secrets;
- flipped and non-Boolean path bits; and
- unknown roots, reused nullifier hashes, and full trees.

```sh
cargo test
cargo test withdraw
```

## Future work

- [ ] Implement Halo2 proof generation and verification beyond `MockProver`.
- [ ] Extend notes with variable values, enforce range constraints, and prove value conservation across inputs, outputs, and withdrawals.
- [ ] Bind each withdrawal proof to its intended recipient.
- [ ] Implement a Solidity verifier and pool contract with incremental Merkle tree updates.
