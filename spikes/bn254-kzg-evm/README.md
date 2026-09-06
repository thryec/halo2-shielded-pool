# BN254/KZG/EVM compatibility spike

This isolated v0.3.0 experiment proves one two-input Poseidon hash. Rust and
Solidity check the same SHPLONK proof and public digest. It has its own Cargo
workspace and lockfile; the Pallas pool keeps its original dependencies.

From the repository root:

```sh
bash spikes/bn254-kzg-evm/verify.sh
```

Requires the root Rust toolchain, Forge 1.5.1 (`forge` on `PATH`), and `jq`. Foundry
downloads the pinned Solidity compiler if needed. All EVM tests run locally;
no RPC endpoint, wallet, or funded account is needed.

With Foundry's installer already installed, select the pinned version:

```sh
foundryup --install v1.5.1
bash spikes/bn254-kzg-evm/verify.sh --check-tools-only
```

The pin lives in `.foundry-version`. The script rejects a missing or different
Forge before compiling. Run `bash spikes/bn254-kzg-evm/test-verify-tools.sh` to
check that guard.

The candidate updates `rand` from 0.8.5 to patched 0.8.6; the original v0.3
measurements below describe the earlier lockfile.

The script checks the dependency graph, runs Rust tests, generates a matching
verifier and proof fixture, then runs Foundry tests. Generated files live in
`contracts/generated/` and `artifacts/`; both are ignored by Git and recreated
on each run. Always regenerate the verifier and proof together.

| File | Role |
| --- | --- |
| `src/native.rs` | Independent native hash, parameter conversion, Solidity hash generator |
| `src/circuit.rs` | Poseidon round constraints, zero capacity, public digest binding |
| `src/proof.rs` | BN254 KZG/SHPLONK proving and Rust verification |
| `src/main.rs` | Generates Solidity verifier and identical valid/invalid calldata fixtures |
| `test/Spike.t.sol` | Solidity parity, proof rejection, bytecode size, and gas checks |

**Hash specification**

BN254 scalar field, width 3, rate 2, exponent 5, 8 full and 57 partial rounds.
Start at `[0, left, right]`; add round constants, apply the S-box, multiply the
MDS matrix, and return final state word zero. Partial rounds change only word
zero through the S-box. Parameters and native hashing come from
`light-poseidon = 0.4.0` (Apache-2.0).

The fixed circom-compatible integer-input vector is:

```text
inputs = [1, 2]
digest = 7853200120776062878684798364095072458815029376092732009249414926327459813530
```

This is the original Poseidon with two inputs, not the newer Poseidon2
permutation. The generated contract's name `Poseidon2` denotes its input count.
This BN254 specification differs from the pool's Pallas `P128Pow5T3` hash.

**Proof format**

The stack uses `snark-verifier`'s `EvmTranscript` with Keccak-256 on both sides.
Scalars use canonical 32-byte big-endian encoding; curve points use two 32-byte
big-endian coordinates. Public inputs are one column containing the digest.
Calldata is the 32-byte digest followed by proof bytes, without an ABI selector
or dynamic-array lengths. The generated fallback returns empty bytes on success
and reverts on failure. The Rust verifier finalizes its accumulation strategy,
including the final pairing check.

See the pinned [transcript source](https://docs.rs/snark-verifier/0.2.7/src/snark_verifier/system/halo2/transcript/evm.rs.html)
and [SDK EVM helpers](https://docs.rs/snark-verifier-sdk/0.2.7/snark_verifier_sdk/evm/index.html).

**Compatibility choices**

- `halo2_proofs` aliases `halo2-axiom = 0.5.3`; only one Halo2 implementation
  resolves in this workspace
- `snark-verifier` and its SDK are pinned to `0.2.7`; `Cargo.lock` pins their
  shared `halo2-base = 0.5.5` dependency
- Axiom uses different assignment APIs from PSE and enables `Circuit::Params`
  through the SDK dependency graph
- The selected x^5 gate needs degree 6; set it explicitly because Axiom caps
  inferred degree at 5 by default
- The generated verifier pins Solidity 0.8.19; Foundry uses Paris EVM rules
  with optimization and `via_ir` disabled, matching the SDK's compiler helper
- Optimized legacy compilation failed with stack depth; optimized `via_ir`
  produced a 67-byte contract that reverted even on the valid proof. The
  generated assembly assumes the Solidity free-memory pointer starts at `0x80`.
  Compiler changes require rerunning the honest-proof test, not only negatives

These are experimental compatibility pins. The v0.4.0 maintenance and security
decision remains open.

**Test-only setup**

`ParamsKZG::setup` creates local test parameters with fresh randomness. This
does not implement a trusted setup ceremony. Do not use these parameters or
the generated verifier to secure funds. A production KZG deployment needs
parameters from an appropriate setup process.

The circuit proves knowledge of two inputs for one digest. It does not prove
pool membership, bind a recipient, or prevent repeated withdrawals.

Foundry prints verifier creation/runtime byte sizes and gas for a cold
`STATICCALL`, including call and return-data overhead. This gas figure excludes
transaction intrinsic/calldata gas, deployment, and any pool logic.
Every verifier test uses a 1,000,000-gas call budget. Malformed curve points can
consume the forwarded precompile gas; rejection does not imply cheap rejection.

**Verified 2026-09-05**

The full script passed: 9 Rust tests and 6 Foundry tests, plus formatting,
Clippy, and the single-Halo2 dependency check. The root pool tests also passed:
49 tests, with one manual benchmark ignored.

| Measurement | Result |
| --- | ---: |
| Circuit size | `k = 7` (128 rows) |
| Proof | 1,312 bytes |
| Calldata, including public digest | 1,344 bytes |
| Verifier runtime bytecode | 9,829 bytes |
| Verifier creation bytecode | 9,861 bytes |
| Cold valid verification call | 269,720 gas |

Measured with Forge 1.5.1 and the compiler settings above. Fresh setup
randomness can slightly change verifier bytecode size. See
[`docs/build-log.md`](../../docs/build-log.md) for dependency pins and run details.
