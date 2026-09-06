//! Circom-compatible BN254 Poseidon: width 3, zero domain tag, x^5, 8/57 rounds.
//!
//! Parameters come from light-poseidon 0.4.0 (Apache-2.0), generated from the
//! original Poseidon parameter script. Native hashing remains independent of
//! the Halo2 circuit and generated Solidity implementation.

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5};
use std::fmt::Write;

pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 57;

fn to_halo2(value: ArkFr) -> Fr {
    let bytes = value.into_bigint().to_bytes_le();
    let mut repr = <Fr as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    Option::<Fr>::from(Fr::from_repr(repr)).expect("BN254 scalar fields share a modulus")
}

fn to_ark(value: Fr) -> ArkFr {
    ArkFr::from_le_bytes_mod_order(value.to_repr().as_ref())
}

/// Returns round-major constants and the MDS matrix in output-row/input-column order.
pub fn parameters() -> (Vec<[Fr; 3]>, [[Fr; 3]; 3]) {
    let params = bn254_x5::get_poseidon_parameters::<ArkFr>(3).unwrap();
    assert_eq!(params.full_rounds, FULL_ROUNDS);
    assert_eq!(params.partial_rounds, PARTIAL_ROUNDS);
    assert_eq!(params.width, 3);
    assert_eq!(params.alpha, 5);
    assert_eq!(params.ark.len(), 3 * (FULL_ROUNDS + PARTIAL_ROUNDS));
    let rounds = params
        .ark
        .chunks_exact(3)
        .map(|row| std::array::from_fn(|i| to_halo2(row[i])))
        .collect();
    let mds = std::array::from_fn(|i| std::array::from_fn(|j| to_halo2(params.mds[i][j])));
    (rounds, mds)
}

/// Computes the reference digest through light-poseidon, not the circuit's witness code.
pub fn hash(inputs: [Fr; 2]) -> Fr {
    let mut poseidon = Poseidon::<ArkFr>::new_circom(2).unwrap();
    to_halo2(poseidon.hash(&inputs.map(to_ark)).unwrap())
}

/// Generates a loop-based contract with packed constants to keep deployed code small.
pub fn solidity_source() -> String {
    let params = bn254_x5::get_poseidon_parameters::<ArkFr>(3).unwrap();
    let mut ark_hex = String::new();
    let mut mds_hex = String::new();
    for value in &params.ark {
        write!(
            ark_hex,
            "{}",
            hex::encode(value.into_bigint().to_bytes_be())
        )
        .unwrap();
    }
    for row in &params.mds {
        for value in row {
            write!(
                mds_hex,
                "{}",
                hex::encode(value.into_bigint().to_bytes_be())
            )
            .unwrap();
        }
    }
    format!(
        r#"// SPDX-License-Identifier: Apache-2.0
// Constants: light-poseidon 0.4.0, Copyright 2023 Light Protocol Labs.
// Source: https://github.com/Lightprotocol/light-poseidon
// License: https://www.apache.org/licenses/LICENSE-2.0
// Changes: constants encoded as big-endian bytes; original Solidity round loop.
// Spec: BN254 Fr, state [0,left,right], width 3, x^5, 8 full/57 partial rounds.
// Each round adds constants, applies S-box, then row-major MDS. Output state[0].
pragma solidity ^0.8.19;

contract Poseidon2 {{
    uint256 private constant P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function hash(uint256 left, uint256 right) public pure returns (uint256) {{
        require(left < P && right < P, "non-canonical field input");
        bytes memory ark = hex"{ark_hex}";
        bytes memory mds = hex"{mds_hex}";
        uint256[3] memory state = [uint256(0), left, right];
        for (uint256 r = 0; r < 65; ++r) {{
            for (uint256 i = 0; i < 3; ++i) {{
                state[i] = addmod(state[i], word(ark, r * 3 + i), P);
            }}
            state[0] = pow5(state[0]);
            if (r < 4 || r >= 61) {{
                state[1] = pow5(state[1]);
                state[2] = pow5(state[2]);
            }}
            uint256[3] memory next;
            for (uint256 i = 0; i < 3; ++i) {{
                for (uint256 j = 0; j < 3; ++j) {{
                    next[i] = addmod(next[i], mulmod(word(mds, i * 3 + j), state[j], P), P);
                }}
            }}
            state = next;
        }}
        return state[0];
    }}

    function pow5(uint256 value) private pure returns (uint256) {{
        uint256 square = mulmod(value, value, P);
        return mulmod(mulmod(square, square, P), value, P);
    }}

    function word(bytes memory data, uint256 index) private pure returns (uint256 value) {{
        assembly ("memory-safe") {{
            value := mload(add(add(data, 32), mul(index, 32)))
        }}
    }}
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_matches_circom_known_vector() {
        let expected = Fr::from_str_vartime(
            "7853200120776062878684798364095072458815029376092732009249414926327459813530",
        )
        .unwrap();
        assert_eq!(hash([Fr::from(1), Fr::from(2)]), expected);
    }

    #[test]
    fn changing_either_input_changes_digest() {
        let digest = hash([Fr::from(1), Fr::from(2)]);
        assert_ne!(hash([Fr::from(3), Fr::from(2)]), digest);
        assert_ne!(hash([Fr::from(1), Fr::from(3)]), digest);
        assert_ne!(hash([Fr::from(2), Fr::from(1)]), digest);
    }
}
