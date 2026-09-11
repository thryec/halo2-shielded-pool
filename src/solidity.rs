//! Generates test hash contracts from the pinned Poseidon parameters.

use crate::{Fr, primitives::poseidon::parameters};
use halo2_proofs::halo2curves::ff::PrimeField;

fn packed(values: impl Iterator<Item = Fr>) -> String {
    values
        .map(|value| {
            let mut bytes = value.to_repr();
            bytes.reverse();

            hex::encode(bytes)
        })
        .collect()
}

pub fn poseidon_source(arity: usize) -> String {
    let spec = parameters(arity);
    let width = spec.width;
    let rounds = spec.full_rounds + spec.partial_rounds;
    let half = spec.full_rounds / 2;
    let partial_end = half + spec.partial_rounds;

    let constants = packed(spec.round_constants.iter().flatten().copied());
    let mds = packed(spec.mds.iter().flatten().copied());

    let (args, check, initial) = match arity {
        1 => ("uint256 value", "value < P", "[uint256(0), value]"),
        2 => (
            "uint256 left, uint256 right",
            "left < P && right < P",
            "[uint256(0), left, right]",
        ),
        _ => unreachable!("parameters rejects unsupported arity"),
    };

    format!(
        r#"// SPDX-License-Identifier: Apache-2.0
// Constants: light-poseidon 0.4.0, Copyright 2023 Light Protocol Labs
// Source: https://github.com/Lightprotocol/light-poseidon
// License: https://www.apache.org/licenses/LICENSE-2.0
// Changes: big-endian packed constants and a Solidity round loop
// Original Poseidon, not Poseidon2: {arity} inputs, width {width}, x^5, 8/{partial} rounds
pragma solidity ^0.8.19;

contract Poseidon{arity} {{
    uint256 private constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function hash({args}) public pure returns (uint256) {{
        require({check}, "noncanonical field input");
        bytes memory constants = hex"{constants}";
        bytes memory mds = hex"{mds}";
        uint256[{width}] memory state = {initial};
        for (uint256 round; round < {rounds}; ++round) {{
            for (uint256 i; i < {width}; ++i) {{
                state[i] = addmod(state[i], word(constants, round * {width} + i), P);
                if (i == 0 || round < {half} || round >= {partial_end}) state[i] = pow5(state[i]);
            }}
            uint256[{width}] memory next;
            for (uint256 i; i < {width}; ++i) {{
                for (uint256 j; j < {width}; ++j) {{
                    next[i] = addmod(next[i], mulmod(word(mds, i * {width} + j), state[j], P), P);
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
        assembly ("memory-safe") {{ value := mload(add(add(data, 32), mul(index, 32))) }}
    }}
}}
"#,
        partial = spec.partial_rounds
    )
}

pub fn verification_key_source(id: [u8; 32]) -> String {
    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

library VerificationKey {{
    bytes32 internal constant ID = 0x{};
}}
"#,
        hex::encode(id)
    )
}
