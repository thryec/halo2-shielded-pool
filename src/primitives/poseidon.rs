//! Circom-compatible BN254 Poseidon with zero domain state and x^5 S-boxes.
//! One input uses width 2 and 8/56 rounds. Two inputs use width 3 and 8/57.
//! light-poseidon 0.4.0 supplies both the parameters and native reference hash.

use crate::Fr;
use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use halo2_proofs::halo2curves::ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5};

/// Constants are round-major. MDS rows select outputs, and columns select inputs.
#[derive(Clone, Debug)]
pub struct PoseidonSpec {
    pub width: usize,
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub round_constants: Vec<Vec<Fr>>,
    pub mds: Vec<Vec<Fr>>,
}

fn to_halo2(value: ArkFr) -> Fr {
    let bytes = value.into_bigint().to_bytes_le();
    let mut repr = <Fr as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    Option::<Fr>::from(Fr::from_repr(repr)).expect("BN254 scalar fields share a modulus")
}

fn to_ark(value: Fr) -> ArkFr {
    ArkFr::from_le_bytes_mod_order(value.to_repr().as_ref())
}

fn check_arity(arity: usize) {
    assert!(
        matches!(arity, 1 | 2),
        "Poseidon supports only one or two inputs"
    );
}

pub fn parameters(arity: usize) -> PoseidonSpec {
    check_arity(arity);
    let width = arity + 1;
    let params = bn254_x5::get_poseidon_parameters::<ArkFr>(width as u8)
        .expect("selected BN254 Poseidon parameters exist");
    assert_eq!(params.width, width);
    assert_eq!(params.alpha, 5);
    assert_eq!(params.full_rounds, 8);
    assert_eq!(params.partial_rounds, if arity == 1 { 56 } else { 57 });
    assert_eq!(
        params.ark.len(),
        width * (params.full_rounds + params.partial_rounds)
    );
    PoseidonSpec {
        width,
        full_rounds: params.full_rounds,
        partial_rounds: params.partial_rounds,
        round_constants: params
            .ark
            .chunks_exact(width)
            .map(|row| row.iter().copied().map(to_halo2).collect())
            .collect(),
        mds: params
            .mds
            .into_iter()
            .map(|row| row.into_iter().map(to_halo2).collect())
            .collect(),
    }
}

/// Hashes one or two fields. Other arities are outside this protocol.
pub fn poseidon_hash<const L: usize>(inputs: [Fr; L]) -> Fr {
    check_arity(L);
    let mut hasher =
        Poseidon::<ArkFr>::new_circom(L).expect("selected BN254 Poseidon parameters exist");
    to_halo2(
        hasher
            .hash(&inputs.map(to_ark))
            .expect("arity matches parameters"),
    )
}
