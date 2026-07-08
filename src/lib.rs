use ff::PrimeField;
use halo2_poseidon::poseidon::primitives::{
    ConstantLength, Hash as NativePoseidonHash, P128Pow5T3 
}
use halo2_proofs::halo2curves::pasta::pallas::Base as Fp; 

pub fn poseidon_hash