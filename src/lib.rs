pub mod circuits;
pub mod primitives;

pub use circuits::PoseidonCircuit;
pub use halo2_proofs::halo2curves::pasta::pallas::Base as Fp;
pub use primitives::poseidon_hash;
