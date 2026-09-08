//! Native BN254 rules. Test these before translating them into circuit gates.

pub mod context;
pub mod merkle;
pub mod note;
pub mod poseidon;

pub use poseidon::poseidon_hash;
