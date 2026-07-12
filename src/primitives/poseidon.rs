use halo2_poseidon::poseidon::primitives::{
    ConstantLength, Hash as NativePoseidonHash, P128Pow5T3,
};

use crate::Fp;

pub const MESSAGE_LEN: usize = 2;

/// Computes either one or two-input Poseidon hash outside the circuit.
pub fn poseidon_hash<const L: usize>(message: [Fp; L]) -> Fp {
    NativePoseidonHash::<Fp, P128Pow5T3, ConstantLength<L>, 3, 2>::init().hash(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let message = [Fp::from(1), Fp::from(2)];

        assert_eq!(poseidon_hash(message), poseidon_hash(message));
    }

    #[test]
    fn hash_depends_on_input_order() {
        assert_ne!(
            poseidon_hash([Fp::from(1), Fp::from(2)]),
            poseidon_hash([Fp::from(2), Fp::from(1)]),
        );
    }
}
