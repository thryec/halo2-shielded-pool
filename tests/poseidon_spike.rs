use halo2_poseidon::poseidon::{
    Hash as CircuitPoseidonHash, Pow5Chip, Pow5Config,
    primitives::{ConstantLength, P128Pow5T3},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};

use halo2_shielded_pool::{Fp, poseidon_hash};

const WIDTH: usize = 3;
const RATE: usize = 2;
const MESSAGE_LEN: usize = 2;

/// Configuration shared by every [`PoseidonCircuit`] witness.
#[derive(Clone, Debug)]
pub struct PoseidonConfig {
    input: [Column<Advice>; MESSAGE_LEN],
    output: Column<Instance>,
    poseidon: Pow5Config<Fp, WIDTH, RATE>,
}

/// Proves that a public digest is the Poseidon hash of two private field elements.
#[derive(Clone, Debug)]
pub struct PoseidonCircuit {
    message: Value<[Fp; MESSAGE_LEN]>,
}

impl PoseidonCircuit {
    pub fn new(message: [Fp; MESSAGE_LEN]) -> Self {
        Self {
            message: Value::known(message),
        }
    }
}

impl Circuit<Fp> for PoseidonCircuit {
    type Config = PoseidonConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let partial_sbox = meta.advice_column();
        let round_constants_a = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let round_constants_b = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let output = meta.instance_column();

        meta.enable_equality(output);
        meta.enable_constant(round_constants_b[0]);

        PoseidonConfig {
            input: [state[0], state[1]],
            output,
            poseidon: Pow5Chip::configure::<P128Pow5T3>(
                meta,
                state,
                partial_sbox,
                round_constants_a,
                round_constants_b,
            ),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let message = layouter.assign_region(
            || "load private message",
            |mut region| {
                let left = region.assign_advice(
                    || "message[0]",
                    config.input[0],
                    0,
                    || self.message.map(|message| message[0]),
                )?;
                let right = region.assign_advice(
                    || "message[1]",
                    config.input[1],
                    0,
                    || self.message.map(|message| message[1]),
                )?;

                Ok([left, right])
            },
        )?;

        let chip = Pow5Chip::construct(config.poseidon);
        let hasher = CircuitPoseidonHash::<
            Fp,
            Pow5Chip<Fp, WIDTH, RATE>,
            P128Pow5T3,
            ConstantLength<MESSAGE_LEN>,
            WIDTH,
            RATE,
        >::init(chip, layouter.namespace(|| "initialize Poseidon"))?;
        let digest = hasher.hash(layouter.namespace(|| "hash message"), message)?;

        layouter.constrain_instance(digest.cell(), config.output, 0)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;

    use super::*;

    const K: u32 = 6;

    #[test]
    fn circuit_digest_matches_native_hash() {
        let message = [Fp::from(7), Fp::from(42)];
        let digest = poseidon_hash(message);
        let circuit = PoseidonCircuit::new(message);

        let prover = MockProver::run(K, &circuit, vec![vec![digest]]).unwrap();

        prover.assert_satisfied();
    }

    #[test]
    fn circuit_rejects_wrong_public_digest() {
        let message = [Fp::from(7), Fp::from(42)];
        let wrong_digest = poseidon_hash(message) + Fp::from(1);
        let circuit = PoseidonCircuit::new(message);

        let prover = MockProver::run(K, &circuit, vec![vec![wrong_digest]]).unwrap();

        assert!(prover.verify().is_err());
    }
}
