use halo2_poseidon::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash as CircuitPoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};

use halo2_shielded_pool::{poseidon_hash, Fp};

const WIDTH: usize = 3;
const RATE: usize = 2;

/// Configuration shared by every [`PoseidonCircuit`] witness.
#[derive(Clone, Debug)]
pub struct PoseidonConfig<const L: usize> {
    input: [Column<Advice>; L],
    output: Column<Instance>,
    poseidon: Pow5Config<Fp, WIDTH, RATE>,
}

/// Proves that a public digest is the Poseidon hash of two private field elements.
#[derive(Clone, Debug)]
pub struct PoseidonCircuit<const L: usize> {
    message: Value<[Fp; L]>,
}

impl<const L: usize> PoseidonCircuit<L> {
    pub fn new(message: [Fp; L]) -> Self {
        Self {
            message: Value::known(message),
        }
    }
}

impl<const L: usize> Circuit<Fp> for PoseidonCircuit<L> {
    type Config = PoseidonConfig<L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        assert!(L <= RATE, "spike supports messages up to Poseidon's rate");

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
            input: std::array::from_fn(|index| state[index]),
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
                let mut cells = Vec::with_capacity(L);
                for index in 0..L {
                    cells.push(region.assign_advice(
                        || format!("message[{index}]"),
                        config.input[index],
                        0,
                        || self.message.map(|message| message[index]),
                    )?);
                }

                cells.try_into().map_err(|_| Error::Synthesis)
            },
        )?;

        let chip = Pow5Chip::construct(config.poseidon);
        let hasher = CircuitPoseidonHash::<
            Fp,
            Pow5Chip<Fp, WIDTH, RATE>,
            P128Pow5T3,
            ConstantLength<L>,
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
    fn two_input_circuit_digest_matches_native_hash() {
        let message = [Fp::from(7), Fp::from(42)];
        let digest = poseidon_hash(message);
        let circuit = PoseidonCircuit::new(message);

        let prover = MockProver::run(K, &circuit, vec![vec![digest]]).unwrap();

        prover.assert_satisfied();
    }

    #[test]
    fn one_input_circuit_digest_matches_native_hash() {
        let message = [Fp::from(7)];
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
