use crate::Fp;
use crate::primitives::poseidon::{POSEIDON_RATE, POSEIDON_WIDTH};
use halo2_poseidon::poseidon::{
    Hash as CircuitPoseidonHash, Pow5Chip, Pow5Config,
    primitives::{ConstantLength, P128Pow5T3},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct NoteHashConfig {
    nullifier: Column<Advice>,
    secret: Column<Advice>,
    poseidon: Pow5Config<Fp, POSEIDON_WIDTH, POSEIDON_RATE>,
}

pub struct NoteHashChip {
    config: NoteHashConfig,
    _ph: PhantomData<Fp>,
}

impl NoteHashChip {
    pub fn construct(config: NoteHashConfig) -> Self {
        NoteHashChip {
            config,
            _ph: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        nullifier: Column<Advice>,
        secret: Column<Advice>,
        poseidon: Pow5Config<Fp, POSEIDON_WIDTH, POSEIDON_RATE>,
    ) -> NoteHashConfig {
        meta.enable_equality(nullifier);
        meta.enable_equality(secret);

        NoteHashConfig {
            nullifier,
            secret,
            poseidon,
        }
    }

    // assign private values into advice cells
    // poseidon hasher copy constrains these cells into its state before hashing
    pub fn compute_hashes(
        &self,
        mut layouter: impl Layouter<Fp>,
        nullifier: Value<Fp>,
        secret: Value<Fp>,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        let config = &self.config;

        let (nullifier_cell, secret_cell) = layouter.assign_region(
            || "hash nullifier and secret",
            |mut region| {
                let nullifier_cell =
                    region.assign_advice(|| "nullifier", config.nullifier, 0, || nullifier)?;
                let secret_cell = region.assign_advice(|| "secret", config.secret, 0, || secret)?;
                Ok((nullifier_cell, secret_cell))
            },
        )?;

        // create two hasher instances because .hash consumes the instance
        // and each input length needs its own hasher
        let commitment_chip = Pow5Chip::construct(config.poseidon.clone());
        let commitment_hasher = CircuitPoseidonHash::<
            Fp,
            Pow5Chip<Fp, POSEIDON_WIDTH, POSEIDON_RATE>,
            P128Pow5T3,
            ConstantLength<2>,
            POSEIDON_WIDTH,
            POSEIDON_RATE,
        >::init(
            commitment_chip,
            layouter.namespace(|| "initialise Poseidon"),
        )?;

        let commitment = commitment_hasher.hash(
            layouter.namespace(|| "hash commitment"),
            [nullifier_cell.clone(), secret_cell.clone()],
        )?;

        let nullifier_chip = Pow5Chip::construct(config.poseidon.clone());
        let nullifier_hasher =
            CircuitPoseidonHash::<
                Fp,
                Pow5Chip<Fp, POSEIDON_WIDTH, POSEIDON_RATE>,
                P128Pow5T3,
                ConstantLength<1>,
                POSEIDON_WIDTH,
                POSEIDON_RATE,
            >::init(nullifier_chip, layouter.namespace(|| "initialise Poseidon"))?;

        let nullifier_hash = nullifier_hasher.hash(
            layouter.namespace(|| "hash nullifier hash"),
            [nullifier_cell],
        )?;

        Ok((commitment, nullifier_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::note::Note;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Circuit, Instance},
    };

    const K: u32 = 7;

    #[derive(Clone)]
    struct NoteHashTestConfig {
        note_hash: NoteHashConfig,
        instance: Column<Instance>,
    }

    #[derive(Clone)]
    struct NoteHashTestCircuit {
        nullifier: Value<Fp>,
        secret: Value<Fp>,
    }

    impl NoteHashTestCircuit {
        fn new(nullifier: Fp, secret: Fp) -> Self {
            Self {
                nullifier: Value::known(nullifier),
                secret: Value::known(secret),
            }
        }
    }

    impl Circuit<Fp> for NoteHashTestCircuit {
        type Config = NoteHashTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                nullifier: Value::unknown(),
                secret: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let nullifier = meta.advice_column();
            let secret = meta.advice_column();
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
            let instance = meta.instance_column();

            meta.enable_equality(instance);
            meta.enable_constant(round_constants_b[0]);

            let poseidon = Pow5Chip::configure::<P128Pow5T3>(
                meta,
                state,
                partial_sbox,
                round_constants_a,
                round_constants_b,
            );
            let note_hash = NoteHashChip::configure(meta, nullifier, secret, poseidon);

            NoteHashTestConfig {
                note_hash,
                instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = NoteHashChip::construct(config.note_hash);
            let (commitment, nullifier_hash) = chip.compute_hashes(
                layouter.namespace(|| "compute note hashes"),
                self.nullifier,
                self.secret,
            )?;

            layouter.constrain_instance(commitment.cell(), config.instance, 0)?;
            layouter.constrain_instance(nullifier_hash.cell(), config.instance, 1)
        }
    }

    #[test]
    fn note_hash_gadget_matches_native_note_hashes() {
        let nullifier = Fp::from(7);
        let secret = Fp::from(42);
        let note = Note::new(nullifier, secret);
        let circuit = NoteHashTestCircuit::new(nullifier, secret);

        let prover = MockProver::run(
            K,
            &circuit,
            vec![vec![note.commitment(), note.nullifier_hash()]],
        )
        .unwrap();

        prover.assert_satisfied();
    }

    #[test]
    fn note_hash_gadget_rejects_wrong_commitment() {
        let nullifier = Fp::from(7);
        let secret = Fp::from(42);
        let note = Note::new(nullifier, secret);
        let circuit = NoteHashTestCircuit::new(nullifier, secret);
        let wrong_commitment = note.commitment() + Fp::from(1);

        let prover = MockProver::run(
            K,
            &circuit,
            vec![vec![wrong_commitment, note.nullifier_hash()]],
        )
        .unwrap();

        assert!(prover.verify().is_err());
    }

    #[test]
    fn note_hash_gadget_rejects_wrong_nullifier_hash() {
        let nullifier = Fp::from(7);
        let secret = Fp::from(42);
        let note = Note::new(nullifier, secret);
        let circuit = NoteHashTestCircuit::new(nullifier, secret);
        let wrong_nullifier_hash = note.nullifier_hash() + Fp::from(1);

        let prover = MockProver::run(
            K,
            &circuit,
            vec![vec![note.commitment(), wrong_nullifier_hash]],
        )
        .unwrap();

        assert!(prover.verify().is_err());
    }
}
