use crate::{
    Fp,
    gadgets::{
        merkle::{MerkleChip, MerkleConfig},
        note::{NoteHashChip, NoteHashConfig},
    },
    primitives::merkle::TREE_DEPTH,
};
use halo2_poseidon::poseidon::{Pow5Chip, primitives::P128Pow5T3};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};

#[derive(Clone)]

pub struct WithdrawConfig {
    merkle: MerkleConfig,
    note: NoteHashConfig,
    instance: Column<Instance>,
}

pub struct WithdrawCircuit {
    pub nullifier: Value<Fp>,
    pub secret: Value<Fp>,
    pub siblings: [Value<Fp>; TREE_DEPTH],
    pub path_bits: [Value<Fp>; TREE_DEPTH],
}

impl Circuit<Fp> for WithdrawCircuit {
    type Config = WithdrawConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            nullifier: Value::unknown(),
            secret: Value::unknown(),
            siblings: [Value::unknown(); TREE_DEPTH],
            path_bits: [Value::unknown(); TREE_DEPTH],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> WithdrawConfig {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // create poseidon columns and pass into Poseidon chip
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

        meta.enable_constant(round_constants_b[0]);

        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state,
            partial_sbox,
            round_constants_a,
            round_constants_b,
        );

        // create note columns and pass into NoteHash chip
        let nullifier = meta.advice_column();
        let secret = meta.advice_column();

        let note = NoteHashChip::configure(meta, nullifier, secret, poseidon.clone());

        // create merkle columns and pass into Merkle chip
        let current = meta.advice_column();
        let sibling = meta.advice_column();
        let path_bit = meta.advice_column();
        let left = meta.advice_column();
        let right = meta.advice_column();

        let merkle = MerkleChip::configure(meta, current, sibling, path_bit, left, right, poseidon);

        WithdrawConfig {
            merkle,
            note,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let note_hash_chip = NoteHashChip::construct(config.note);
        let (commitment, nullifier_hash) = note_hash_chip.compute_hashes(
            layouter.namespace(|| "compute hashes"),
            self.nullifier,
            self.secret,
        )?;

        let merkle_chip = MerkleChip::construct(config.merkle);
        let root = merkle_chip.compute_root(
            layouter.namespace(|| "compute root"),
            commitment,
            self.siblings,
            self.path_bits,
        )?;

        layouter.constrain_instance(root.cell(), config.instance, 0)?;
        layouter.constrain_instance(nullifier_hash.cell(), config.instance, 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{merkle::MerkleTree, note::Note};
    use halo2_proofs::dev::MockProver;

    const K: u32 = 10;

    fn initialize_circuit_state() -> (WithdrawCircuit, Fp, Fp) {
        let nullifier = Fp::from(3);
        let secret = Fp::from(4);

        let note = Note::new(nullifier, secret);
        let mut tree = MerkleTree::new();

        let decoy_note = Note::new(Fp::from(1), Fp::from(2));
        tree.insert(decoy_note.commitment()).unwrap();

        let index = tree.insert(note.commitment()).unwrap();
        let path = tree.prove(index).unwrap();

        let siblings = (*path.siblings()).map(Value::known);
        let path_bits =
            std::array::from_fn(|level| Value::known(Fp::from(path.path_bits()[level] as u64)));

        let circuit = WithdrawCircuit {
            nullifier: Value::known(note.nullifier()),
            secret: Value::known(note.secret()),
            siblings,
            path_bits,
        };

        (circuit, tree.root(), note.nullifier_hash())
    }

    #[test]
    fn withdrawal_works_with_valid_commitment() {
        let (circuit, root, nullifier_hash) = initialize_circuit_state();

        let prover = MockProver::run(K, &circuit, vec![vec![root, nullifier_hash]]).unwrap();

        prover.assert_satisfied();
    }

    #[test]
    fn withdrawal_fails_with_wrong_public_root() {
        let (circuit, root, nullifier_hash) = initialize_circuit_state();
        let wrong_root = root + Fp::from(1);

        let prover = MockProver::run(K, &circuit, vec![vec![wrong_root, nullifier_hash]]).unwrap();

        assert!(prover.verify().is_err());
    }

    #[test]
    fn withdrawal_fails_with_wrong_public_nullifier_hash() {
        let (circuit, root, nullifier_hash) = initialize_circuit_state();
        let wrong_nullifier_hash = nullifier_hash + Fp::from(1);

        let prover = MockProver::run(K, &circuit, vec![vec![root, wrong_nullifier_hash]]).unwrap();

        assert!(prover.verify().is_err());
    }

    #[test]
    fn withdrawal_fails_when_note_is_not_in_tree() {
        let (mut circuit, root, _) = initialize_circuit_state();
        let absent_note = Note::new(Fp::from(5), Fp::from(6));
        circuit.nullifier = Value::known(absent_note.nullifier());
        circuit.secret = Value::known(absent_note.secret());

        let prover =
            MockProver::run(K, &circuit, vec![vec![root, absent_note.nullifier_hash()]]).unwrap();

        assert!(prover.verify().is_err());
    }

    #[test]
    fn withdrawal_fails_with_tampered_secret() {
        let (mut circuit, root, nullifier_hash) = initialize_circuit_state();
        circuit.secret = Value::known(Fp::from(5));

        let prover = MockProver::run(K, &circuit, vec![vec![root, nullifier_hash]]).unwrap();

        assert!(prover.verify().is_err());
    }

    #[test]
    fn withdrawal_fails_with_tampered_merkle_path() {
        let (mut circuit, root, nullifier_hash) = initialize_circuit_state();
        let decoy_note = Note::new(Fp::from(1), Fp::from(2));
        circuit.siblings[0] = Value::known(decoy_note.commitment() + Fp::from(1));

        let prover = MockProver::run(K, &circuit, vec![vec![root, nullifier_hash]]).unwrap();

        assert!(prover.verify().is_err());
    }
}
