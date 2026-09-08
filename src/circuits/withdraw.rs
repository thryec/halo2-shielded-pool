use crate::{
    Fr,
    gadgets::{
        AssignedValue,
        merkle::{MerkleChip, MerkleConfig},
        note::{NoteChip, NoteConfig},
        poseidon::{PoseidonChip, PoseidonConfig},
        range::{RangeChip, RangeConfig},
    },
    primitives::{
        context::withdrawal_binding,
        merkle::{MerklePath, TREE_DEPTH},
        note::Note,
    },
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::ff::Field,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
};
use snark_verifier_sdk::CircuitExt;

pub const K: u32 = 10;

#[derive(Clone, Debug)]
pub struct WithdrawConfig {
    note: NoteConfig,
    merkle: MerkleConfig,
    two: PoseidonConfig<3>,
    range: RangeConfig,
    context: Column<Advice>,
    instance: Column<Instance>,
}

/// Public rows: root, nullifier hash, recipient, domain, binding.
/// The caller's pool contract must check that domain matches its own context.
#[derive(Clone, Debug)]
pub struct WithdrawCircuit {
    pub nullifier: Value<Fr>,
    pub secret: Value<Fr>,
    pub siblings: [Value<Fr>; TREE_DEPTH],
    pub path_bits: [Value<Fr>; TREE_DEPTH],
    pub recipient: Value<Fr>,
    pub domain: Value<Fr>,
    pub public_inputs: [Fr; 5],
}

impl WithdrawCircuit {
    pub fn new(note: Note, path: &MerklePath, recipient: Fr, domain: Fr) -> Self {
        Self {
            nullifier: Value::known(note.nullifier()),
            secret: Value::known(note.secret()),
            siblings: path.siblings().map(Value::known),
            path_bits: path
                .path_bits()
                .map(|bit| Value::known(Fr::from(u64::from(bit)))),
            recipient: Value::known(recipient),
            domain: Value::known(domain),
            public_inputs: [
                path.compute_root(note.commitment()),
                note.nullifier_hash(),
                recipient,
                domain,
                withdrawal_binding(note.nullifier(), recipient, domain),
            ],
        }
    }
}

impl Circuit<Fr> for WithdrawCircuit {
    type Config = WithdrawConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            nullifier: Value::unknown(),
            secret: Value::unknown(),
            siblings: [Value::unknown(); TREE_DEPTH],
            path_bits: [Value::unknown(); TREE_DEPTH],
            recipient: Value::unknown(),
            domain: Value::unknown(),
            public_inputs: [Fr::ZERO; 5],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let one = PoseidonChip::<2>::configure(meta);
        let two = PoseidonChip::<3>::configure(meta);
        let note = NoteChip::configure(meta, one, two.clone());
        let merkle = MerkleChip::configure(meta, two.clone());
        let range = RangeChip::configure(meta);
        let context = meta.advice_column();
        let instance = meta.instance_column();
        meta.enable_equality(context);
        meta.enable_equality(instance);
        WithdrawConfig {
            note,
            merkle,
            two,
            range,
            context,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut offset = 0;
        let note = NoteChip::construct(config.note).compute_hashes(
            layouter.namespace(|| "note"),
            &mut offset,
            self.nullifier,
            self.secret,
        )?;
        let root = MerkleChip::construct(config.merkle).compute_root(
            layouter.namespace(|| "membership"),
            &mut offset,
            note.commitment,
            self.siblings,
            self.path_bits,
        )?;
        let [recipient, domain] = layouter.assign_region(
            || "withdrawal context",
            |mut region| {
                Ok([
                    AssignedValue::assign(&mut region, config.context, offset, self.recipient),
                    AssignedValue::assign(&mut region, config.context, offset + 1, self.domain),
                ])
            },
        )?;
        offset += 2;
        RangeChip::construct(config.range).check(
            layouter.namespace(|| "recipient range"),
            &mut offset,
            recipient,
        )?;
        let hash = PoseidonChip::construct(config.two);
        let recipient_binding = hash.hash(
            layouter.namespace(|| "nullifier and recipient"),
            &mut offset,
            [note.nullifier, recipient],
        )?;
        let binding = hash.hash(
            layouter.namespace(|| "domain binding"),
            &mut offset,
            [recipient_binding, domain],
        )?;
        for (row, cell) in [root, note.nullifier_hash, recipient, domain, binding]
            .into_iter()
            .enumerate()
        {
            layouter.constrain_instance(cell.cell, config.instance, row);
        }
        Ok(())
    }
}

impl CircuitExt<Fr> for WithdrawCircuit {
    fn num_instance(&self) -> Vec<usize> {
        vec![5]
    }
    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.public_inputs.to_vec()]
    }
    fn selectors(config: &Self::Config) -> Vec<Selector> {
        let mut selectors = config.note.one.selectors();
        selectors.extend(config.two.selectors());
        selectors.push(config.merkle.order);
        selectors.extend(config.range.selectors());
        selectors
    }
}
