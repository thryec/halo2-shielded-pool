use crate::{
    Fr,
    gadgets::{
        AssignedValue,
        poseidon::{PoseidonChip, PoseidonConfig},
    },
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};

#[derive(Clone, Debug)]
pub struct NoteConfig {
    input: Column<Advice>,
    pub(crate) one: PoseidonConfig<2>,
    pub(crate) two: PoseidonConfig<3>,
}

pub struct NoteChip {
    config: NoteConfig,
}

pub struct NoteCells {
    pub nullifier: AssignedValue,
    pub commitment: AssignedValue,
    pub nullifier_hash: AssignedValue,
}

impl NoteChip {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        one: PoseidonConfig<2>,
        two: PoseidonConfig<3>,
    ) -> NoteConfig {
        let input = meta.advice_column();
        meta.enable_equality(input);
        NoteConfig { input, one, two }
    }

    pub fn construct(config: NoteConfig) -> Self {
        Self { config }
    }

    pub fn compute_hashes(
        &self,
        mut layouter: impl Layouter<Fr>,
        offset: &mut usize,
        nullifier: Value<Fr>,
        secret: Value<Fr>,
    ) -> Result<NoteCells, Error> {
        let start = *offset;
        *offset += 2;
        let [nullifier, secret] = layouter.assign_region(
            || "note fields",
            |mut region| {
                Ok([
                    AssignedValue::assign(&mut region, self.config.input, start, nullifier),
                    AssignedValue::assign(&mut region, self.config.input, start + 1, secret),
                ])
            },
        )?;
        let commitment = PoseidonChip::construct(self.config.two.clone()).hash(
            layouter.namespace(|| "commitment"),
            offset,
            [nullifier, secret],
        )?;
        let nullifier_hash = PoseidonChip::construct(self.config.one.clone()).hash(
            layouter.namespace(|| "nullifier hash"),
            offset,
            [nullifier],
        )?;
        // Return the same cell for the withdrawal binding's private input.
        Ok(NoteCells {
            nullifier,
            commitment,
            nullifier_hash,
        })
    }
}
