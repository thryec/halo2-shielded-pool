pub mod merkle;
pub mod note;
pub mod poseidon;
pub mod range;

use crate::Fr;
use halo2_proofs::{
    circuit::{Cell, Region, Value},
    plonk::{Advice, Column},
};

/// A cell and its witness value. Passing this between chips keeps copy
/// constraints explicit, without exposing Axiom's borrowed assignment type.
#[derive(Clone, Copy, Debug)]
pub struct AssignedValue {
    pub cell: Cell,
    pub value: Value<Fr>,
}

impl AssignedValue {
    pub fn assign(
        region: &mut Region<'_, Fr>,
        column: Column<Advice>,
        row: usize,
        value: Value<Fr>,
    ) -> Self {
        Self {
            cell: region.assign_advice(column, row, value).cell(),
            value,
        }
    }

    pub fn copy(self, region: &mut Region<'_, Fr>, column: Column<Advice>, row: usize) -> Self {
        let copied = Self::assign(region, column, row, self.value);
        region.constrain_equal(self.cell, copied.cell);
        copied
    }
}
