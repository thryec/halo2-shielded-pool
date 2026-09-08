use crate::{
    Fr,
    gadgets::{
        AssignedValue,
        poseidon::{PoseidonChip, PoseidonConfig},
    },
    primitives::merkle::TREE_DEPTH,
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::ff::Field,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct MerkleConfig {
    current: Column<Advice>,
    sibling: Column<Advice>,
    bit: Column<Advice>,
    left: Column<Advice>,
    right: Column<Advice>,
    pub(crate) order: Selector,
    poseidon: PoseidonConfig<3>,
}

pub struct MerkleChip {
    config: MerkleConfig,
    #[cfg(test)]
    fault: Option<(usize, Fault)>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum Fault {
    Current,
    Left,
    Right,
}

impl MerkleChip {
    pub fn configure(meta: &mut ConstraintSystem<Fr>, poseidon: PoseidonConfig<3>) -> MerkleConfig {
        let [current, sibling, bit, left, right] = std::array::from_fn(|_| meta.advice_column());
        for column in [current, left, right] {
            meta.enable_equality(column);
        }
        let order = meta.selector();
        meta.create_gate("Merkle order", |meta| {
            let q = meta.query_selector(order);
            let current = meta.query_advice(current, Rotation::cur());
            let sibling = meta.query_advice(sibling, Rotation::cur());
            let bit = meta.query_advice(bit, Rotation::cur());
            let left = meta.query_advice(left, Rotation::cur());
            let right = meta.query_advice(right, Rotation::cur());
            vec![
                q.clone() * bit.clone() * (bit.clone() - Expression::Constant(Fr::ONE)),
                q.clone()
                    * (left - current.clone() - bit.clone() * (sibling.clone() - current.clone())),
                q * (right - sibling.clone() - bit * (current - sibling)),
            ]
        });
        MerkleConfig {
            current,
            sibling,
            bit,
            left,
            right,
            order,
            poseidon,
        }
    }

    pub fn construct(config: MerkleConfig) -> Self {
        Self {
            config,
            #[cfg(test)]
            fault: None,
        }
    }

    pub fn compute_root(
        &self,
        mut layouter: impl Layouter<Fr>,
        offset: &mut usize,
        leaf: AssignedValue,
        siblings: [Value<Fr>; TREE_DEPTH],
        bits: [Value<Fr>; TREE_DEPTH],
    ) -> Result<AssignedValue, Error> {
        let mut current = leaf;
        for level in 0..TREE_DEPTH {
            let row = *offset;
            *offset += 1;
            let config = &self.config;
            let current_value = current.value;
            #[cfg(test)]
            let current_value = if matches!(self.fault, Some((index, Fault::Current)) if index == level)
            {
                current_value + Value::known(Fr::ONE)
            } else {
                current_value
            };
            let sibling = siblings[level];
            let bit = bits[level];
            let left = current_value + bit * (sibling - current_value);
            let right = sibling + bit * (current_value - sibling);
            #[cfg(test)]
            let left = if matches!(self.fault, Some((index, Fault::Left)) if index == level) {
                left + Value::known(Fr::ONE)
            } else {
                left
            };
            #[cfg(test)]
            let right = if matches!(self.fault, Some((index, Fault::Right)) if index == level) {
                right + Value::known(Fr::ONE)
            } else {
                right
            };
            let inputs = layouter.assign_region(
                || format!("order level {level}"),
                |mut region| {
                    config.order.enable(&mut region, row)?;
                    let copied =
                        AssignedValue::assign(&mut region, config.current, row, current_value);
                    region.constrain_equal(copied.cell, current.cell);
                    AssignedValue::assign(&mut region, config.sibling, row, sibling);
                    AssignedValue::assign(&mut region, config.bit, row, bit);
                    Ok([
                        AssignedValue::assign(&mut region, config.left, row, left),
                        AssignedValue::assign(&mut region, config.right, row, right),
                    ])
                },
            )?;
            current = PoseidonChip::construct(config.poseidon.clone()).hash(
                layouter.namespace(|| format!("parent {level}")),
                offset,
                inputs,
            )?;
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{merkle::MerkleTree, poseidon::poseidon_hash};
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, Instance},
    };

    #[derive(Clone)]
    struct PathCircuit {
        leaf: Fr,
        siblings: [Fr; TREE_DEPTH],
        bits: [Fr; TREE_DEPTH],
        root: Fr,
        fault: Option<(usize, Fault)>,
    }

    impl Circuit<Fr> for PathCircuit {
        type Config = (MerkleConfig, Column<Instance>);
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self {
            self.clone()
        }
        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let poseidon = PoseidonChip::<3>::configure(meta);
            let merkle = MerkleChip::configure(meta, poseidon);
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            (merkle, instance)
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let leaf = layouter.assign_region(
                || "leaf",
                |mut region| {
                    Ok(AssignedValue::assign(
                        &mut region,
                        config.0.current,
                        0,
                        Value::known(self.leaf),
                    ))
                },
            )?;
            let mut chip = MerkleChip::construct(config.0);
            chip.fault = self.fault;
            let mut offset = 1;
            let root = chip.compute_root(
                layouter.namespace(|| "path"),
                &mut offset,
                leaf,
                self.siblings.map(Value::known),
                self.bits.map(Value::known),
            )?;
            layouter.constrain_instance(root.cell, config.1, 0);
            Ok(())
        }
    }

    fn circuit() -> PathCircuit {
        let mut tree = MerkleTree::new();
        for leaf in 1..=8 {
            tree.insert(Fr::from(leaf)).unwrap();
        }
        let path = tree.prove(5).unwrap();
        PathCircuit {
            leaf: Fr::from(6),
            siblings: *path.siblings(),
            bits: path.path_bits().map(|bit| Fr::from(u64::from(bit))),
            root: tree.root(),
            fault: None,
        }
    }

    fn forged_root(circuit: &PathCircuit) -> Fr {
        let mut current = circuit.leaf;
        for level in 0..TREE_DEPTH {
            let fault = circuit
                .fault
                .filter(|(fault_level, _)| *fault_level == level)
                .map(|(_, fault)| fault);
            if matches!(fault, Some(Fault::Current)) {
                current += Fr::ONE;
            }
            let sibling = circuit.siblings[level];
            let bit = circuit.bits[level];
            let mut left = current + bit * (sibling - current);
            let mut right = sibling + bit * (current - sibling);
            if matches!(fault, Some(Fault::Left)) {
                left += Fr::ONE;
            }
            if matches!(fault, Some(Fault::Right)) {
                right += Fr::ONE;
            }
            current = poseidon_hash([left, right]);
        }
        current
    }

    #[test]
    fn forged_left_right_or_current_rejected_at_each_level_with_matching_root() {
        let honest = circuit();
        for level in 0..TREE_DEPTH {
            for fault in [Fault::Current, Fault::Left, Fault::Right] {
                let mut circuit = honest.clone();
                circuit.fault = Some((level, fault));
                circuit.root = forged_root(&circuit);
                let failures = MockProver::run(10, &circuit, vec![vec![circuit.root]])
                    .unwrap()
                    .verify()
                    .unwrap_err();
                if matches!(fault, Fault::Current) {
                    assert!(
                        failures
                            .iter()
                            .all(|failure| matches!(failure, VerifyFailure::Permutation { .. })),
                        "{failures:?}"
                    );
                } else {
                    assert_eq!(failures.len(), 1, "{failures:?}");
                    assert!(matches!(
                        failures[0],
                        VerifyFailure::ConstraintNotSatisfied { .. }
                    ));
                }
            }
        }
    }

    #[test]
    fn ordered_merkle_path_matches_native_tree() {
        let circuit = circuit();
        MockProver::run(10, &circuit, vec![vec![circuit.root]])
            .unwrap()
            .assert_satisfied();
    }

    #[test]
    fn empty_merkle_tree_matches_frozen_root() {
        use halo2_proofs::halo2curves::ff::PrimeField;
        let mut zero = Fr::ZERO;
        let siblings = std::array::from_fn(|_| {
            let sibling = zero;
            zero = poseidon_hash([zero, zero]);
            sibling
        });
        let root = Fr::from_str_vartime(
            "21551820661461729022865262380882070649935529853313286572328683688269863701601",
        )
        .unwrap();
        let circuit = PathCircuit {
            leaf: Fr::ZERO,
            siblings,
            bits: [Fr::ZERO; TREE_DEPTH],
            root,
            fault: None,
        };
        MockProver::run(10, &circuit, vec![vec![root]])
            .unwrap()
            .assert_satisfied();
    }
}
