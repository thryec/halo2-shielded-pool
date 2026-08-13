use crate::primitives::poseidon::{POSEIDON_RATE, POSEIDON_WIDTH};
use crate::{Fp, primitives::merkle::TREE_DEPTH};
use halo2_poseidon::poseidon::{
    Hash as CircuitPoseidonHash, Pow5Chip, Pow5Config,
    primitives::{ConstantLength, P128Pow5T3},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct MerkleConfig {
    current: Column<Advice>,
    sibling: Column<Advice>,
    path_bit: Column<Advice>,
    left: Column<Advice>,
    right: Column<Advice>,
    q_order: Selector,
    poseidon: Pow5Config<Fp, POSEIDON_WIDTH, POSEIDON_RATE>,
}

pub struct MerkleChip {
    config: MerkleConfig,
    _ph: PhantomData<Fp>,
}

impl MerkleChip {
    pub fn construct(config: MerkleConfig) -> Self {
        MerkleChip {
            config,
            _ph: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        current: Column<Advice>,
        sibling: Column<Advice>,
        path_bit: Column<Advice>,
        left: Column<Advice>,
        right: Column<Advice>,
        poseidon: Pow5Config<Fp, POSEIDON_WIDTH, POSEIDON_RATE>,
    ) -> MerkleConfig {
        let q_order = meta.selector();

        meta.enable_equality(current);
        meta.enable_equality(left);
        meta.enable_equality(right);

        // path bit is either 0 or 1
        meta.create_gate("path bit boolean", |meta| {
            let path_bit = meta.query_advice(path_bit, Rotation::cur());
            let q_order = meta.query_selector(q_order);
            let one = Expression::Constant(Fp::from(1));

            vec![q_order * path_bit.clone() * (one - path_bit)]
        });

        // left matches current or sibling, depending on path bit
        meta.create_gate("left order", |meta| {
            let left = meta.query_advice(left, Rotation::cur());
            let current = meta.query_advice(current, Rotation::cur());
            let sibling = meta.query_advice(sibling, Rotation::cur());
            let path_bit = meta.query_advice(path_bit, Rotation::cur());

            let q_order = meta.query_selector(q_order);

            let one = Expression::Constant(Fp::from(1));

            // if path bit = 0, left = current
            // if path bit = 1, left = sibling
            vec![
                q_order.clone() * path_bit.clone() * (left.clone() - sibling),
                q_order * (one - path_bit) * (left - current),
            ]
        });

        // right is the other value
        meta.create_gate("right order", |meta| {
            let right = meta.query_advice(right, Rotation::cur());
            let current = meta.query_advice(current, Rotation::cur());
            let sibling = meta.query_advice(sibling, Rotation::cur());
            let path_bit = meta.query_advice(path_bit, Rotation::cur());

            let q_order = meta.query_selector(q_order);

            let one = Expression::Constant(Fp::from(1));

            // if path bit = 0, right = sibling
            // if path bit = 1, right = current
            vec![
                q_order.clone() * path_bit.clone() * (right.clone() - current),
                q_order * (one - path_bit) * (right - sibling),
            ]
        });

        MerkleConfig {
            current,
            sibling,
            path_bit,
            left,
            right,
            q_order,
            poseidon,
        }
    }

    // returns assigned cell holding the computed root
    pub fn compute_root(
        &self,                              // merkle chip and config
        mut layouter: impl Layouter<Fp>,    // assigns circuit regions
        leaf: AssignedCell<Fp, Fp>,         // constrained commitment cell
        siblings: [Value<Fp>; TREE_DEPTH],  // eight private sibling hashes
        path_bits: [Value<Fp>; TREE_DEPTH], // eight private values expected to be 0 or 1
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let config = &self.config;
        let mut current = leaf;

        for level in 0..TREE_DEPTH {
            let sibling = siblings[level];
            let path_bit = path_bits[level];
            let current_value = current.value().copied();

            let left_value = current_value + path_bit * (sibling - current_value);
            let right_value = sibling + path_bit * (current_value - sibling);

            let (left_cell, right_cell) = layouter.assign_region(
                || format!("order Merkle level {level}"),
                |mut region| {
                    config.q_order.enable(&mut region, 0)?;

                    current.copy_advice(|| "current", &mut region, config.current, 0)?;
                    region.assign_advice(|| "sibling", config.sibling, 0, || sibling)?;
                    region.assign_advice(|| "path bit", config.path_bit, 0, || path_bit)?;

                    let left_cell =
                        region.assign_advice(|| "left", config.left, 0, || left_value)?;
                    let right_cell =
                        region.assign_advice(|| "right", config.right, 0, || right_value)?;

                    Ok((left_cell, right_cell))
                },
            )?;

            let poseidon_chip = Pow5Chip::construct(config.poseidon.clone());
            let hasher = CircuitPoseidonHash::<
                Fp,
                Pow5Chip<Fp, POSEIDON_WIDTH, POSEIDON_RATE>,
                P128Pow5T3,
                ConstantLength<2>,
                POSEIDON_WIDTH,
                POSEIDON_RATE,
            >::init(
                poseidon_chip,
                layouter.namespace(|| format!("initialise Poseidon level {level}")),
            )?;

            current = hasher.hash(
                layouter.namespace(|| format!("hash Merkle level {level}")),
                [left_cell, right_cell],
            )?;
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::merkle::MerkleTree;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Circuit, Instance},
    };

    const K: u32 = 10;

    #[derive(Clone)]
    struct MerkleTestConfig {
        merkle: MerkleConfig,
        instance: Column<Instance>,
    }

    #[derive(Clone)]
    struct MerkleTestCircuit {
        leaf: Value<Fp>,
        siblings: [Value<Fp>; TREE_DEPTH],
        path_bits: [Value<Fp>; TREE_DEPTH],
    }

    impl MerkleTestCircuit {
        fn new(leaf: Fp, siblings: [Fp; TREE_DEPTH], path_bits: [Fp; TREE_DEPTH]) -> Self {
            Self {
                leaf: Value::known(leaf),
                siblings: siblings.map(Value::known),
                path_bits: path_bits.map(Value::known),
            }
        }
    }

    impl Circuit<Fp> for MerkleTestCircuit {
        type Config = MerkleTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                leaf: Value::unknown(),
                siblings: [Value::unknown(); TREE_DEPTH],
                path_bits: [Value::unknown(); TREE_DEPTH],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let current = meta.advice_column();
            let sibling = meta.advice_column();
            let path_bit = meta.advice_column();
            let left = meta.advice_column();
            let right = meta.advice_column();

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
            let merkle =
                MerkleChip::configure(meta, current, sibling, path_bit, left, right, poseidon);

            MerkleTestConfig { merkle, instance }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let leaf_cell = layouter.assign_region(
                || "load leaf",
                |mut region| {
                    region.assign_advice(|| "leaf", config.merkle.current, 0, || self.leaf)
                },
            )?;

            let chip = MerkleChip::construct(config.merkle);
            let root = chip.compute_root(
                layouter.namespace(|| "compute Merkle root"),
                leaf_cell,
                self.siblings,
                self.path_bits,
            )?;

            layouter.constrain_instance(root.cell(), config.instance, 0)
        }
    }

    fn native_witness(
        leaves: &[Fp],
        leaf_index: usize,
    ) -> (Fp, [Fp; TREE_DEPTH], [Fp; TREE_DEPTH], Fp) {
        let mut tree = MerkleTree::new();
        for leaf in leaves {
            tree.insert(*leaf).unwrap();
        }

        let path = tree.prove(leaf_index).unwrap();
        let siblings = *path.siblings();
        let path_bits = std::array::from_fn(|level| Fp::from(path.path_bits()[level] as u64));

        (leaves[leaf_index], siblings, path_bits, tree.root())
    }

    #[test]
    fn merkle_gadget_accepts_real_native_path() {
        let leaves = [Fp::from(5), Fp::from(7), Fp::from(11), Fp::from(13)];
        let (leaf, siblings, path_bits, root) = native_witness(&leaves, 2);
        let circuit = MerkleTestCircuit::new(leaf, siblings, path_bits);

        let prover = MockProver::run(K, &circuit, vec![vec![root]]).unwrap();

        prover.assert_satisfied();
    }

    #[test]
    fn merkle_gadget_rejects_wrong_sibling() {
        let leaves = [Fp::from(5), Fp::from(7), Fp::from(11), Fp::from(13)];
        let (leaf, mut siblings, path_bits, root) = native_witness(&leaves, 2);
        siblings[0] += Fp::from(1);
        let circuit = MerkleTestCircuit::new(leaf, siblings, path_bits);

        let prover = MockProver::run(K, &circuit, vec![vec![root]]).unwrap();

        assert!(prover.verify().is_err());
    }

    #[test]
    fn merkle_gadget_rejects_wrong_leaf() {
        let leaves = [Fp::from(5), Fp::from(7), Fp::from(11), Fp::from(13)];
        let (leaf, siblings, path_bits, root) = native_witness(&leaves, 2);
        let circuit = MerkleTestCircuit::new(leaf + Fp::from(1), siblings, path_bits);

        let prover = MockProver::run(K, &circuit, vec![vec![root]]).unwrap();

        assert!(prover.verify().is_err());
    }

    #[test]
    fn merkle_gadget_rejects_flipped_path_bit() {
        let leaves = [Fp::from(5), Fp::from(7), Fp::from(11), Fp::from(13)];
        let (leaf, siblings, mut path_bits, root) = native_witness(&leaves, 2);
        path_bits[0] = Fp::from(1) - path_bits[0];
        let circuit = MerkleTestCircuit::new(leaf, siblings, path_bits);

        let prover = MockProver::run(K, &circuit, vec![vec![root]]).unwrap();

        assert!(prover.verify().is_err());
    }

    #[test]
    fn merkle_gadget_rejects_non_boolean_path_bit() {
        let leaves = [Fp::from(5), Fp::from(5)];
        let (leaf, siblings, mut path_bits, root) = native_witness(&leaves, 0);
        path_bits[0] = Fp::from(2);
        let circuit = MerkleTestCircuit::new(leaf, siblings, path_bits);

        let prover = MockProver::run(K, &circuit, vec![vec![root]]).unwrap();

        assert!(prover.verify().is_err());
    }
}
