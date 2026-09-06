use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::{bn256::Fr, ff::Field},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use snark_verifier_sdk::CircuitExt;

use crate::native;

#[derive(Clone, Debug)]
pub struct PoseidonConfig {
    state: [Column<Advice>; 3],
    round_constants: [Column<Fixed>; 3],
    initial: Selector,
    full: Selector,
    partial: Selector,
    instance: Column<Instance>,
}

#[derive(Clone, Debug)]
pub struct PoseidonCircuit {
    inputs: Value<[Fr; 2]>,
    pub digest: Fr,
    #[cfg(test)]
    trace_override: Option<Vec<[Fr; 3]>>,
}

impl PoseidonCircuit {
    pub fn new(inputs: [Fr; 2]) -> Self {
        Self {
            inputs: Value::known(inputs),
            digest: native::hash(inputs),
            #[cfg(test)]
            trace_override: None,
        }
    }
}

fn fifth_power(value: Expression<Fr>) -> Expression<Fr> {
    let square = value.clone() * value.clone();
    square.clone() * square * value
}

impl Circuit<Fr> for PoseidonCircuit {
    type Config = PoseidonConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: Value::unknown(),
            digest: Fr::ZERO,
            #[cfg(test)]
            trace_override: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // Axiom caps inferred degree at five; the selector times x^5 needs six.
        meta.set_minimum_degree(6);
        let state = std::array::from_fn(|_| meta.advice_column());
        let round_constants = std::array::from_fn(|_| meta.fixed_column());
        let initial = meta.selector();
        let full = meta.selector();
        let partial = meta.selector();
        let instance = meta.instance_column();
        meta.enable_equality(state[0]);
        meta.enable_equality(instance);

        meta.create_gate("zero initial capacity", |meta| {
            vec![meta.query_selector(initial) * meta.query_advice(state[0], Rotation::cur())]
        });

        let (_, mds) = native::parameters();
        for (name, selector, is_full) in [
            ("Poseidon full round", full, true),
            ("Poseidon partial round", partial, false),
        ] {
            meta.create_gate(name, |meta| {
                let q = meta.query_selector(selector);
                let nonlinear: [Expression<Fr>; 3] = std::array::from_fn(|word| {
                    let value = meta.query_advice(state[word], Rotation::cur())
                        + meta.query_fixed(round_constants[word], Rotation::cur());
                    if is_full || word == 0 {
                        fifth_power(value)
                    } else {
                        value
                    }
                });
                (0..3)
                    .map(|word| {
                        let mixed = (0..3).fold(Expression::Constant(Fr::ZERO), |sum, input| {
                            sum + nonlinear[input].clone() * Expression::Constant(mds[word][input])
                        });
                        q.clone() * (meta.query_advice(state[word], Rotation::next()) - mixed)
                    })
                    .collect::<Vec<_>>()
            });
        }

        PoseidonConfig {
            state,
            round_constants,
            initial,
            full,
            partial,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (round_constants, mds) = native::parameters();
        let digest = layouter.assign_region(
            || "Poseidon permutation",
            |mut region| {
                config.initial.enable(&mut region, 0)?;
                let mut state = self.inputs.map(|inputs| [Fr::ZERO, inputs[0], inputs[1]]);
                #[cfg(test)]
                if let Some(trace) = &self.trace_override {
                    state = Value::known(trace[0]);
                }
                for word in 0..3 {
                    region.assign_advice(config.state[word], 0, state.map(|values| values[word]));
                }

                let mut digest = None;
                for (round, constants) in round_constants.iter().enumerate() {
                    let is_full = !(native::FULL_ROUNDS / 2
                        ..native::FULL_ROUNDS / 2 + native::PARTIAL_ROUNDS)
                        .contains(&round);
                    if is_full { config.full } else { config.partial }
                        .enable(&mut region, round)?;
                    for (word, constant) in constants.iter().enumerate() {
                        region.assign_fixed(config.round_constants[word], round, *constant);
                    }
                    state = state.map(|mut values| {
                        for word in 0..3 {
                            values[word] += constants[word];
                            if is_full || word == 0 {
                                values[word] = values[word].square().square() * values[word];
                            }
                        }
                        std::array::from_fn(|word| {
                            (0..3).fold(Fr::ZERO, |sum, input| {
                                sum + mds[word][input] * values[input]
                            })
                        })
                    });
                    #[cfg(test)]
                    if let Some(trace) = &self.trace_override {
                        state = Value::known(trace[round + 1]);
                    }
                    for word in 0..3 {
                        let cell = region.assign_advice(
                            config.state[word],
                            round + 1,
                            state.map(|values| values[word]),
                        );
                        if word == 0 {
                            digest = Some(cell.cell());
                        }
                    }
                }
                Ok(digest.expect("Poseidon parameters contain rounds"))
            },
        )?;
        layouter.constrain_instance(digest, config.instance, 0);
        Ok(())
    }
}

impl CircuitExt<Fr> for PoseidonCircuit {
    fn num_instance(&self) -> Vec<usize> {
        vec![1]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![vec![self.digest]]
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        vec![config.initial, config.full, config.partial]
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::{FailureLocation, MockProver, VerifyFailure, metadata};

    use super::*;

    // Recompute every later row so only the chosen constraint can reject the trace.
    fn forged_trace(fault_row: usize, fault_word: usize) -> PoseidonCircuit {
        let inputs = [Fr::ONE, Fr::from(2)];
        let (round_constants, mds) = native::parameters();
        let mut state = [Fr::ZERO, inputs[0], inputs[1]];
        let mut trace = Vec::new();
        for row in 0..=round_constants.len() {
            if row == fault_row {
                state[fault_word] += Fr::ONE;
            }
            trace.push(state);
            if let Some(constants) = round_constants.get(row) {
                let full = !(native::FULL_ROUNDS / 2
                    ..native::FULL_ROUNDS / 2 + native::PARTIAL_ROUNDS)
                    .contains(&row);
                for word in 0..3 {
                    state[word] += constants[word];
                    if full || word == 0 {
                        state[word] = state[word].square().square() * state[word];
                    }
                }
                state = std::array::from_fn(|word| {
                    (0..3).fold(Fr::ZERO, |sum, input| sum + mds[word][input] * state[input])
                });
            }
        }
        let mut circuit = PoseidonCircuit::new(inputs);
        circuit.digest = trace.last().unwrap()[0];
        circuit.trace_override = Some(trace);
        circuit
    }

    fn assert_only_gate_fails(
        circuit: PoseidonCircuit,
        gate_index: usize,
        gate_name: &str,
        constraint_index: usize,
        row: usize,
    ) {
        let failures = MockProver::run(8, &circuit, circuit.instances())
            .unwrap()
            .verify()
            .expect_err("a forged trace must fail its defining constraint");
        assert_eq!(failures.len(), 1, "unexpected failures: {failures:?}");
        let expected: metadata::Constraint =
            ((gate_index, gate_name).into(), constraint_index, "").into();
        match &failures[0] {
            VerifyFailure::ConstraintNotSatisfied {
                constraint,
                location,
                ..
            } => {
                assert_eq!(constraint, &expected);
                let failed_row = match location {
                    FailureLocation::InRegion { offset, .. } => *offset,
                    FailureLocation::OutsideRegion { row } => *row,
                };
                assert_eq!(failed_row, row);
            }
            failure => panic!("expected the forged row's gate failure, got {failure:?}"),
        }
    }

    #[test]
    fn nonzero_capacity_with_consistent_trace_fails() {
        assert_only_gate_fails(forged_trace(0, 0), 0, "zero initial capacity", 0, 0);
    }

    #[test]
    fn forged_full_round_output_fails_for_each_word() {
        let round = 1;
        for word in 0..3 {
            assert_only_gate_fails(
                forged_trace(round + 1, word),
                1,
                "Poseidon full round",
                word,
                round,
            );
        }
    }

    #[test]
    fn forged_partial_round_output_fails_for_each_word() {
        let round = native::FULL_ROUNDS / 2;
        for word in 0..3 {
            assert_only_gate_fails(
                forged_trace(round + 1, word),
                2,
                "Poseidon partial round",
                word,
                round,
            );
        }
    }

    #[test]
    fn honest_witness_matches_native_poseidon() {
        for inputs in [
            [Fr::ZERO, Fr::ZERO],
            [Fr::ONE, Fr::from(2)],
            [-Fr::ONE, Fr::from(42)],
        ] {
            let circuit = PoseidonCircuit::new(inputs);
            MockProver::run(8, &circuit, circuit.instances())
                .unwrap()
                .assert_satisfied();
        }
    }

    #[test]
    fn wrong_public_digest_fails() {
        let circuit = PoseidonCircuit::new([Fr::ONE, Fr::from(2)]);
        let prover = MockProver::run(8, &circuit, vec![vec![circuit.digest + Fr::ONE]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn changed_private_input_with_old_digest_fails() {
        let original = PoseidonCircuit::new([Fr::ONE, Fr::from(2)]);
        for inputs in [[Fr::from(3), Fr::from(2)], [Fr::ONE, Fr::from(3)]] {
            let changed = PoseidonCircuit::new(inputs);
            let prover = MockProver::run(8, &changed, original.instances()).unwrap();
            assert!(prover.verify().is_err());
        }
    }
}
