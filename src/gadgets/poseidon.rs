//! One permutation per hash, using original Circom parameters.
use crate::{Fr, gadgets::AssignedValue, primitives::poseidon::parameters};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::ff::Field,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct PoseidonConfig<const W: usize> {
    state: [Column<Advice>; W],
    constants: [Column<Fixed>; W],
    initial: Selector,
    full: Selector,
    partial: Selector,
}

impl<const W: usize> PoseidonConfig<W> {
    pub(crate) fn selectors(&self) -> Vec<Selector> {
        vec![self.initial, self.full, self.partial]
    }
}

pub struct PoseidonChip<const W: usize> {
    config: PoseidonConfig<W>,
    #[cfg(test)]
    trace_override: Option<Vec<Vec<Fr>>>,
}

fn fifth(value: Expression<Fr>) -> Expression<Fr> {
    let square = value.clone() * value.clone();
    square.clone() * square * value
}

impl<const W: usize> PoseidonChip<W> {
    pub fn construct(config: PoseidonConfig<W>) -> Self {
        Self {
            config,
            #[cfg(test)]
            trace_override: None,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> PoseidonConfig<W> {
        assert!(
            matches!(W, 2 | 3),
            "only widths two and three are supported"
        );
        // Axiom otherwise caps its inferred degree at five. q * x^5 needs six.
        meta.set_minimum_degree(6);
        let state = std::array::from_fn(|_| meta.advice_column());
        let constants = std::array::from_fn(|_| meta.fixed_column());
        for column in state {
            meta.enable_equality(column);
        }
        let initial = meta.selector();
        let full = meta.selector();
        let partial = meta.selector();
        meta.create_gate("zero Poseidon capacity", |meta| {
            vec![meta.query_selector(initial) * meta.query_advice(state[0], Rotation::cur())]
        });
        let spec = parameters(W - 1);
        for (name, selector, is_full) in [
            ("Poseidon full round", full, true),
            ("Poseidon partial round", partial, false),
        ] {
            meta.create_gate(name, |meta| {
                let q = meta.query_selector(selector);
                let nonlinear: [Expression<Fr>; W] = std::array::from_fn(|word| {
                    let value = meta.query_advice(state[word], Rotation::cur())
                        + meta.query_fixed(constants[word], Rotation::cur());
                    if is_full || word == 0 {
                        fifth(value)
                    } else {
                        value
                    }
                });
                (0..W)
                    .map(|word| {
                        let mixed = (0..W).fold(Expression::Constant(Fr::ZERO), |sum, input| {
                            sum + nonlinear[input].clone()
                                * Expression::Constant(spec.mds[word][input])
                        });
                        q.clone() * (meta.query_advice(state[word], Rotation::next()) - mixed)
                    })
                    .collect::<Vec<_>>()
            });
        }
        PoseidonConfig {
            state,
            constants,
            initial,
            full,
            partial,
        }
    }

    pub fn hash<const L: usize>(
        &self,
        mut layouter: impl Layouter<Fr>,
        offset: &mut usize,
        inputs: [AssignedValue; L],
    ) -> Result<AssignedValue, Error> {
        assert_eq!(L + 1, W, "input count must match Poseidon width");
        let config = &self.config;
        let spec = parameters(L);
        // Axiom's SimpleFloorPlanner uses absolute rows across all regions.
        let start = *offset;
        *offset += spec.round_constants.len() + 1;
        layouter.assign_region(
            || "Poseidon permutation",
            |mut region| {
                config.initial.enable(&mut region, start)?;
                let mut state: [Value<Fr>; W] = std::array::from_fn(|word| {
                    if word == 0 {
                        Value::known(Fr::ZERO)
                    } else {
                        inputs[word - 1].value
                    }
                });
                #[cfg(test)]
                if let Some(trace) = &self.trace_override {
                    state = std::array::from_fn(|word| Value::known(trace[0][word]));
                }
                for (word, value) in state.iter().enumerate() {
                    let cell =
                        AssignedValue::assign(&mut region, config.state[word], start, *value);
                    if word > 0 {
                        region.constrain_equal(cell.cell, inputs[word - 1].cell);
                    }
                }
                let mut digest = None;
                for (round, constants) in spec.round_constants.iter().enumerate() {
                    let full = !(spec.full_rounds / 2..spec.full_rounds / 2 + spec.partial_rounds)
                        .contains(&round);
                    if full { config.full } else { config.partial }
                        .enable(&mut region, start + round)?;
                    for (word, constant) in constants.iter().enumerate() {
                        region.assign_fixed(config.constants[word], start + round, *constant);
                        state[word] = state[word].map(|value| {
                            let shifted = value + constant;
                            if full || word == 0 {
                                shifted.square().square() * shifted
                            } else {
                                shifted
                            }
                        });
                    }
                    state = std::array::from_fn(|word| {
                        (0..W).fold(Value::known(Fr::ZERO), |sum, input| {
                            sum + state[input] * Value::known(spec.mds[word][input])
                        })
                    });
                    #[cfg(test)]
                    if let Some(trace) = &self.trace_override {
                        state = std::array::from_fn(|word| Value::known(trace[round + 1][word]));
                    }
                    for (word, value) in state.iter().enumerate() {
                        let cell = AssignedValue::assign(
                            &mut region,
                            config.state[word],
                            start + round + 1,
                            *value,
                        );
                        if word == 0 {
                            digest = Some(cell);
                        }
                    }
                }
                Ok(digest.expect("selected Poseidon has at least one round"))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, Instance},
    };

    #[derive(Clone)]
    struct HashCircuit<const W: usize, const L: usize> {
        inputs: [Fr; L],
        digest: Fr,
        trace: Option<Vec<Vec<Fr>>>,
    }

    impl<const W: usize, const L: usize> Circuit<Fr> for HashCircuit<W, L> {
        type Config = (PoseidonConfig<W>, Column<Advice>, Column<Instance>);
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let config = PoseidonChip::<W>::configure(meta);
            let input = meta.advice_column();
            let instance = meta.instance_column();
            meta.enable_equality(input);
            meta.enable_equality(instance);
            (config, input, instance)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let inputs: [AssignedValue; L] = layouter.assign_region(
                || "source inputs",
                |mut region| {
                    Ok(std::array::from_fn(|row| {
                        AssignedValue::assign(
                            &mut region,
                            config.1,
                            row,
                            Value::known(self.inputs[row]),
                        )
                    }))
                },
            )?;
            let mut chip = PoseidonChip::construct(config.0);
            chip.trace_override = self.trace.clone();
            let mut offset = L;
            let digest = chip.hash(layouter.namespace(|| "hash"), &mut offset, inputs)?;
            layouter.constrain_instance(digest.cell, config.2, 0);
            Ok(())
        }
    }

    fn check<const W: usize, const L: usize>(
        circuit: &HashCircuit<W, L>,
    ) -> Result<(), Vec<VerifyFailure>> {
        MockProver::run(8, circuit, vec![vec![circuit.digest]])
            .unwrap()
            .verify()
    }

    fn forged<const W: usize, const L: usize>(row: usize, word: usize) -> HashCircuit<W, L> {
        let inputs = std::array::from_fn(|i| Fr::from(i as u64 + 1));
        let spec = parameters(L);
        let mut state = vec![Fr::ZERO];
        state.extend(inputs);
        let mut trace = Vec::new();
        for offset in 0..=spec.round_constants.len() {
            if offset == row {
                state[word] += Fr::ONE;
            }
            trace.push(state.clone());
            if let Some(constants) = spec.round_constants.get(offset) {
                let full = !(spec.full_rounds / 2..spec.full_rounds / 2 + spec.partial_rounds)
                    .contains(&offset);
                for index in 0..W {
                    state[index] += constants[index];
                    if full || index == 0 {
                        state[index] = state[index].square().square() * state[index];
                    }
                }
                state = spec
                    .mds
                    .iter()
                    .map(|row| row.iter().zip(&state).map(|(m, v)| *m * v).sum())
                    .collect();
            }
        }
        HashCircuit {
            inputs,
            digest: trace.last().unwrap()[0],
            trace: Some(trace),
        }
    }

    fn adversarial_checks<const W: usize, const L: usize>() {
        let failures = check(&forged::<W, L>(0, 0)).unwrap_err();
        assert_eq!(failures.len(), 1, "false capacity: {failures:?}");
        assert!(matches!(
            failures[0],
            VerifyFailure::ConstraintNotSatisfied { .. }
        ));
        for word in 1..W {
            let failures = check(&forged::<W, L>(0, word)).unwrap_err();
            assert!(
                failures
                    .iter()
                    .all(|failure| matches!(failure, VerifyFailure::Permutation { .. })),
                "input copy: {failures:?}"
            );
        }
        for row in [2, 5, parameters(L).round_constants.len()] {
            for word in 0..W {
                let failures = check(&forged::<W, L>(row, word)).unwrap_err();
                assert_eq!(failures.len(), 1, "row {row}, word {word}: {failures:?}");
                assert!(matches!(
                    failures[0],
                    VerifyFailure::ConstraintNotSatisfied { .. }
                ));
            }
        }
    }

    #[test]
    fn width_two_rejects_false_capacity_copies_and_full_partial_transitions() {
        adversarial_checks::<2, 1>();
    }

    #[test]
    fn width_three_rejects_false_capacity_copies_and_full_partial_transitions() {
        adversarial_checks::<3, 2>();
    }

    #[test]
    fn both_widths_match_frozen_circom_vectors() {
        use halo2_proofs::halo2curves::ff::PrimeField;
        let one = HashCircuit::<2, 1> {
            inputs: [Fr::ONE],
            digest: Fr::from_str_vartime(
                "18586133768512220936620570745912940619677854269274689475585506675881198879027",
            )
            .unwrap(),
            trace: None,
        };
        check(&one).unwrap();
        let two = HashCircuit::<3, 2> {
            inputs: [Fr::ONE, Fr::from(2)],
            digest: Fr::from_str_vartime(
                "7853200120776062878684798364095072458815029376092732009249414926327459813530",
            )
            .unwrap(),
            trace: None,
        };
        check(&two).unwrap();
    }
}
