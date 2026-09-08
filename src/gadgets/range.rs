//! A 160-bit unsigned recipient, with no field wrap: 2^160 is below Fr's modulus.
use crate::{Fr, gadgets::AssignedValue};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::ff::{Field, PrimeField},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct RangeConfig {
    accumulator: Column<Advice>,
    bit: Column<Advice>,
    initial: Selector,
    step: Selector,
}

impl RangeConfig {
    pub(crate) fn selectors(&self) -> Vec<Selector> {
        vec![self.initial, self.step]
    }
}

pub struct RangeChip {
    config: RangeConfig,
    #[cfg(test)]
    fault: Option<Fault>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum Fault {
    Initial,
    Bit(usize, Fr),
    Step(usize),
}

impl RangeChip {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> RangeConfig {
        let accumulator = meta.advice_column();
        let bit = meta.advice_column();
        let initial = meta.selector();
        let step = meta.selector();
        meta.enable_equality(accumulator);
        meta.create_gate("zero range accumulator", |meta| {
            vec![meta.query_selector(initial) * meta.query_advice(accumulator, Rotation::cur())]
        });
        meta.create_gate("recipient bits", |meta| {
            let q = meta.query_selector(step);
            let bit = meta.query_advice(bit, Rotation::cur());
            let current = meta.query_advice(accumulator, Rotation::cur());
            let next = meta.query_advice(accumulator, Rotation::next());
            vec![
                q.clone() * bit.clone() * (bit.clone() - Expression::Constant(Fr::ONE)),
                q * (next - current * Expression::Constant(Fr::from(2)) - bit),
            ]
        });
        RangeConfig {
            accumulator,
            bit,
            initial,
            step,
        }
    }

    pub fn construct(config: RangeConfig) -> Self {
        Self {
            config,
            #[cfg(test)]
            fault: None,
        }
    }

    pub fn check(
        &self,
        mut layouter: impl Layouter<Fr>,
        offset: &mut usize,
        recipient: AssignedValue,
    ) -> Result<(), Error> {
        let config = &self.config;
        let start = *offset;
        *offset += 161;
        layouter.assign_region(
            || "recipient 160 bits",
            |mut region| {
                config.initial.enable(&mut region, start)?;
                let mut accumulator = Value::known(Fr::ZERO);
                #[cfg(test)]
                if matches!(self.fault, Some(Fault::Initial)) {
                    accumulator = Value::known(Fr::ONE);
                }
                AssignedValue::assign(&mut region, config.accumulator, start, accumulator);
                for row in 0..160 {
                    config.step.enable(&mut region, start + row)?;
                    let bit = recipient.value.map(|value| {
                        let bytes = value.to_repr();
                        let index = 159 - row;
                        Fr::from(u64::from((bytes.as_ref()[index / 8] >> (index % 8)) & 1))
                    });
                    #[cfg(test)]
                    let bit = match self.fault {
                        Some(Fault::Bit(index, value)) if index == row => Value::known(value),
                        Some(Fault::Bit(..) | Fault::Step(..)) => Value::known(Fr::ZERO),
                        _ => bit,
                    };
                    AssignedValue::assign(&mut region, config.bit, start + row, bit);
                    accumulator = accumulator * Value::known(Fr::from(2)) + bit;
                    #[cfg(test)]
                    if matches!(self.fault, Some(Fault::Step(index)) if index == row) {
                        accumulator = accumulator + Value::known(Fr::from(2));
                    }
                    let cell = AssignedValue::assign(
                        &mut region,
                        config.accumulator,
                        start + row + 1,
                        accumulator,
                    );
                    if row == 159 {
                        region.constrain_equal(cell.cell, recipient.cell);
                    }
                }
                Ok(())
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
    struct RangeCircuit {
        recipient: Fr,
        fault: Option<Fault>,
    }

    impl Circuit<Fr> for RangeCircuit {
        type Config = (RangeConfig, Column<Instance>);
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self {
            self.clone()
        }
        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let config = RangeChip::configure(meta);
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            (config, instance)
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let recipient = layouter.assign_region(
                || "recipient",
                |mut region| {
                    Ok(AssignedValue::assign(
                        &mut region,
                        config.0.accumulator,
                        0,
                        Value::known(self.recipient),
                    ))
                },
            )?;
            layouter.constrain_instance(recipient.cell, config.1, 0);
            let mut chip = RangeChip::construct(config.0);
            chip.fault = self.fault;
            let mut offset = 1;
            chip.check(layouter.namespace(|| "range"), &mut offset, recipient)
        }
    }

    #[test]
    fn nonboolean_bit_with_matching_accumulator_fails() {
        let circuit = RangeCircuit {
            recipient: Fr::from(2),
            fault: Some(Fault::Bit(159, Fr::from(2))),
        };
        let failures = MockProver::run(8, &circuit, vec![vec![circuit.recipient]])
            .unwrap()
            .verify()
            .unwrap_err();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(matches!(
            failures[0],
            VerifyFailure::ConstraintNotSatisfied { .. }
        ));
    }

    #[test]
    fn nonzero_initial_accumulator_with_matching_recipient_fails() {
        let circuit = RangeCircuit {
            recipient: Fr::from(2).pow_vartime([160]),
            fault: Some(Fault::Initial),
        };
        let failures = MockProver::run(8, &circuit, vec![vec![circuit.recipient]])
            .unwrap()
            .verify()
            .unwrap_err();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(matches!(
            failures[0],
            VerifyFailure::ConstraintNotSatisfied { .. }
        ));
    }

    #[test]
    fn forged_accumulator_step_with_matching_recipient_fails() {
        let circuit = RangeCircuit {
            recipient: Fr::from(2),
            fault: Some(Fault::Step(159)),
        };
        let failures = MockProver::run(8, &circuit, vec![vec![circuit.recipient]])
            .unwrap()
            .verify()
            .unwrap_err();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(matches!(
            failures[0],
            VerifyFailure::ConstraintNotSatisfied { .. }
        ));
    }
}
