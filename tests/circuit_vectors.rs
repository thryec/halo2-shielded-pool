use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::ff::Field};
use halo2_shielded_pool::{
    Fr,
    circuits::withdraw::{K, WithdrawCircuit},
    primitives::{
        context::withdrawal_binding,
        merkle::{MerkleTree, TREE_DEPTH},
        note::Note,
        poseidon::poseidon_hash,
    },
};
use snark_verifier_sdk::CircuitExt;

fn fixture() -> WithdrawCircuit {
    let note = Note::new(Fr::from(3), Fr::from(4));
    let mut tree = MerkleTree::new();
    for value in 1..=7 {
        tree.insert(Fr::from(value)).unwrap();
    }
    let index = tree.insert(note.commitment()).unwrap();
    WithdrawCircuit::new(
        note,
        &tree.prove(index).unwrap(),
        Fr::from(42),
        Fr::from(99),
    )
}

fn assert_rejected(circuit: &WithdrawCircuit) {
    assert!(
        MockProver::run(K, circuit, circuit.instances())
            .unwrap()
            .verify()
            .is_err()
    );
}

#[test]
fn honest_withdrawal_passes() {
    let circuit = fixture();
    MockProver::run(K, &circuit, circuit.instances())
        .unwrap()
        .assert_satisfied();
}

#[test]
fn note_path_and_binding_match_frozen_reference_vectors() {
    use halo2_proofs::halo2curves::ff::PrimeField;
    let f = |decimal| Fr::from_str_vartime(decimal).unwrap();
    let note = Note::new(Fr::from(7), Fr::from(42));
    let mut tree = MerkleTree::new();
    for (nullifier, secret) in [(3, 4), (7, 42), (9, 10)] {
        tree.insert(Note::new(Fr::from(nullifier), Fr::from(secret)).commitment())
            .unwrap();
    }
    let recipient = Fr::from(0x2222);
    let domain = f("7435514727583055506883087577328231697046918116103978064544660803043359354150");
    let mut circuit = WithdrawCircuit::new(note, &tree.prove(1).unwrap(), recipient, domain);
    circuit.public_inputs = [
        f("6728680792506271963433879736350438974885545747502843013872348209184901611108"),
        f("7061949393491957813657776856458368574501817871421526214197139795307327923534"),
        recipient,
        domain,
        f("3823014039291392129407375480527439191252523218263895949729914267965686033809"),
    ];
    MockProver::run(K, &circuit, circuit.instances())
        .unwrap()
        .assert_satisfied();
}

#[test]
fn withdrawal_does_not_fit_one_smaller_domain() {
    let circuit = fixture();
    // Axiom panics for advice rows beyond capacity, while other assignments return Err.
    let attempt =
        std::panic::catch_unwind(|| MockProver::run(K - 1, &circuit, circuit.instances()));
    assert!(!matches!(attempt, Ok(Ok(_))));
}

#[test]
fn every_public_field_is_bound() {
    let original = fixture();
    for row in 0..5 {
        let mut changed = original.clone();
        changed.public_inputs[row] += Fr::ONE;
        assert_rejected(&changed);
    }
}

#[test]
fn wrong_secret_and_nullifier_fail() {
    let original = fixture();
    let mut changed = original.clone();
    changed.secret = Value::known(Fr::from(5));
    assert_rejected(&changed);
    let mut changed = original;
    changed.nullifier = Value::known(Fr::from(5));
    assert_rejected(&changed);
}

#[test]
fn wrong_sibling_and_direction_fail_at_every_level() {
    let original = fixture();
    for level in 0..TREE_DEPTH {
        let mut changed = original.clone();
        changed.siblings[level] = changed.siblings[level] + Value::known(Fr::ONE);
        assert_rejected(&changed);
        let mut changed = original.clone();
        changed.path_bits[level] = Value::known(Fr::ONE) - changed.path_bits[level];
        assert_rejected(&changed);
    }
}

#[test]
fn nonboolean_direction_fails_even_with_consistent_interpolated_root() {
    let original = fixture();
    for fault_level in 0..TREE_DEPTH {
        let mut changed = original.clone();
        changed.path_bits[fault_level] = Value::known(Fr::from(2));
        let mut root = Value::known(poseidon_hash([Fr::from(3), Fr::from(4)]));
        for level in 0..TREE_DEPTH {
            root = root
                .zip(changed.siblings[level])
                .zip(changed.path_bits[level])
                .map(|((current, sibling), bit)| {
                    poseidon_hash([
                        current + bit * (sibling - current),
                        sibling + bit * (current - sibling),
                    ])
                });
        }
        root.map(|root| changed.public_inputs[0] = root);
        assert_rejected(&changed);
    }
}

#[test]
fn recipient_range_accepts_maximum_and_rejects_bit_160_with_matching_binding() {
    let mut circuit = fixture();
    let limit = Fr::from(2).pow_vartime([160]);
    for (recipient, passes) in [(Fr::ZERO, true), (limit - Fr::ONE, true), (limit, false)] {
        circuit.recipient = Value::known(recipient);
        circuit.public_inputs[2] = recipient;
        circuit.public_inputs[4] = withdrawal_binding(Fr::from(3), recipient, Fr::from(99));
        let prover = MockProver::run(K, &circuit, circuit.instances()).unwrap();
        if passes {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }
}

#[test]
fn new_domain_with_new_binding_is_a_valid_statement() {
    let mut circuit = fixture();
    let domain = Fr::from(100);
    circuit.domain = Value::known(domain);
    circuit.public_inputs[3] = domain;
    circuit.public_inputs[4] = withdrawal_binding(Fr::from(3), Fr::from(42), domain);
    // The future pool contract must compare this domain with its own context.
    MockProver::run(K, &circuit, circuit.instances())
        .unwrap()
        .assert_satisfied();
}

#[test]
fn changed_recipient_or_domain_with_old_binding_fails() {
    for row in [2, 3] {
        let mut circuit = fixture();
        circuit.public_inputs[row] += Fr::ONE;
        if row == 2 {
            circuit.recipient = Value::known(circuit.public_inputs[row]);
        } else {
            circuit.domain = Value::known(circuit.public_inputs[row]);
        }
        assert_rejected(&circuit);
    }
}
