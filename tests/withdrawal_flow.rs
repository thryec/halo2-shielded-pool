use halo2_proofs::dev::MockProver;
use halo2_shielded_pool::{
    Fr,
    circuits::withdraw::{K, WithdrawCircuit},
    pool::{Pool, PoolError},
    primitives::note::Note,
};
use snark_verifier_sdk::CircuitExt;

#[test]
fn valid_withdrawal_flow_updates_pool_and_rejects_replay() {
    let mut pool = Pool::new();
    let decoy_note = Note::new(Fr::from(1), Fr::from(2));
    let note = Note::new(Fr::from(3), Fr::from(4));

    pool.deposit(decoy_note.commitment()).unwrap();
    let note_index = pool.deposit(note.commitment()).unwrap();
    let root = pool.root();
    let path = pool.merkle_path(note_index).unwrap();

    let circuit = WithdrawCircuit::new(note, &path, Fr::from(42), Fr::from(99));
    assert_eq!(circuit.public_inputs[0], root);
    let nullifier_hash = note.nullifier_hash();
    let prover = MockProver::run(K, &circuit, circuit.instances()).unwrap();

    prover.assert_satisfied();
    assert_eq!(pool.record_withdrawal(root, nullifier_hash), Ok(()));
    assert!(pool.is_spent_nullifier(nullifier_hash));
    assert_eq!(
        pool.record_withdrawal(root, nullifier_hash),
        Err(PoolError::NullifierAlreadySpent)
    );
}
