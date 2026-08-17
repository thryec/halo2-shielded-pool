use halo2_proofs::{circuit::Value, dev::MockProver};
use halo2_shielded_pool::{
    Fp,
    circuits::withdraw::WithdrawCircuit,
    pool::{Pool, PoolError},
    primitives::note::Note,
};

const K: u32 = 10;

#[test]
fn valid_withdrawal_flow_updates_pool_and_rejects_replay() {
    let mut pool = Pool::new();
    let decoy_note = Note::new(Fp::from(1), Fp::from(2));
    let note = Note::new(Fp::from(3), Fp::from(4));

    pool.deposit(decoy_note.commitment()).unwrap();
    let note_index = pool.deposit(note.commitment()).unwrap();
    let root = pool.root();
    let path = pool.merkle_path(note_index).unwrap();

    let circuit = WithdrawCircuit {
        nullifier: Value::known(note.nullifier()),
        secret: Value::known(note.secret()),
        siblings: (*path.siblings()).map(Value::known),
        path_bits: std::array::from_fn(|level| {
            Value::known(Fp::from(path.path_bits()[level] as u64))
        }),
    };
    let nullifier_hash = note.nullifier_hash();
    let prover = MockProver::run(K, &circuit, vec![vec![root, nullifier_hash]]).unwrap();

    prover.assert_satisfied();
    assert_eq!(pool.record_withdrawal(root, nullifier_hash), Ok(()));
    assert!(pool.is_spent_nullifier(nullifier_hash));
    assert_eq!(
        pool.record_withdrawal(root, nullifier_hash),
        Err(PoolError::NullifierAlreadySpent)
    );
}
