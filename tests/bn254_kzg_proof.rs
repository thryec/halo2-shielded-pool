use halo2_proofs::circuit::Value;
use halo2_shielded_pool::{
    Fr,
    circuits::withdraw::WithdrawCircuit,
    primitives::{
        context::{ProtocolDomain, address_field},
        merkle::MerkleTree,
        note::Note,
    },
    proof::{TestKeys, decode_calldata, encode_calldata},
    solidity::{poseidon_source, verification_key_source},
};
use snark_verifier_sdk::CircuitExt;
use std::{fs, path::Path};

fn circuit(seed: u64) -> WithdrawCircuit {
    let note = Note::new(Fr::from(seed), Fr::from(42));
    let mut tree = MerkleTree::new();

    tree.insert(Note::new(Fr::from(1), Fr::from(2)).commitment())
        .unwrap();

    let index = tree.insert(note.commitment()).unwrap();

    let mut chain_id = [0; 32];
    chain_id[24..].copy_from_slice(&31337_u64.to_be_bytes());

    let domain = ProtocolDomain {
        chain_id,
        pool: [0x11; 20],
        asset: [0; 20],
        version: seed,
    };

    WithdrawCircuit::new(
        note,
        &tree.prove(index).unwrap(),
        address_field([0x22; 20]),
        domain.digest(),
    )
}

#[test]
fn reusable_keys_prove_two_withdrawals_and_reject_changed_statements() {
    let first = circuit(7);
    let keys = TestKeys::setup(&first).unwrap();

    for circuit in [first, circuit(8)] {
        let instances = circuit.instances();
        let proof = keys.prove(circuit).unwrap();

        assert!(keys.verify(&proof, &instances));

        for row in 0..5 {
            let mut changed = instances.clone();
            changed[0][row] += Fr::from(1);
            assert!(!keys.verify(&proof, &changed), "changed row {row} accepted");
        }

        let mut corrupt = proof.clone();
        corrupt[0] ^= 1;

        assert!(!keys.verify(&corrupt, &instances));
        assert!(!keys.verify(&proof[..proof.len() - 1], &instances));
        assert!(!keys.verify(&[], &instances));

        let mut appended = proof.clone();
        appended.push(0);

        assert!(!keys.verify(&appended, &instances));
        assert!(!keys.verify(&proof, &[]));
        assert!(!keys.verify(&proof, &[vec![]]));
        assert!(!keys.verify(&proof, &[vec![Fr::from(0); 6]]));

        let calldata = encode_calldata(&instances, &proof).unwrap();

        assert_eq!(calldata.len(), 160 + proof.len());

        let (decoded, decoded_proof) = decode_calldata(&calldata, proof.len()).unwrap();

        assert_eq!(decoded, instances);
        assert_eq!(decoded_proof, proof);
        assert!(keys.verify(decoded_proof, &decoded));
        assert!(decode_calldata(&calldata[..159], proof.len()).is_err());

        let mut bad_word = calldata.clone();
        bad_word[..32].fill(0xff);

        assert!(decode_calldata(&bad_word, proof.len()).is_err());
    }
}

#[test]
fn prover_returns_error_for_invalid_witness() {
    let valid = circuit(7);
    let keys = TestKeys::setup(&valid).unwrap();

    let mut invalid = valid;
    invalid.secret = Value::known(Fr::from(999));

    assert!(keys.prove(invalid).is_err());
}

#[test]
fn test_setup_reproduces_same_verifier() {
    let witness = circuit(7);
    let first = TestKeys::setup(&witness).unwrap();
    let second = TestKeys::setup(&witness).unwrap();

    assert_eq!(
        first.solidity_verifier(3_360),
        second.solidity_verifier(3_360)
    );
}

#[test]
fn generated_verifier_has_clean_whitespace() {
    let verifier = TestKeys::setup(&circuit(7))
        .unwrap()
        .solidity_verifier(3_360);

    assert!(verifier.lines().all(|line| line == line.trim_end()));
    assert!(!verifier.ends_with("\n\n"));
}

#[test]
fn verification_key_id_matches_strict_verifier_source() {
    let keys = TestKeys::setup(&circuit(7)).unwrap();
    let expected: [u8; 32] =
        hex::decode("3f89c07a1dc30a5a4c5f49368390a2be67d6c3c8b55a99cacf2fae033dca905e")
            .unwrap()
            .try_into()
            .unwrap();

    assert_eq!(keys.verification_key_id(3_360), expected);
}

#[test]
fn pinned_solidity_matches_fixed_setup_and_hash_parameters() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("contracts/generated");
    let keys = TestKeys::setup(&circuit(7)).unwrap();
    let verification_key_id = keys.verification_key_id(3_360);

    assert_eq!(
        fs::read_to_string(root.join("Halo2Verifier.sol")).unwrap(),
        keys.solidity_verifier(3_360)
    );
    assert_eq!(
        fs::read_to_string(root.join("Poseidon1.sol")).unwrap(),
        poseidon_source(1)
    );
    assert_eq!(
        fs::read_to_string(root.join("Poseidon2.sol")).unwrap(),
        poseidon_source(2)
    );
    assert_eq!(
        fs::read_to_string(root.join("VerificationKey.sol")).unwrap(),
        verification_key_source(verification_key_id)
    );
}

#[test]
fn evm_encoding_is_big_endian_and_rejects_field_aliases() {
    use halo2_proofs::halo2curves::ff::PrimeField;

    let instances = vec![vec![
        Fr::from(1),
        Fr::from(2),
        Fr::from(3),
        Fr::from(4),
        Fr::from(5),
    ]];

    let encoded = encode_calldata(&instances, &[0xaa, 0xbb]).unwrap();

    for row in 0..5 {
        assert_eq!(&encoded[row * 32..row * 32 + 31], &[0; 31]);
        assert_eq!(encoded[row * 32 + 31], (row + 1) as u8);
    }

    assert_eq!(&encoded[160..], &[0xaa, 0xbb]);
    assert!(encode_calldata(&[], &[]).is_err());

    let mut alias = encoded;
    let modulus = hex::decode(Fr::MODULUS.trim_start_matches("0x")).unwrap();
    alias[..32].copy_from_slice(&modulus);

    assert!(decode_calldata(&alias, 2).is_err());
    assert!(decode_calldata(&alias, usize::MAX).is_err());
}

#[test]
#[ignore = "manual release benchmark for docs/build-log.md"]
fn benchmark_bn254_kzg_proof() {
    use std::time::Instant;

    println!("run,setup_and_keys_ms,prove_and_self_check_ms,verify_ms,proof_bytes");

    for run in 1..=3 {
        let witness = circuit(7);
        let instances = witness.instances();

        let start = Instant::now();
        let keys = TestKeys::setup(&witness).unwrap();
        let setup = start.elapsed();

        let start = Instant::now();
        let proof = keys.prove(witness).unwrap();
        let proving = start.elapsed();

        let start = Instant::now();
        assert!(keys.verify(&proof, &instances));
        let verifying = start.elapsed();

        println!(
            "{run},{:.3},{:.3},{:.3},{}",
            setup.as_secs_f64() * 1000.0,
            proving.as_secs_f64() * 1000.0,
            verifying.as_secs_f64() * 1000.0,
            proof.len(),
        );
    }
}
