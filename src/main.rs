//! Generates matching local test proof, verifier, and cross-language hash vectors.

use halo2_proofs::halo2curves::ff::Field;
use halo2_shielded_pool::{
    Fr,
    circuits::withdraw::{K, WithdrawCircuit},
    poseidon_hash,
    primitives::{
        context::{ProtocolDomain, address_field, withdrawal_binding},
        merkle::MerkleTree,
        note::Note,
    },
    proof::{TestKeys, encode_calldata, field_bytes},
    solidity::poseidon_source,
};
use serde_json::json;
use snark_verifier_sdk::CircuitExt;
use std::{fs, path::Path, time::Instant};

fn hex_field(value: Fr) -> String {
    format!("0x{}", hex::encode(field_bytes(value)))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let artifacts = root.join("artifacts");
    let generated = root.join("contracts/generated");
    let note = Note::new(Fr::from(7), Fr::from(42));
    let mut tree = MerkleTree::new();
    for (nullifier, secret) in [(3, 4), (7, 42), (9, 10)] {
        tree.insert(Note::new(Fr::from(nullifier), Fr::from(secret)).commitment())
            .unwrap();
    }
    let path = tree.prove(1).unwrap();
    let mut chain_id = [0; 32];
    chain_id[24..].copy_from_slice(&31337_u64.to_be_bytes());
    let domain = ProtocolDomain {
        chain_id,
        pool: [0x11; 20],
        asset: [0; 20],
        version: 1,
    };
    let max_domain = ProtocolDomain {
        chain_id: [0xff; 32],
        pool: [0xff; 20],
        asset: [0xff; 20],
        version: u64::MAX,
    };
    let recipient = address_field([0x22; 20]);
    let circuit = WithdrawCircuit::new(note, &path, recipient, domain.digest());
    let instances = circuit.instances();
    let start = Instant::now();
    let keys = TestKeys::setup(&circuit)?;
    let setup_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    let proof = keys.prove(circuit)?;
    let prove_and_self_check_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    assert!(keys.verify(&proof, &instances));
    let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
    let calldata = encode_calldata(&instances, &proof)?;
    let verifier = keys.solidity_verifier(proof.len());
    // Record scalar positions from the pinned verifier for byte-level parity tests.
    let proof_scalar_offsets: Vec<usize> = verifier
        .split("checked_scalar(0x")
        .skip(1)
        .map(|tail| {
            let offset = tail.split_once(')').expect("pinned scalar-load shape").0;
            usize::from_str_radix(offset, 16).expect("hex calldata offset")
        })
        .filter(|offset| *offset >= 160)
        .collect();
    assert!(
        !proof_scalar_offsets.is_empty(),
        "proof contains scalar evaluations"
    );
    let json = json!({
        "test_only_setup": true,
        "public_input_order": ["root", "nullifier_hash", "recipient", "domain", "binding"],
        "public_inputs": instances[0].iter().copied().map(hex_field).collect::<Vec<_>>(),
        "calldata": format!("0x{}", hex::encode(&calldata)),
        "proof_scalar_offsets": proof_scalar_offsets,
        "proof_bytes": proof.len(),
        "calldata_bytes": calldata.len(),
        "k": K,
        "setup_ms": setup_ms,
        "prove_and_self_check_ms": prove_and_self_check_ms,
        "rust_verify_ms": verify_ms,
        "vectors": {
            "h1_one": hex_field(poseidon_hash([Fr::ONE])),
            "h1_max": hex_field(poseidon_hash([-Fr::ONE])),
            "h2_max": hex_field(poseidon_hash([-Fr::ONE, Fr::from(42)])),
            "commitment": hex_field(note.commitment()),
            "nullifier_hash": hex_field(note.nullifier_hash()),
            "empty_root": hex_field(MerkleTree::new().root()),
            "root": hex_field(tree.root()),
            "siblings": path.siblings().iter().copied().map(hex_field).collect::<Vec<_>>(),
            "domain": hex_field(domain.digest()),
            "max_domain": hex_field(max_domain.digest()),
            "binding": hex_field(withdrawal_binding(note.nullifier(), recipient, domain.digest())),
        }
    });
    // Every run replaces only these generated test artifacts, as one matching set.
    fs::create_dir_all(&artifacts)?;
    fs::create_dir_all(&generated)?;
    fs::write(generated.join("Halo2Verifier.sol"), verifier)?;
    fs::write(generated.join("Poseidon1.sol"), poseidon_source(1))?;
    fs::write(generated.join("Poseidon2.sol"), poseidon_source(2))?;
    fs::write(
        artifacts.join("withdrawal.json"),
        serde_json::to_string_pretty(&json)?,
    )?;
    println!(
        "proof_bytes={} calldata_bytes={} k={K}",
        proof.len(),
        calldata.len()
    );
    println!(
        "setup_ms={setup_ms:.3} prove_and_self_check_ms={prove_and_self_check_ms:.3} rust_verify_ms={verify_ms:.3}"
    );
    println!("wrote matching test-only artifacts to {}", root.display());
    Ok(())
}
