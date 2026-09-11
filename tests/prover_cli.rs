use halo2_shielded_pool::{
    Fr,
    circuits::withdraw::WithdrawCircuit,
    primitives::{
        context::{ProtocolDomain, address_field},
        merkle::MerkleTree,
        note::Note,
    },
    proof::{TestKeys, decode_calldata, field_bytes},
};
use serde_json::{Value, json};
use snark_verifier_sdk::CircuitExt;
use std::{fs, process::Command, time::SystemTime};

fn hex_field(value: Fr) -> String {
    format!("0x{}", hex::encode(field_bytes(value)))
}

#[test]
fn prove_command_rebuilds_path_and_writes_verifiable_calldata() {
    let note = Note::new(Fr::from(7), Fr::from(42));
    let recipient = [0x22; 20];
    let pool = [0x11; 20];
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp = std::env::temp_dir().join(format!("halo2-pool-prover-{nonce}"));
    let input_path = temp.with_extension("input.json");
    let output_path = temp.with_extension("output.json");
    let input = json!({
        "commitments": [hex_field(note.commitment())],
        "leaf_index": 0,
        "nullifier": hex_field(note.nullifier()),
        "secret": hex_field(note.secret()),
        "recipient": format!("0x{}", hex::encode(recipient)),
        "chain_id": "31337",
        "pool": format!("0x{}", hex::encode(pool)),
    });

    fs::write(&input_path, serde_json::to_vec_pretty(&input).unwrap()).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_halo2-shielded-pool"))
        .args([
            "prove",
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();

    assert!(status.success(), "prove command failed");

    let output: Value = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    let calldata = hex::decode(
        output["calldata"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let proof_bytes = output["proof_bytes"].as_u64().unwrap() as usize;
    let (instances, proof) = decode_calldata(&calldata, proof_bytes).unwrap();

    let mut tree = MerkleTree::new();
    let index = tree.insert(note.commitment()).unwrap();
    let mut chain_id = [0; 32];
    chain_id[24..].copy_from_slice(&31337_u64.to_be_bytes());
    let domain = ProtocolDomain {
        chain_id,
        pool,
        asset: [0; 20],
        version: 1,
    };
    let circuit = WithdrawCircuit::new(
        note,
        &tree.prove(index).unwrap(),
        address_field(recipient),
        domain.digest(),
    );

    assert_eq!(instances, circuit.instances());
    assert!(TestKeys::setup(&circuit).unwrap().verify(proof, &instances));

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(output_path);
}
