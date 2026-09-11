//! Generates matching local test proof, verifier, and cross-language hash vectors.

use halo2_proofs::halo2curves::ff::{Field, PrimeField};
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
    solidity::{poseidon_source, verification_key_source},
};
use serde_json::{Value, json};
use snark_verifier_sdk::CircuitExt;
use std::{env, fs, path::Path, time::Instant};

fn hex_field(value: Fr) -> String {
    format!("0x{}", hex::encode(field_bytes(value)))
}

fn parse_field(value: &str) -> Result<Fr, String> {
    let bytes = hex::decode(value.trim_start_matches("0x")).map_err(|error| error.to_string())?;

    if bytes.len() > 32 {
        return Err("field value exceeds 32 bytes".into());
    }

    let mut repr = <Fr as PrimeField>::Repr::default();
    repr.as_mut()[32 - bytes.len()..].copy_from_slice(&bytes);
    repr.as_mut().reverse();

    Option::<Fr>::from(Fr::from_repr(repr)).ok_or_else(|| "noncanonical field value".into())
}

fn parse_address(value: &str) -> Result<[u8; 20], String> {
    let bytes = hex::decode(value.trim_start_matches("0x")).map_err(|error| error.to_string())?;

    bytes
        .try_into()
        .map_err(|_| "address must contain 20 bytes".into())
}

fn parse_chain_id(value: &str) -> Result<[u8; 32], String> {
    let mut chain_id = [0; 32];

    if let Some(hex) = value.strip_prefix("0x") {
        let bytes = hex::decode(hex).map_err(|error| error.to_string())?;

        if bytes.len() > 32 {
            return Err("chain id exceeds 32 bytes".into());
        }

        chain_id[32 - bytes.len()..].copy_from_slice(&bytes);
    } else {
        let chain = value.parse::<u64>().map_err(|error| error.to_string())?;
        chain_id[24..].copy_from_slice(&chain.to_be_bytes());
    }

    Ok(chain_id)
}

fn input_string<'a>(input: &'a Value, key: &str) -> Result<&'a str, String> {
    input[key]
        .as_str()
        .ok_or_else(|| format!("{key} must be a string"))
}

fn prove_from_file(
    input_path: &Path,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let input: Value = serde_json::from_slice(&fs::read(input_path)?)?;
    let commitment_values = input["commitments"]
        .as_array()
        .ok_or("commitments must be an array")?;
    let leaf_index = input["leaf_index"]
        .as_u64()
        .ok_or("leaf_index must be an integer")? as usize;
    let note = Note::new(
        parse_field(input_string(&input, "nullifier")?)?,
        parse_field(input_string(&input, "secret")?)?,
    );
    let recipient_address = parse_address(input_string(&input, "recipient")?)?;
    let recipient = address_field(recipient_address);
    let domain = ProtocolDomain {
        chain_id: parse_chain_id(input_string(&input, "chain_id")?)?,
        pool: parse_address(input_string(&input, "pool")?)?,
        asset: [0; 20],
        version: 1,
    };
    let domain = match input.get("domain_override") {
        Some(value) => parse_field(value.as_str().ok_or("domain_override must be a string")?)?,
        None => domain.digest(),
    };

    let commitments = commitment_values
        .iter()
        .map(|commitment| {
            parse_field(
                commitment
                    .as_str()
                    .ok_or("each commitment must be a string")?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    if commitments.get(leaf_index) != Some(&note.commitment()) {
        return Err("note commitment does not match leaf index".into());
    }

    let mut tree = MerkleTree::new();

    for commitment in commitments {
        tree.insert(commitment)
            .map_err(|error| format!("cannot insert commitment: {error:?}"))?;
    }

    let path = tree
        .prove(leaf_index)
        .map_err(|error| format!("cannot build Merkle path: {error:?}"))?;
    let circuit = WithdrawCircuit::new(note, &path, recipient, domain);
    let instances = circuit.instances();

    let setup_start = Instant::now();
    let keys = TestKeys::setup(&circuit)?;
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    let prove_start = Instant::now();
    let proof = keys.prove(circuit)?;
    let prove_and_self_check_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
    let calldata = encode_calldata(&instances, &proof)?;
    let output = json!({
        "test_only_setup": true,
        "public_inputs": instances[0].iter().copied().map(hex_field).collect::<Vec<_>>(),
        "proof": format!("0x{}", hex::encode(&proof)),
        "calldata": format!("0x{}", hex::encode(&calldata)),
        "proof_bytes": proof.len(),
        "calldata_bytes": calldata.len(),
        "setup_ms": setup_ms,
        "prove_and_self_check_ms": prove_and_self_check_ms,
    });

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(output_path, serde_json::to_vec_pretty(&output)?)?;

    Ok(())
}

fn generate_artifacts() -> Result<(), Box<dyn std::error::Error>> {
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
    let verification_key_id = keys.verification_key_id(proof.len());
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
        "verification_key_id": format!("0x{}", hex::encode(verification_key_id)),
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
        generated.join("VerificationKey.sol"),
        verification_key_source(verification_key_id),
    )?;
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        None | Some("generate") => {
            if args.next().is_some() {
                return Err("generate takes no arguments".into());
            }

            generate_artifacts()
        }
        Some("prove") => {
            let input = args.next().ok_or("prove requires an input path")?;
            let output = args.next().ok_or("prove requires an output path")?;

            if args.next().is_some() {
                return Err("prove takes exactly two paths".into());
            }

            prove_from_file(Path::new(&input), Path::new(&output))
        }
        Some(command) => Err(format!("unknown command: {command}").into()),
    }
}
