use bn254_kzg_evm_spike::{native, proof};
use halo2_proofs::halo2curves::bn256::Fr;
use serde_json::json;
use snark_verifier_sdk::evm::encode_calldata;
use std::{fs, path::Path, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let artifacts = root.join("artifacts");
    let generated = root.join("contracts/generated");
    fs::create_dir_all(&artifacts)?;
    fs::create_dir_all(&generated)?;

    let start = Instant::now();
    let fixture = proof::build()?;
    let setup_and_prove_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    assert!(proof::verify(&fixture, &fixture.proof, &fixture.instances));
    let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut wrong = fixture.instances.clone();
    wrong[0][0] += Fr::from(1);
    assert!(!proof::verify(&fixture, &fixture.proof, &wrong));
    let mut corrupted = fixture.proof.clone();
    corrupted[0] ^= 1;
    assert!(!proof::verify(&fixture, &corrupted, &fixture.instances));

    let json = json!({
        "calldata": format!("0x{}", hex::encode(encode_calldata(&fixture.instances, &fixture.proof))),
        "wrong_instance_calldata": format!("0x{}", hex::encode(encode_calldata(&wrong, &fixture.proof))),
        "corrupted_calldata": format!("0x{}", hex::encode(encode_calldata(&fixture.instances, &corrupted))),
        "proof_bytes": fixture.proof.len(),
        "calldata_bytes": encode_calldata(&fixture.instances, &fixture.proof).len(),
        "k": proof::K,
        "setup_and_prove_ms": setup_and_prove_ms,
        "rust_verify_ms": verify_ms,
        "test_only_setup": true,
    });
    fs::write(
        artifacts.join("proof.json"),
        serde_json::to_string_pretty(&json)?,
    )?;
    fs::write(
        generated.join("Halo2Verifier.sol"),
        proof::solidity_verifier(&fixture),
    )?;
    fs::write(generated.join("Poseidon2.sol"), native::solidity_source())?;
    println!(
        "proof_bytes={} calldata_bytes={} k={}",
        fixture.proof.len(),
        fixture.proof.len() + 32,
        proof::K
    );
    println!("setup_and_prove_ms={setup_and_prove_ms:.3} rust_verify_ms={verify_ms:.3}");
    println!(
        "generated matching verifier and calldata under {}",
        root.display()
    );
    Ok(())
}
