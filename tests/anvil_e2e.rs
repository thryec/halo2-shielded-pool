use halo2_shielded_pool::{Fr, primitives::note::Note, proof::field_bytes};
use serde_json::{Value, json};
use std::{
    ffi::OsStr,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, SystemTime},
};

const PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEPLOYER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const RECIPIENT: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const OTHER_RECIPIENT: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
const WITHDRAW: &str = "withdraw(uint256,uint256,address,uint256,bytes)";

struct Anvil {
    child: Child,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn command_output<I, S>(program: &str, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(program)
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap_or_else(|error| panic!("cannot run {program}: {error}"))
}

fn run<I, S>(program: &str, args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = command_output(program, args);

    assert!(
        output.status.success(),
        "{program} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).unwrap()
}

fn run_json<I, S>(program: &str, args: I) -> Value
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    serde_json::from_str(&run(program, args)).unwrap()
}

fn deploy(contract: &str, constructor: &[&str], rpc_url: &str) -> String {
    let mut args = vec![
        "create".into(),
        contract.to_owned(),
        "--broadcast".into(),
        "--json".into(),
        "--rpc-url".into(),
        rpc_url.into(),
        "--private-key".into(),
        PRIVATE_KEY.into(),
    ];

    if !constructor.is_empty() {
        args.push("--constructor-args".into());
        args.extend(constructor.iter().map(|value| (*value).to_owned()));
    }

    run_json("forge", args)["deployedTo"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn send(
    target: &str,
    signature: &str,
    values: &[&str],
    rpc_url: &str,
    value: Option<&str>,
) -> Value {
    let mut args = vec![target.to_owned(), signature.to_owned()];
    args.extend(values.iter().map(|value| (*value).to_owned()));

    if let Some(value) = value {
        args.extend(["--value".into(), value.into()]);
    }

    args.extend([
        "--gas-limit".into(),
        "30000000".into(),
        "--json".into(),
        "--rpc-url".into(),
        rpc_url.into(),
        "--private-key".into(),
        PRIVATE_KEY.into(),
    ]);

    run_json("cast", std::iter::once("send".to_owned()).chain(args))
}

fn assert_call_reverts(target: &str, values: &[&str], rpc_url: &str, case: &str) {
    let mut args = vec!["call".to_owned(), target.to_owned(), WITHDRAW.to_owned()];
    args.extend(values.iter().map(|value| (*value).to_owned()));
    args.extend([
        "--rpc-url".into(),
        rpc_url.into(),
        "--from".into(),
        DEPLOYER.into(),
    ]);

    let output = command_output("cast", args);

    assert!(!output.status.success(), "{case} was accepted");
}

fn prove(input: &Value, input_path: &Path, output_path: &Path) -> Value {
    fs::write(input_path, serde_json::to_vec_pretty(input).unwrap()).unwrap();

    run(
        env!("CARGO_BIN_EXE_halo2-shielded-pool"),
        [
            "prove",
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
        ],
    );

    serde_json::from_slice(&fs::read(output_path).unwrap()).unwrap()
}

fn hex_field(value: Fr) -> String {
    format!("0x{}", hex::encode(field_bytes(value)))
}

fn mutate_hex(value: &str) -> String {
    let mut bytes = hex::decode(value.trim_start_matches("0x")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;

    format!("0x{}", hex::encode(bytes))
}

fn hex_u64(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn balance(address: &str, rpc_url: &str) -> u128 {
    run("cast", ["balance", address, "--rpc-url", rpc_url])
        .trim()
        .parse()
        .unwrap()
}

fn code_size(address: &str, rpc_url: &str) -> usize {
    let code = run("cast", ["code", address, "--rpc-url", rpc_url]);

    code.trim().trim_start_matches("0x").len() / 2
}

fn start_anvil(rpc_url: &str, port: u16) -> Anvil {
    let child = Command::new("anvil")
        .args([
            "--port",
            &port.to_string(),
            "--chain-id",
            "31337",
            "--hardfork",
            "paris",
            "--silent",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("cannot start anvil");
    let mut anvil = Anvil { child };

    for _ in 0..100 {
        if command_output("cast", ["block-number", "--rpc-url", rpc_url])
            .status
            .success()
        {
            return anvil;
        }

        if let Some(status) = anvil.child.try_wait().unwrap() {
            panic!("anvil exited before startup: {status}");
        }

        thread::sleep(Duration::from_millis(50));
    }

    panic!("anvil did not start");
}

fn temp_paths() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("halo2-pool-anvil-{nonce}"));

    (
        root.with_extension("input.json"),
        root.with_extension("proof.json"),
        root.with_extension("wrong-input.json"),
        root.with_extension("wrong-proof.json"),
    )
}

#[test]
#[ignore = "starts anvil and runs the full v0.5 release gate"]
fn deposit_prove_withdraw_and_hostile_cases_on_anvil() {
    let port = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let rpc_url = format!("http://127.0.0.1:{port}");
    let _anvil = start_anvil(&rpc_url, port);

    run("forge", ["build"]);

    let verifier = deploy(
        "contracts/generated/Halo2Verifier.sol:Halo2Verifier",
        &[],
        &rpc_url,
    );
    let poseidon = deploy("contracts/generated/Poseidon2.sol:Poseidon2", &[], &rpc_url);
    let pool = deploy(
        "contracts/WithdrawalPool.sol:WithdrawalPool",
        &[&verifier, &poseidon],
        &rpc_url,
    );

    let note = Note::new(Fr::from(7), Fr::from(42));
    let deposit = send(
        &pool,
        "deposit(uint256)",
        &[&hex_field(note.commitment())],
        &rpc_url,
        Some("1ether"),
    );
    let log = &deposit["logs"][0];
    let commitment = log["topics"][1].as_str().unwrap();
    let leaf_index = hex_u64(&log["topics"][2]);
    let root = log["data"].as_str().unwrap();
    let input = json!({
        "commitments": [commitment],
        "leaf_index": leaf_index,
        "nullifier": hex_field(note.nullifier()),
        "secret": hex_field(note.secret()),
        "recipient": RECIPIENT,
        "chain_id": "31337",
        "pool": pool.clone(),
    });
    let (input_path, output_path, wrong_input_path, wrong_output_path) = temp_paths();
    let proof_output = prove(&input, &input_path, &output_path);
    let public = proof_output["public_inputs"].as_array().unwrap();
    let proof = proof_output["proof"].as_str().unwrap();

    assert_eq!(public[0].as_str().unwrap(), root);

    let unknown_root = mutate_hex(root);
    assert_call_reverts(
        &pool,
        &[
            &unknown_root,
            public[1].as_str().unwrap(),
            RECIPIENT,
            public[4].as_str().unwrap(),
            proof,
        ],
        &rpc_url,
        "unknown root",
    );
    assert_call_reverts(
        &pool,
        &[
            root,
            public[1].as_str().unwrap(),
            OTHER_RECIPIENT,
            public[4].as_str().unwrap(),
            proof,
        ],
        &rpc_url,
        "changed recipient",
    );
    assert_call_reverts(
        &pool,
        &[root, public[1].as_str().unwrap(), RECIPIENT, "1", proof],
        &rpc_url,
        "wrong instance",
    );

    let corrupted_proof = mutate_hex(proof);
    assert_call_reverts(
        &pool,
        &[
            root,
            public[1].as_str().unwrap(),
            RECIPIENT,
            public[4].as_str().unwrap(),
            &corrupted_proof,
        ],
        &rpc_url,
        "corrupted proof",
    );

    let mut wrong_domain_input = input.clone();
    wrong_domain_input["domain_override"] = json!(hex_field(Fr::from(1)));
    let wrong_domain = prove(&wrong_domain_input, &wrong_input_path, &wrong_output_path);
    let wrong_public = wrong_domain["public_inputs"].as_array().unwrap();

    assert_call_reverts(
        &pool,
        &[
            root,
            wrong_public[1].as_str().unwrap(),
            RECIPIENT,
            wrong_public[4].as_str().unwrap(),
            wrong_domain["proof"].as_str().unwrap(),
        ],
        &rpc_url,
        "wrong domain",
    );

    let estimate_request = format!(
        "{{\"to\":\"{verifier}\",\"data\":\"{}\"}}",
        proof_output["calldata"].as_str().unwrap()
    );
    let verifier_gas: String = serde_json::from_str(&run(
        "cast",
        [
            "rpc",
            "--rpc-url",
            &rpc_url,
            "eth_estimateGas",
            &estimate_request,
        ],
    ))
    .unwrap();

    let before = balance(RECIPIENT, &rpc_url);
    let withdrawal = send(
        &pool,
        WITHDRAW,
        &[
            root,
            public[1].as_str().unwrap(),
            RECIPIENT,
            public[4].as_str().unwrap(),
            proof,
        ],
        &rpc_url,
        None,
    );
    let after = balance(RECIPIENT, &rpc_url);

    assert_eq!(after - before, 1_000_000_000_000_000_000);

    assert_call_reverts(
        &pool,
        &[
            root,
            public[1].as_str().unwrap(),
            RECIPIENT,
            public[4].as_str().unwrap(),
            proof,
        ],
        &rpc_url,
        "replayed nullifier",
    );

    println!("proof_bytes={}", proof_output["proof_bytes"]);
    println!(
        "prove_and_self_check_ms={}",
        proof_output["prove_and_self_check_ms"]
    );
    println!("verifier_transaction_gas={}", hex_u64(&json!(verifier_gas)));
    println!("withdrawal_gas={}", hex_u64(&withdrawal["gasUsed"]));
    println!("verifier_runtime_bytes={}", code_size(&verifier, &rpc_url));
    println!("pool_runtime_bytes={}", code_size(&pool, &rpc_url));

    for path in [input_path, output_path, wrong_input_path, wrong_output_path] {
        let _ = fs::remove_file(path);
    }
}
