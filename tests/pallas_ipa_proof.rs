use halo2_proofs::{
    circuit::Value,
    halo2curves::pasta::EqAffine, // ipa curve point type whose scalar field matches our circuit's Fp
    plonk::{
        Circuit,
        Error,
        VerifyingKey, // stores the circuit data needed to verify proofs
        create_proof, // creates proof bytes from the proving key, witness, and public inputs
        keygen_pk,    // builds the proving key and stores the verification key inside it
        keygen_vk,    // builds the verification key from the circuit's rules and layout
        verify_proof, // checks proof bytes against the verification key and public inputs
    },
    poly::{
        VerificationStrategy,     // trait that provides SingleStrategy::new()
        commitment::ParamsProver, // trait that provides ParamsIPA::new(K)
        ipa::{
            commitment::{
                IPACommitmentScheme, // selects the inner-product argument (ipa) commitment backend
                ParamsIPA,           // shared ipa parameters for the chosen curve and circuit size
            },
            multiopen::{
                ProverIPA,   // proves claimed polynomial evaluations in the ipa backend
                VerifierIPA, // checks those polynomial evaluation claims
            },
            strategy::SingleStrategy, // performs the final checks for one proof
        },
    },
    transcript::{
        Blake2bRead,  // reads proof bytes and hashes the transcript to derive verifier challenges
        Blake2bWrite, // writes proof bytes and derives matching prover challenges
        Challenge255, // encodes transcript challenges as field elements for the chosen curve
        TranscriptReadBuffer, // trait that provides Blake2bRead::init()
        TranscriptWriterBuffer, // trait that provides Blake2bWrite::init() and finalize()
    },
};
use halo2_shielded_pool::{
    Fp, circuits::withdraw::WithdrawCircuit, pool::Pool, primitives::note::Note,
};
use rand_core::OsRng; // supplies fresh operating-system randomness for proof blinding

const K: u32 = 10;

fn build_fixture() -> (WithdrawCircuit, Fp, Fp) {
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

    (circuit, root, note.nullifier_hash())
}

struct ProofFixture {
    params: ParamsIPA<EqAffine>,
    vk: VerifyingKey<EqAffine>,
    proof: Vec<u8>,
    public_inputs: [Fp; 2],
}

fn build_proof() -> Result<ProofFixture, Error> {
    // 1. Build the same note, tree, path, circuit and public inputs as v0.1.0.
    let (circuit, root, nullifier_hash) = build_fixture();

    // 2. Generate parameters and keys from the empty circuit.
    let params = ParamsIPA::<EqAffine>::new(K);
    let empty_circuit = circuit.without_witnesses();
    let vk = keygen_vk(&params, &empty_circuit)?;
    let pk = keygen_pk(&params, vk, &empty_circuit)?;

    // Shape: [proof][instance column][row]
    let public_inputs = [root, nullifier_hash];
    let instance_columns = [&public_inputs[..]];
    let instances = [&instance_columns[..]];

    // 3. Generate real proof bytes.
    let mut writer = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(vec![]);

    create_proof::<IPACommitmentScheme<EqAffine>, ProverIPA<EqAffine>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &instances,
        OsRng,
        &mut writer,
    )?;

    let proof = writer.finalize();

    Ok(ProofFixture {
        params,
        vk: pk.get_vk().clone(),
        proof,
        public_inputs,
    })
}

fn verify(fixture: &ProofFixture, proof: &[u8], public_inputs: &[Fp; 2]) -> Result<(), Error> {
    let instance_columns = [&public_inputs[..]];
    let instances = [&instance_columns[..]];
    let strategy = SingleStrategy::new(&fixture.params);
    let mut reader = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(proof);

    verify_proof::<IPACommitmentScheme<EqAffine>, VerifierIPA<EqAffine>, _, _, _>(
        &fixture.params,
        &fixture.vk,
        strategy,
        &instances,
        &mut reader,
    )
}

#[test]
fn real_proof_round_trip() -> Result<(), Error> {
    let fixture = build_proof()?;
    verify(&fixture, &fixture.proof, &fixture.public_inputs)
}

#[test]
fn proof_rejects_corrupted_bytes() -> Result<(), Error> {
    let fixture = build_proof()?;
    verify(&fixture, &fixture.proof, &fixture.public_inputs)?;

    let mut corrupted_proof = fixture.proof.clone();
    corrupted_proof[0] ^= 1;

    assert!(
        verify(&fixture, &corrupted_proof, &fixture.public_inputs).is_err(),
        "verifier accepted corrupted proof bytes"
    );
    Ok(())
}

#[test]
fn proof_rejects_wrong_public_root() -> Result<(), Error> {
    let fixture = build_proof()?;
    verify(&fixture, &fixture.proof, &fixture.public_inputs)?;

    let mut wrong_inputs = fixture.public_inputs;
    wrong_inputs[0] += Fp::from(1);

    assert!(
        verify(&fixture, &fixture.proof, &wrong_inputs).is_err(),
        "verifier accepted a changed public root"
    );
    Ok(())
}

#[test]
fn proof_rejects_wrong_public_nullifier_hash() -> Result<(), Error> {
    let fixture = build_proof()?;
    verify(&fixture, &fixture.proof, &fixture.public_inputs)?;

    let mut wrong_inputs = fixture.public_inputs;
    wrong_inputs[1] += Fp::from(1);

    assert!(
        verify(&fixture, &fixture.proof, &wrong_inputs).is_err(),
        "verifier accepted a changed public nullifier hash"
    );
    Ok(())
}
