use halo2_proofs::{
    circuit::Value,
    halo2curves::pasta::EqAffine, // ipa curve point type whose scalar field matches our circuit's Fp
    plonk::{
        Circuit,
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

#[test]
fn real_proof_round_trip() -> Result<(), halo2_proofs::plonk::Error> {
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

    // 4. Verify the proof.
    let strategy = SingleStrategy::new(&params);
    let mut reader = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&proof[..]);

    verify_proof::<IPACommitmentScheme<EqAffine>, VerifierIPA<EqAffine>, _, _, _>(
        &params,
        pk.get_vk(),
        strategy,
        &instances,
        &mut reader,
    )?;

    Ok(())
}
