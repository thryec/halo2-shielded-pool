//! Local test keys and the BN254/KZG/SHPLONK withdrawal proof flow.
//! Never use this single-party setup to protect real funds.

use crate::{
    Fr,
    circuits::withdraw::{K, WithdrawCircuit},
};
use halo2_proofs::{
    halo2curves::{
        bn256::{Bn256, G1Affine},
        ff::PrimeField,
    },
    plonk::{Circuit, Error, ProvingKey, create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::{
        VerificationStrategy,
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand::{SeedableRng, rngs::OsRng};
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Keccak256};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier_sdk::{CircuitExt, SHPLONK, evm::gen_evm_verifier_sol_code};
use std::io::Cursor;

pub const PUBLIC_INPUTS: usize = 5;
pub const INSTANCE_BYTES: usize = PUBLIC_INPUTS * 32;
const TEST_SETUP_SEED: [u8; 32] = [0x42; 32];

pub struct TestKeys {
    pub params: ParamsKZG<Bn256>,
    pub pk: ProvingKey<G1Affine>,
}

impl TestKeys {
    /// Key generation uses only the fixed circuit shape, not a user's note.
    pub fn setup(circuit: &WithdrawCircuit) -> Result<Self, Error> {
        let params = ParamsKZG::<Bn256>::setup(K, ChaCha20Rng::from_seed(TEST_SETUP_SEED));
        let empty = circuit.without_witnesses();
        let vk = keygen_vk(&params, &empty)?;
        let pk = keygen_pk(&params, vk, &empty)?;

        Ok(Self { params, pk })
    }

    /// The prover uses the public proving key plus its private witness.
    pub fn prove(&self, circuit: WithdrawCircuit) -> Result<Vec<u8>, Error> {
        let instances = circuit.instances();
        let columns: Vec<_> = instances.iter().map(Vec::as_slice).collect();
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());

        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<_>,
            _,
            _,
            EvmTranscript<_, _, _, _>,
            _,
        >(
            &self.params,
            &self.pk,
            &[circuit],
            &[&columns],
            OsRng,
            &mut transcript,
        )?;

        let proof = transcript.finalize();

        // Halo2 can emit proof bytes for an invalid witness, so check before returning.
        if !self.verify(&proof, &instances) {
            return Err(Error::ConstraintSystemFailure);
        }

        Ok(proof)
    }

    /// Checking needs only verifier parameters and the vk held inside pk.
    pub fn verify(&self, proof: &[u8], instances: &[Vec<Fr>]) -> bool {
        if instances.len() != 1 || instances[0].len() != PUBLIC_INPUTS {
            return false;
        }

        let columns: Vec<_> = instances.iter().map(Vec::as_slice).collect();
        let mut reader = Cursor::new(proof);

        let accepted = {
            let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(&mut reader);
            match verify_proof::<_, VerifierSHPLONK<_>, _, EvmTranscript<_, _, _, _>, _>(
                self.params.verifier_params(),
                self.pk.get_vk(),
                AccumulatorStrategy::new(self.params.verifier_params()),
                &[&columns],
                &mut transcript,
            ) {
                Ok(strategy) => VerificationStrategy::<_, VerifierSHPLONK<_>>::finalize(strategy),
                Err(_) => false,
            }
        };

        accepted && reader.position() == proof.len() as u64
    }

    /// Check length and every scalar before the SDK can reduce it modulo Fr.
    pub fn solidity_verifier(&self, proof_bytes: usize) -> String {
        let strict = self.strict_solidity_verifier(proof_bytes);
        let id: [u8; 32] = Keccak256::digest(strict.as_bytes()).into();
        let declaration = format!(
            "contract Halo2Verifier {{\n    bytes32 public constant VERIFICATION_KEY_ID = 0x{};",
            hex::encode(id)
        );

        strict.replacen("contract Halo2Verifier {", &declaration, 1)
    }

    fn strict_solidity_verifier(&self, proof_bytes: usize) -> String {
        let code = gen_evm_verifier_sol_code::<WithdrawCircuit, SHPLONK>(
            &self.params,
            self.pk.get_vk(),
            vec![PUBLIC_INPUTS],
        );

        let mut strict = String::with_capacity(code.len());
        let mut scalar_count = 0;

        for line in code.lines().map(str::trim_end) {
            if let Some((_, tail)) = line.split_once("mod(calldataload(") {
                assert_eq!(
                    line.matches("mod(calldataload(").count(),
                    1,
                    "SDK scalar-load template changed"
                );
                let offset = tail
                    .split_once("), f_q)")
                    .expect("SDK scalar-load template changed")
                    .0;
                strict.push_str(&line.replace(
                    &format!("mod(calldataload({offset}), f_q)"),
                    &format!("checked_scalar({offset})"),
                ));
                scalar_count += 1;
            } else {
                strict.push_str(line);
            }
            strict.push('\n');
        }

        assert!(
            scalar_count > PUBLIC_INPUTS,
            "SDK scalar-load template changed"
        );

        let anchor = "assembly (\"memory-safe\") {";

        assert_eq!(
            strict.matches(anchor).count(),
            1,
            "SDK verifier template changed"
        );

        let calldata_bytes = INSTANCE_BYTES
            .checked_add(proof_bytes)
            .expect("proof length fits usize");

        let guards = format!(
            "{anchor}\n            if iszero(eq(calldatasize(), {calldata_bytes})) {{ revert(0, 0) }}\n            function checked_scalar(offset) -> value {{\n                value := calldataload(offset)\n                if iszero(lt(value, {})) {{ revert(0, 0) }}\n            }}",
            Fr::MODULUS,
        );

        let mut strict = strict.trim_end().replacen(anchor, &guards, 1);
        strict.push('\n');

        strict
    }

    pub fn verification_key_id(&self, proof_bytes: usize) -> [u8; 32] {
        Keccak256::digest(self.strict_solidity_verifier(proof_bytes).as_bytes()).into()
    }
}

pub fn field_bytes(value: Fr) -> [u8; 32] {
    let mut bytes = value.to_repr();
    bytes.reverse();

    bytes
}

pub fn encode_calldata(instances: &[Vec<Fr>], proof: &[u8]) -> Result<Vec<u8>, &'static str> {
    if instances.len() != 1 || instances[0].len() != PUBLIC_INPUTS {
        return Err("expected one column with five public inputs");
    }

    let mut encoded = Vec::with_capacity(INSTANCE_BYTES + proof.len());

    for &field in &instances[0] {
        encoded.extend_from_slice(&field_bytes(field));
    }

    encoded.extend_from_slice(proof);

    Ok(encoded)
}

pub fn decode_calldata(
    calldata: &[u8],
    proof_bytes: usize,
) -> Result<(Vec<Vec<Fr>>, &[u8]), &'static str> {
    if INSTANCE_BYTES.checked_add(proof_bytes) != Some(calldata.len()) {
        return Err("wrong calldata length");
    }

    let mut instances = Vec::with_capacity(PUBLIC_INPUTS);

    for word in calldata[..INSTANCE_BYTES].chunks_exact(32) {
        let mut bytes: [u8; 32] = word.try_into().expect("exact word length");
        bytes.reverse();
        let field = Option::<Fr>::from(Fr::from_repr(bytes)).ok_or("noncanonical public input")?;
        instances.push(field);
    }

    Ok((vec![instances], &calldata[INSTANCE_BYTES..]))
}
