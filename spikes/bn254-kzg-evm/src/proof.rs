use crate::circuit::PoseidonCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{Circuit, Error, VerifyingKey, keygen_pk, keygen_vk, verify_proof},
    poly::{
        VerificationStrategy,
        commitment::ParamsProver,
        kzg::{commitment::ParamsKZG, multiopen::VerifierSHPLONK, strategy::AccumulatorStrategy},
    },
    transcript::TranscriptReadBuffer,
};
use rand::rngs::OsRng;
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier_sdk::{
    CircuitExt, SHPLONK,
    evm::{gen_evm_proof_shplonk, gen_evm_verifier_sol_code},
};

pub const K: u32 = 7;

pub struct ProofFixture {
    pub params: ParamsKZG<Bn256>,
    pub vk: VerifyingKey<G1Affine>,
    pub instances: Vec<Vec<Fr>>,
    pub proof: Vec<u8>,
}

pub fn build() -> Result<ProofFixture, Error> {
    let circuit = PoseidonCircuit::new([Fr::from(1), Fr::from(2)]);
    let instances = circuit.instances();
    // local test setup only; these parameters are not a production ceremony
    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let empty = circuit.without_witnesses();
    let vk = keygen_vk(&params, &empty)?;
    let pk = keygen_pk(&params, vk, &empty)?;
    let proof = gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());
    Ok(ProofFixture {
        params,
        vk: pk.get_vk().clone(),
        instances,
        proof,
    })
}

pub fn verify(fixture: &ProofFixture, proof: &[u8], instances: &[Vec<Fr>]) -> bool {
    let columns: Vec<_> = instances.iter().map(Vec::as_slice).collect();
    let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof);
    match verify_proof::<_, VerifierSHPLONK<_>, _, EvmTranscript<_, _, _, _>, _>(
        fixture.params.verifier_params(),
        &fixture.vk,
        AccumulatorStrategy::new(fixture.params.verifier_params()),
        &[&columns],
        &mut transcript,
    ) {
        Ok(strategy) => VerificationStrategy::<_, VerifierSHPLONK<_>>::finalize(strategy),
        Err(_) => false,
    }
}

pub fn solidity_verifier(fixture: &ProofFixture) -> String {
    gen_evm_verifier_sol_code::<PoseidonCircuit, SHPLONK>(&fixture.params, &fixture.vk, vec![1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_proof_accepts_honest_and_rejects_changed_inputs_and_bytes() {
        let fixture = build().unwrap();
        assert!(verify(&fixture, &fixture.proof, &fixture.instances));
        let mut wrong = fixture.instances.clone();
        wrong[0][0] += Fr::from(1);
        assert!(!verify(&fixture, &fixture.proof, &wrong));
        let mut corrupted = fixture.proof.clone();
        corrupted[0] ^= 1;
        assert!(!verify(&fixture, &corrupted, &fixture.instances));
    }
}
