use crate::{Fr, poseidon_hash};
use halo2_proofs::halo2curves::ff::PrimeField;

/// Deployment context. Integers and addresses use big-endian bytes.
/// Every u64 version is valid. A deployed pool fixes its chosen version.
#[derive(Clone, Copy, Debug)]
pub struct ProtocolDomain {
    pub chain_id: [u8; 32],
    pub pool: [u8; 20],
    /// Zero address denotes the native asset.
    pub asset: [u8; 20],
    pub version: u64,
}

/// Encodes up to 160 bits without reducing modulo the field modulus.
fn small_be_field(bytes: &[u8]) -> Fr {
    let mut repr = <Fr as PrimeField>::Repr::default();
    for (target, byte) in repr.as_mut().iter_mut().zip(bytes.iter().rev()) {
        *target = *byte;
    }
    Option::<Fr>::from(Fr::from_repr(repr)).expect("160-bit values fit the BN254 scalar field")
}

pub fn address_field(address: [u8; 20]) -> Fr {
    small_be_field(&address)
}

impl ProtocolDomain {
    /// H(HSP, H(H(H(chain_lo, chain_hi), H(pool, asset)), version)).
    /// Splitting the chain ID preserves all 256 bits without modular aliases.
    pub fn digest(&self) -> Fr {
        let chain = poseidon_hash([
            small_be_field(&self.chain_id[16..]),
            small_be_field(&self.chain_id[..16]),
        ]);
        let deployment = poseidon_hash([address_field(self.pool), address_field(self.asset)]);
        let body = poseidon_hash([poseidon_hash([chain, deployment]), Fr::from(self.version)]);
        poseidon_hash([Fr::from(0x485350), body])
    }
}

/// The private nullifier binds the recipient and deployment to this withdrawal.
/// The circuit must also constrain recipient to 160 bits.
pub fn withdrawal_binding(nullifier: Fr, recipient: Fr, domain: Fr) -> Fr {
    poseidon_hash([poseidon_hash([nullifier, recipient]), domain])
}
