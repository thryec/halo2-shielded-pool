use crate::{Fr, poseidon_hash};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    nullifier: Fr,
    secret: Fr,
}

impl Note {
    pub fn new(nullifier: Fr, secret: Fr) -> Self {
        Self { nullifier, secret }
    }

    pub fn commitment(&self) -> Fr {
        poseidon_hash([self.nullifier, self.secret])
    }

    pub fn nullifier_hash(&self) -> Fr {
        poseidon_hash([self.nullifier])
    }

    pub fn nullifier(&self) -> Fr {
        self.nullifier
    }

    pub fn secret(&self) -> Fr {
        self.secret
    }
}
