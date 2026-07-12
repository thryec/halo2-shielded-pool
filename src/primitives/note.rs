// computes note using nullifier hash and secret

use crate::Fp;
use crate::poseidon_hash;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Note {
    nullifier: Fp,
    secret: Fp,
}

impl Note {
    pub fn new(nullifier: Fp, secret: Fp) -> Self {
        Self { nullifier, secret }
    }

    pub fn commitment(&self) -> Fp {
        poseidon_hash([self.nullifier, self.secret])
    }

    pub fn nullifier_hash(&self) -> Fp {
        poseidon_hash([self.nullifier])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_matches_poseidon_hash() {
        let note = Note::new(Fp::from(2), Fp::from(4));

        assert_eq!(note.commitment(), poseidon_hash([Fp::from(2), Fp::from(4)]))
    }

    fn nullifier_matches_poseidon_hash() {
        let note = Note::new(Fp::from(2), Fp::from(4));

        assert_eq!(note.nullifier_hash(), poseidon_hash([Fp::from(2)]))
    }

    fn changing_secret_only_changes_commitment() {
        let note1 = Note::new(Fp::from(2), Fp::from(4));
        let note2 = Note::new(Fp::from(2), Fp::from(5));

        assert_eq!(note1.nullifier_hash(), note2.nullifier_hash());
        assert_ne!(note1.commitment(), note2.commitment());
    }

    fn changing_nullifier_changes_both_hashes() {
        let note1 = Note::new(Fp::from(2), Fp::from(4));
        let note2 = Note::new(Fp::from(3), Fp::from(4));

        assert_ne!(note1.commitment(), note2.commitment());
        assert_ne!(note1.nullifier_hash(), note2.nullifier_hash());
    }
}
