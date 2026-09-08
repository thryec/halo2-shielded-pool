use crate::{Fr, poseidon_hash};

pub const TREE_DEPTH: usize = 8;
pub const TREE_CAPACITY: usize = 1 << TREE_DEPTH;

#[derive(Default)]
pub struct MerkleTree {
    leaves: Vec<Fr>,
}

#[derive(Clone, Debug)]
pub struct MerklePath {
    siblings: [Fr; TREE_DEPTH],
    path_bits: [bool; TREE_DEPTH],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleError {
    TreeFull,
    LeafIndexOutOfBounds,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, leaf: Fr) -> Result<usize, MerkleError> {
        if self.leaves.len() == TREE_CAPACITY {
            return Err(MerkleError::TreeFull);
        }
        let index = self.leaves.len();
        self.leaves.push(leaf);
        Ok(index)
    }

    /// Unused leaves hold field zero, not a note commitment or a hashed zero.
    fn padded_leaves(&self) -> Vec<Fr> {
        let mut leaves = vec![Fr::from(0); TREE_CAPACITY];
        leaves[..self.leaves.len()].copy_from_slice(&self.leaves);
        leaves
    }

    pub fn root(&self) -> Fr {
        let mut level = self.padded_leaves();
        for _ in 0..TREE_DEPTH {
            level = parent_level(&level);
        }
        level[0]
    }

    /// Paths run from leaf to root. A true bit places the current node right.
    pub fn prove(&self, index: usize) -> Result<MerklePath, MerkleError> {
        if index >= self.leaves.len() {
            return Err(MerkleError::LeafIndexOutOfBounds);
        }
        let mut level = self.padded_leaves();
        let mut current_index = index;
        let mut siblings = [Fr::from(0); TREE_DEPTH];
        let mut path_bits = [false; TREE_DEPTH];
        for depth in 0..TREE_DEPTH {
            siblings[depth] = level[current_index ^ 1];
            path_bits[depth] = current_index & 1 == 1;
            level = parent_level(&level);
            current_index /= 2;
        }
        Ok(MerklePath {
            siblings,
            path_bits,
        })
    }
}

impl MerklePath {
    pub fn siblings(&self) -> &[Fr; TREE_DEPTH] {
        &self.siblings
    }

    pub fn path_bits(&self) -> &[bool; TREE_DEPTH] {
        &self.path_bits
    }

    pub fn compute_root(&self, leaf: Fr) -> Fr {
        let mut current = leaf;
        for depth in 0..TREE_DEPTH {
            current = if self.path_bits[depth] {
                poseidon_hash([self.siblings[depth], current])
            } else {
                poseidon_hash([current, self.siblings[depth]])
            };
        }
        current
    }

    pub fn verify(&self, leaf: Fr, expected_root: Fr) -> bool {
        self.compute_root(leaf) == expected_root
    }
}

fn parent_level(level: &[Fr]) -> Vec<Fr> {
    level
        .chunks_exact(2)
        .map(|pair| poseidon_hash([pair[0], pair[1]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_merkle_rejects_each_tampered_sibling_and_direction() {
        let leaf = Fr::from(7);
        let mut tree = MerkleTree::new();
        tree.insert(Fr::from(3)).unwrap();
        tree.insert(leaf).unwrap();
        tree.insert(Fr::from(9)).unwrap();
        let root = tree.root();
        let path = tree.prove(1).unwrap();
        for depth in 0..TREE_DEPTH {
            let mut wrong_sibling = path.clone();
            wrong_sibling.siblings[depth] += Fr::from(1);
            assert!(!wrong_sibling.verify(leaf, root), "sibling {depth}");
            let mut wrong_direction = path.clone();
            wrong_direction.path_bits[depth] ^= true;
            assert!(!wrong_direction.verify(leaf, root), "direction {depth}");
        }
    }
}
