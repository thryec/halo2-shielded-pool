// merkle tree operations: insert, root, prove, verify

use crate::poseidon_hash;
use crate::Fp;

pub const TREE_DEPTH: usize = 8;
pub const TREE_CAPACITY: usize = 1 << TREE_DEPTH;

#[derive(Default)]
pub struct MerkleTree {
    leaves: Vec<Fp>,
}

pub struct MerklePath {
    siblings: [Fp; TREE_DEPTH],
    path_bits: [bool; TREE_DEPTH],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleError {
    TreeFull,
    LeafIndexOutOfBounds,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn insert(&mut self, leaf: Fp) -> Result<usize, MerkleError> {
        if self.leaves.len() >= TREE_CAPACITY {
            return Err(MerkleError::TreeFull);
        }

        let index = self.leaves.len();
        self.leaves.push(leaf);

        Ok(index)
    }

    pub fn root(&self) -> Fp {
        let mut level = vec![Fp::from(0); TREE_CAPACITY];

        level[..self.leaves.len()].copy_from_slice(&self.leaves[..]);

        while level.len() > 1 {
            let mut next_level = Vec::new();
            let mut index = 0;

            while index < level.len() {
                let parent = hash_pair(level[index], level[index + 1]);
                next_level.push(parent);

                index += 2
            }
            level = next_level;
        }
        level[0]
    }

    // generate a Merkle path for one inserted leaf
    pub fn prove(&self, index: usize) -> Result<MerklePath, MerkleError> {
        if index >= self.leaves.len() {
            return Err(MerkleError::LeafIndexOutOfBounds);
        }

        let mut level = vec![Fp::from(0); TREE_CAPACITY];
        level[..self.leaves.len()].copy_from_slice(&self.leaves[..]);

        let mut siblings = [Fp::from(0); TREE_DEPTH];
        let mut path_bits = [false; TREE_DEPTH];
        let mut current_index = index;

        for depth in 0..TREE_DEPTH {
            let is_right = current_index % 2 == 1;
            let sibling_index = if is_right {
                current_index - 1
            } else {
                current_index + 1
            };
            siblings[depth] = level[sibling_index];
            path_bits[depth] = is_right;

            let mut next_level = Vec::with_capacity(level.len() / 2);

            for pair in level.chunks_exact(2) {
                next_level.push(hash_pair(pair[0], pair[1]))
            }

            level = next_level;
            current_index /= 2;
        }
        Ok(MerklePath {
            siblings,
            path_bits,
        })
    }
}

impl MerklePath {
    fn compute_root(&self, leaf: Fp) -> Fp {
        let mut current = leaf;

        for level in 0..TREE_DEPTH {
            let sibling = self.siblings[level];
            let is_right = self.path_bits[level];

            current = if is_right {
                hash_pair(sibling, current)
            } else {
                hash_pair(current, sibling)
            };
        }
        current
    }

    pub fn verify(&self, leaf: Fp, expected_root: Fp) -> bool {
        self.compute_root(leaf) == expected_root
    }
}

fn hash_pair(left: Fp, right: Fp) -> Fp {
    poseidon_hash([left, right])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_leaf_at_next_index() {
        let mut tree = MerkleTree::new();

        assert_eq!(tree.insert(Fp::from(2)), Ok(0));
        assert_eq!(tree.insert(Fp::from(3)), Ok(1));
    }

    #[test]
    fn empty_tree_root_is_deterministic() {
        let tree1 = MerkleTree::new();
        let tree2 = MerkleTree::new();

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn generates_valid_proof_for_inserted_leaf() {
        let mut tree = MerkleTree::new();
        let leaf = Fp::from(5);
        let index = tree.insert(leaf).unwrap();

        let proof = tree.prove(index).unwrap();
        assert!(proof.verify(leaf, tree.root()));
    }

    #[test]
    fn proof_verifies_after_multiple_inserts() {
        let mut tree = MerkleTree::new();
        let leaf1 = Fp::from(5);
        let leaf2 = Fp::from(1);

        let index1 = tree.insert(leaf1).unwrap();
        let index2 = tree.insert(leaf2).unwrap();

        let proof1 = tree.prove(index1).unwrap();
        let proof2 = tree.prove(index2).unwrap();

        assert!(proof1.verify(leaf1, tree.root()));
        assert!(proof2.verify(leaf2, tree.root()));
    }

    #[test]
    fn wrong_leaf_fails() {
        let mut tree = MerkleTree::new();
        let leaf1 = Fp::from(5);
        let leaf2 = Fp::from(1);

        let index1 = tree.insert(leaf1).unwrap();
        let index2 = tree.insert(leaf2).unwrap();

        let proof1 = tree.prove(index1).unwrap();
        let proof2 = tree.prove(index2).unwrap();

        let root = tree.root();
        assert!(!proof1.verify(leaf2, root));
        assert!(!proof2.verify(leaf1, root));
    }

    #[test]
    fn wrong_root_fails() {
        let mut tree = MerkleTree::new();
        let leaf = Fp::from(5);
        let index = tree.insert(leaf).unwrap();
        let wrong_root = tree.root() + Fp::from(1);

        let proof = tree.prove(index).unwrap();
        assert!(!proof.verify(leaf, wrong_root));
    }

    #[test]
    fn insertion_changes_root() {
        let mut tree = MerkleTree::new();
        tree.insert(Fp::from(5)).unwrap();
        let root1 = tree.root();

        tree.insert(Fp::from(10)).unwrap();
        let root2 = tree.root();

        assert_ne!(root1, root2);
    }

    #[test]
    fn invalid_index_returns_error() {
        let tree = MerkleTree::new();

        assert!(matches!(
            tree.prove(0),
            Err(MerkleError::LeafIndexOutOfBounds)
        ))
    }

    #[test]
    fn full_tree_rejects_another_leaf() {
        let mut tree = MerkleTree::new();
        for value in 0..TREE_CAPACITY {
            tree.insert(Fp::from(value as u64)).unwrap();
        }

        assert_eq!(tree.insert(Fp::from(1000)), Err(MerkleError::TreeFull));
    }

    #[test]
    fn flipped_path_bit_fails() {
        let mut tree = MerkleTree::new();
        let leaf = Fp::from(5);
        let index = tree.insert(leaf).unwrap();
        let mut proof = tree.prove(index).unwrap();
        let root = tree.root();

        proof.path_bits[0] = !proof.path_bits[0];

        assert!(!proof.verify(leaf, root));
    }

    #[test]
    fn tampered_sibling_fails() {
        let mut tree = MerkleTree::new();
        let leaf = Fp::from(5);
        let index = tree.insert(leaf).unwrap();
        let mut proof = tree.prove(index).unwrap();

        proof.siblings[0] += Fp::from(2);

        assert!(!proof.verify(leaf, tree.root()))
    }
}
