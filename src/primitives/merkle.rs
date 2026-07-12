// merkle tree operations: insert, root, prove, verify

use std::ptr::hash;
use std::thread::current;

use crate::Fp;
use crate::poseidon_hash;

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
}
