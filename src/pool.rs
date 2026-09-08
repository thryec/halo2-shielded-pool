// native pool state simulation — caller must verify the proof before recording a withdrawal

use crate::{
    Fr,
    primitives::merkle::{MerkleError, MerklePath, MerkleTree},
};

#[derive(Default)]
pub struct Pool {
    tree: MerkleTree,
    known_roots: Vec<Fr>,
    spent_nullifier_hashes: Vec<Fr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolError {
    TreeFull,
    UnknownRoot,
    NullifierAlreadySpent,
}

impl Pool {
    pub fn new() -> Self {
        let tree = MerkleTree::new();
        let empty_root = tree.root();

        Self {
            tree,
            known_roots: vec![empty_root],
            spent_nullifier_hashes: Vec::new(),
        }
    }

    // insert commitment as leaf into tree
    // record new root
    pub fn deposit(&mut self, commitment: Fr) -> Result<usize, PoolError> {
        let index = self
            .tree
            .insert(commitment)
            .map_err(|_| PoolError::TreeFull)?;

        let new_root = self.tree.root();
        self.known_roots.push(new_root);

        Ok(index)
    }

    pub fn root(&self) -> Fr {
        self.tree.root()
    }

    pub fn merkle_path(&self, index: usize) -> Result<MerklePath, MerkleError> {
        self.tree.prove(index)
    }

    // check if nullifier hash is spent
    // if so, reject withdrawal
    // check if root is in valid known roots
    // if hash and root are valid, store hash in spent hashes and return success for withdrawal
    pub fn record_withdrawal(&mut self, root: Fr, nullifier_hash: Fr) -> Result<(), PoolError> {
        if !self.is_known_root(root) {
            return Err(PoolError::UnknownRoot);
        }

        if self.is_spent_nullifier(nullifier_hash) {
            return Err(PoolError::NullifierAlreadySpent);
        }

        self.spent_nullifier_hashes.push(nullifier_hash);

        Ok(())
    }

    // check if root exists in known_roots
    pub fn is_known_root(&self, root: Fr) -> bool {
        self.known_roots.contains(&root)
    }

    // check nullifier against spent_nullifier_hashes
    pub fn is_spent_nullifier(&self, nullifier_hash: Fr) -> bool {
        self.spent_nullifier_hashes.contains(&nullifier_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::merkle::TREE_CAPACITY;

    #[test]
    fn deposit_updates_root() {
        let mut pool = Pool::new();
        let root1 = pool.tree.root();
        let commitment = Fr::from(5);

        let index = pool.deposit(commitment).unwrap();
        let root2 = pool.tree.root();

        assert_eq!(index, 0);
        assert_ne!(root1, root2);
    }

    #[test]
    fn deposit_root_becomes_recognized() {
        let mut pool = Pool::new();
        let commitment = Fr::from(5);

        let index = pool.deposit(commitment).unwrap();
        let root = pool.tree.root();

        assert_eq!(index, 0);
        assert!(pool.is_known_root(root))
    }

    #[test]
    fn can_withdraw_from_pool() {
        let mut pool = Pool::new();
        let commitment = Fr::from(5);
        let nullifier_hash = Fr::from(10);

        pool.deposit(commitment).unwrap();
        let root = pool.tree.root();

        let result = pool.record_withdrawal(root, nullifier_hash);

        assert_eq!(result, Ok(()));
        assert!(pool.is_spent_nullifier(nullifier_hash));
    }

    #[test]
    fn reusing_nullifier_hash_fails() {
        let mut pool = Pool::new();
        let commitment = Fr::from(5);
        let nullifier_hash = Fr::from(10);

        pool.deposit(commitment).unwrap();
        let root = pool.tree.root();

        let result1 = pool.record_withdrawal(root, nullifier_hash);

        assert_eq!(result1, Ok(()));
        assert_eq!(
            pool.record_withdrawal(root, nullifier_hash),
            Err(PoolError::NullifierAlreadySpent)
        );
    }

    #[test]
    fn unknown_root_fails() {
        let mut pool = Pool::new();
        let commitment = Fr::from(5);
        let nullifier_hash = Fr::from(10);

        pool.deposit(commitment).unwrap();
        let root = pool.tree.root() + Fr::from(1);

        assert_eq!(
            pool.record_withdrawal(root, nullifier_hash),
            Err(PoolError::UnknownRoot)
        );
    }

    #[test]
    fn empty_root_is_recognized() {
        let pool = Pool::new();
        let empty_root = MerkleTree::new().root();

        assert!(pool.is_known_root(empty_root));
    }

    #[test]
    fn older_root_remains_recognized_after_later_deposit() {
        let mut pool = Pool::new();

        pool.deposit(Fr::from(5)).unwrap();
        let older_root = pool.tree.root();

        pool.deposit(Fr::from(10)).unwrap();
        let latest_root = pool.tree.root();

        assert_ne!(older_root, latest_root);
        assert!(pool.is_known_root(older_root));
        assert!(pool.is_known_root(latest_root));
    }

    #[test]
    fn deposit_returns_tree_full_when_tree_is_full() {
        let mut pool = Pool::new();

        for value in 0..TREE_CAPACITY {
            pool.tree.insert(Fr::from(value as u64)).unwrap();
        }

        assert_eq!(pool.deposit(Fr::from(1_000)), Err(PoolError::TreeFull));
    }
}
