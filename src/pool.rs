// mimics onchain smart contract by simulating pool state for deposits and withdrawals
// proof verification happens in offchain prover logic (withdraw.rs)

use crate::{primitives::merkle::MerkleTree, Fp};

#[derive(Default)]
pub struct Pool {
    tree: MerkleTree,
    known_roots: Vec<Fp>,
    spent_nullifier_hashes: Vec<Fp>,
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
    pub fn deposit(&mut self, commitment: Fp) -> Result<usize, PoolError> {
        let index = self
            .tree
            .insert(commitment)
            .map_err(|_| PoolError::TreeFull)?;

        let new_root = self.tree.root();
        self.known_roots.push(new_root);

        Ok(index)
    }

    // check if nullifier hash is spent
    // if so, reject withdrawal
    // check if root is in valid known roots
    // if hash and root are valid, store hash in spent hashes and return success for withdrawal
    pub fn record_withdrawal(&mut self, root: Fp, nullifier_hash: Fp) -> Result<(), PoolError> {
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
    pub fn is_known_root(&self, root: Fp) -> bool {
        self.known_roots.contains(&root)
    }

    // check nullifier against spent_nullifier_hashes
    pub fn is_spent_nullifier(&self, nullifier_hash: Fp) -> bool {
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
        let commitment = Fp::from(5);

        let index = pool.deposit(commitment).unwrap();
        let root2 = pool.tree.root();

        assert_eq!(index, 0);
        assert_ne!(root1, root2);
    }

    #[test]
    fn deposit_root_becomes_recognized() {
        let mut pool = Pool::new();
        let commitment = Fp::from(5);

        let index = pool.deposit(commitment).unwrap();
        let root = pool.tree.root();

        assert_eq!(index, 0);
        assert!(pool.is_known_root(root))
    }

    #[test]
    fn can_withdraw_from_pool() {
        let mut pool = Pool::new();
        let commitment = Fp::from(5);
        let nullifier_hash = Fp::from(10);

        pool.deposit(commitment).unwrap();
        let root = pool.tree.root();

        let result = pool.record_withdrawal(root, nullifier_hash);

        assert_eq!(result, Ok(()));
        assert!(pool.is_spent_nullifier(nullifier_hash));
    }

    #[test]
    fn reusing_nullifier_hash_fails() {
        let mut pool = Pool::new();
        let commitment = Fp::from(5);
        let nullifier_hash = Fp::from(10);

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
        let commitment = Fp::from(5);
        let nullifier_hash = Fp::from(10);

        pool.deposit(commitment).unwrap();
        let root = pool.tree.root() + Fp::from(1);

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

        pool.deposit(Fp::from(5)).unwrap();
        let older_root = pool.tree.root();

        pool.deposit(Fp::from(10)).unwrap();
        let latest_root = pool.tree.root();

        assert_ne!(older_root, latest_root);
        assert!(pool.is_known_root(older_root));
        assert!(pool.is_known_root(latest_root));
    }

    #[test]
    fn deposit_returns_tree_full_when_tree_is_full() {
        let mut pool = Pool::new();

        for value in 0..TREE_CAPACITY {
            pool.tree.insert(Fp::from(value as u64)).unwrap();
        }

        assert_eq!(pool.deposit(Fp::from(1_000)), Err(PoolError::TreeFull));
    }
}
