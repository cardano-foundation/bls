// Sparse Merkle Tree using MiMC(x^7) over BLS12-381
// This project is strictly focused on BLS12-381. BN254 is not supported.

use ark_bls12_381::Fr;
use std::collections::HashMap;
use crate::mimc::mimc2;

/// An insert-only sparse Merkle tree backed by MiMC(x^7) hashing.
///
/// Unoccupied nodes have value `Fr::zero()` at the leaf level and
/// `mimc2(default, default)` at each higher level.
pub struct SparseMerkleTree {
    depth: usize,
    defaults: Vec<Fr>,
    nodes: HashMap<String, Fr>,
    leaf_indices: HashMap<String, usize>,
    next_index: usize,
}

impl SparseMerkleTree {
    /// Create a new sparse Merkle tree with the given depth.
    pub fn new(depth: usize) -> Self {
        let mut defaults = vec![Fr::from(0u64)];
        while defaults.len() < depth + 1 {
            let last = *defaults.last().unwrap();
            defaults.push(mimc2(last, last));
        }
        defaults.reverse();
        Self {
            depth,
            defaults,
            nodes: HashMap::new(),
            leaf_indices: HashMap::new(),
            next_index: 0,
        }
    }

    /// Return the Merkle digest (root hash).
    pub fn digest(&self) -> Fr {
        self.node(0, 0)
    }

    /// Insert an item into the next open leaf.
    /// Panics if the item already exists or the tree is full.
    pub fn insert(&mut self, item: Fr) {
        let item_key = fr_to_key(item);
        if self.leaf_indices.contains_key(&item_key) {
            panic!("Item {} already exists in tree", item);
        }
        if self.next_index >= (1usize << self.depth) {
            panic!("Tree is full");
        }
        let index = self.next_index;
        self.next_index += 1;
        self.leaf_indices.insert(item_key.clone(), index);
        self.nodes.insert(node_key(self.depth, index), item);

        let mut level = self.depth;
        let mut idx = index;
        while level > 0 {
            level -= 1;
            idx = idx / 2;
            let left = self.node(level + 1, 2 * idx);
            let right = self.node(level + 1, 2 * idx + 1);
            self.nodes.insert(node_key(level, idx), mimc2(left, right));
        }
    }

    /// Return the Merkle path for an item.
    ///
    /// The path is a vector of `(sibling, direction)` pairs from leaf to root.
    /// `direction` is `true` when the sibling is on the left.
    pub fn path(&self, item: Fr) -> Vec<(Fr, bool)> {
        let item_key = fr_to_key(item);
        let Some(&index) = self.leaf_indices.get(&item_key) else {
            panic!("Item {} not found in tree", item);
        };

        let mut level = self.depth;
        let mut idx = index;
        let mut path = Vec::with_capacity(self.depth);
        while level > 0 {
            let direction = (idx & 1) == 1;
            level -= 1;
            idx = idx / 2;
            let sibling_idx = 2 * idx + if direction { 0 } else { 1 };
            let sibling = self.node(level + 1, sibling_idx);
            path.push((sibling, direction));
        }
        path
    }

    fn node(&self, level: usize, index: usize) -> Fr {
        self.nodes
            .get(&node_key(level, index))
            .copied()
            .unwrap_or(self.defaults[level])
    }
}

fn fr_to_key(fr: Fr) -> String {
    fr.to_string()
}

fn node_key(level: usize, index: usize) -> String {
    format!("{}, {}", level, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::Zero;

    #[test]
    fn test_empty_tree_digest() {
        let tree = SparseMerkleTree::new(2);
        let d = tree.digest();
        assert_ne!(d, Fr::zero());
    }

    #[test]
    fn test_insert_and_path() {
        let mut tree = SparseMerkleTree::new(2);
        let item = Fr::from(42u64);
        tree.insert(item);
        let path = tree.path(item);
        assert_eq!(path.len(), 2);
    }
}
