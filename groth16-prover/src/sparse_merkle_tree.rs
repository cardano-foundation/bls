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
        if self.next_index >= (1usize << self.depth) {
            panic!("Tree is full");
        }
        let index = self.next_index;
        self.next_index += 1;
        self.insert_at(item, index);
    }

    /// Place a single item at an explicit leaf index in an otherwise default
    /// (empty) tree.
    ///
    /// This is the way to reproduce trees whose empty leaves stay zero-padded
    /// (e.g. a single-leaf tree where the leaf sits at index `> 0`).  Unlike
    /// [`Self::insert`], this does not advance the next-open index, so mixing
    /// it with later sequential `insert` calls can cause leaf collisions.
    /// Panics if the item already exists.
    pub fn insert_at(&mut self, item: Fr, index: usize) {
        assert!(
            index < (1usize << self.depth),
            "index {} out of range for depth {}",
            index,
            self.depth
        );
        let item_key = fr_to_key(item);
        if self.leaf_indices.contains_key(&item_key) {
            panic!("Item {} already exists in tree", item);
        }
        self.leaf_indices.insert(item_key, index);
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
    /// Returns `None` if the item is not in the tree.
    pub fn path(&self, item: Fr) -> Option<Vec<(Fr, bool)>> {
        let item_key = fr_to_key(item);
        let &index = self.leaf_indices.get(&item_key)?;

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
        Some(path)
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
    use proptest::prelude::*;

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
        let path = tree.path(item).unwrap();
        assert_eq!(path.len(), 2);
    }

    #[test]
    fn test_insert_at_offset_path_hashes_to_root() {
        // Single leaf at index 3 (0-padded tree), depth 2.
        let mut tree = SparseMerkleTree::new(2);
        let item = Fr::from(42u64);
        tree.insert_at(item, 3);
        let path = tree.path(item).unwrap();
        // Index 3 = 0b11: both directions are "sibling on left" (true).
        // Level-0 sibling is the empty left subtree parent mimc2(0, 0).
        assert_eq!(path, vec![(Fr::zero(), true), (mimc2(Fr::zero(), Fr::zero()), true)]);
        let root = recompute_root(item, &path);
        assert_eq!(root, tree.digest());
    }

    /// Recompute the root from a leaf and its Merkle path.
    ///
    /// `direction` is `true` when the sibling is on the **left**.
    fn recompute_root(leaf: Fr, path: &[(Fr, bool)]) -> Fr {
        let mut current = leaf;
        for (sibling, direction) in path {
            current = if *direction {
                // sibling is on the left
                mimc2(*sibling, current)
            } else {
                // sibling is on the right
                mimc2(current, *sibling)
            };
        }
        current
    }

    proptest! {
        #[test]
        fn prop_path_hashes_to_root(item in 1u64..1000u64) {
            let mut tree = SparseMerkleTree::new(4);
            let fr = Fr::from(item);
            tree.insert(fr);
            let path = tree.path(fr).unwrap();
            let root = recompute_root(fr, &path);
            prop_assert_eq!(root, tree.digest());
        }

        #[test]
        fn prop_multiple_items_path_verifies(
            items in prop::collection::hash_set(1u64..1000u64, 1..10)
        ) {
            let mut tree = SparseMerkleTree::new(4);
            let frs: Vec<Fr> = items.iter().map(|&i| Fr::from(i)).collect();
            for fr in &frs {
                tree.insert(*fr);
            }
            for fr in &frs {
                let path = tree.path(*fr).unwrap();
                let root = recompute_root(*fr, &path);
                prop_assert_eq!(root, tree.digest());
            }
        }

        #[test]
        fn prop_rebuild_tree_same_digest(
            items in prop::collection::hash_set(1u64..1000u64, 1..10)
        ) {
            let mut tree1 = SparseMerkleTree::new(4);
            let frs: Vec<Fr> = items.iter().map(|&i| Fr::from(i)).collect();
            for fr in &frs {
                tree1.insert(*fr);
            }
            let mut tree2 = SparseMerkleTree::new(4);
            for fr in &frs {
                tree2.insert(*fr);
            }
            prop_assert_eq!(tree1.digest(), tree2.digest());
        }

        #[test]
        fn prop_missing_leaf_returns_none(
            items in prop::collection::hash_set(1u64..1000u64, 1..10),
            missing in 1001u64..2000u64
        ) {
            let mut tree = SparseMerkleTree::new(4);
            for &i in &items {
                tree.insert(Fr::from(i));
            }
            prop_assert!(tree.path(Fr::from(missing)).is_none());
        }
    }
}
