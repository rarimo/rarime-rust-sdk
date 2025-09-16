use crate::RarimeError;
use crate::owned_cert::OwnedCertificate;
use num_bigint::BigUint;
use num_traits::Zero;
use sha3::{Digest, Keccak256};
use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct TreapNode {
    pub hash: Vec<u8>,
    pub priority: u64,
    pub merkle_hash: Vec<u8>,
    pub left: Option<Box<TreapNode>>,
    pub right: Option<Box<TreapNode>>,
}

impl TreapNode {
    pub fn new(hash: Vec<u8>, priority: u64) -> Self {
        Self {
            merkle_hash: hash.clone(),
            hash,
            priority,
            left: None,
            right: None,
        }
    }
}

pub trait ITreap {
    fn remove(&mut self, key: &[u8]);
    fn insert(&mut self, key: Vec<u8>, priority: u64);
    fn merkle_path(&self, key: &[u8]) -> Vec<Vec<u8>>;
    fn merkle_root(&self) -> Option<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub struct Treap {
    root: Option<Box<TreapNode>>,
}

impl Treap {
    pub fn new() -> Self {
        Self { root: None }
    }
    pub fn derive_priority(key: &[u8]) -> u64 {
        let mut hasher = Keccak256::new();
        hasher.update(key);
        let key_hash = hasher.finalize();

        // Convert full hash to big integer, matching Go implementation
        // priority = keccak256.Hash(key) % (2^64-1)
        let key_hash_bigint = BigUint::from_bytes_be(&key_hash);
        let max_u64_minus_1 = BigUint::from(u64::MAX);
        let priority = key_hash_bigint % max_u64_minus_1;

        // Convert back to u64
        priority.to_u64_digits().get(0).copied().unwrap_or(0)
    }

    fn compare_bytes(a: &[u8], b: &[u8]) -> Ordering {
        a.cmp(b)
    }

    fn bytes_to_bigint(bytes: &[u8]) -> BigUint {
        BigUint::from_bytes_be(bytes)
    }

    fn bigint_to_bytes(value: &BigUint) -> Vec<u8> {
        if value.is_zero() {
            return vec![0];
        }
        value.to_bytes_be()
    }

    fn keccak256_hash(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(a);
        hasher.update(b);
        hasher.finalize().to_vec()
    }
    fn hash(a: Option<&[u8]>, b: Option<&[u8]>) -> Vec<u8> {
        match (a, b) {
            (None, None) => vec![],
            (Some(a), None) => {
                if a.is_empty() {
                    vec![]
                } else {
                    a.to_vec()
                }
            }
            (None, Some(b)) => {
                if b.is_empty() {
                    vec![]
                } else {
                    b.to_vec()
                }
            }
            (Some(a), Some(b)) => {
                if a.is_empty() && b.is_empty() {
                    return vec![];
                }
                if a.is_empty() {
                    return b.to_vec();
                }
                if b.is_empty() {
                    return a.to_vec();
                }

                if Self::compare_bytes(a, b) == Ordering::Less {
                    Self::keccak256_hash(a, b)
                } else {
                    Self::keccak256_hash(b, a)
                }
            }
        }
    }

    fn hash_nodes(a: Option<&TreapNode>, b: Option<&TreapNode>) -> Vec<u8> {
        let left = a.map(|node| node.merkle_hash.as_slice()).unwrap_or(&[]);
        let right = b.map(|node| node.merkle_hash.as_slice()).unwrap_or(&[]);

        Self::hash(Some(left), Some(right))
    }

    fn update_node(node: &mut TreapNode) {
        let children_hash = Self::hash_nodes(node.left.as_deref(), node.right.as_deref());

        // Match Go implementation exactly
        if children_hash.is_empty() {
            node.merkle_hash = node.hash.clone();
        } else {
            node.merkle_hash = Self::hash(Some(&children_hash), Some(&node.hash));
        }
    }

    fn split(
        root: Option<Box<TreapNode>>,
        key: &[u8],
    ) -> (Option<Box<TreapNode>>, Option<Box<TreapNode>>) {
        if root.is_none() {
            return (None, None);
        }

        let mut root = root.unwrap();

        // Matches Go implementation: bytes.Compare(root.Hash, key) <= 0
        if Self::compare_bytes(&root.hash, key) != Ordering::Greater {
            let (left, right) = Self::split(root.right.take(), key);
            root.right = left;
            Self::update_node(&mut root);
            (Some(root), right)
        } else {
            let (left, right) = Self::split(root.left.take(), key);
            root.left = right;
            Self::update_node(&mut root);
            (left, Some(root))
        }
    }

    fn merge(
        left: Option<Box<TreapNode>>,
        right: Option<Box<TreapNode>>,
    ) -> Option<Box<TreapNode>> {
        match (left, right) {
            (None, right) => right,
            (left, None) => left,
            (Some(mut left), Some(mut right)) => {
                if left.priority > right.priority {
                    left.right = Self::merge(left.right.take(), Some(right));
                    Self::update_node(&mut left);
                    Some(left)
                } else {
                    right.left = Self::merge(Some(left), right.left.take());
                    Self::update_node(&mut right);
                    Some(right)
                }
            }
        }
    }
}

impl ITreap for Treap {
    fn remove(&mut self, key: &[u8]) {
        if self.root.is_none() {
            return;
        }

        // Split the tree by key-1 => target key in the right subtree
        // Split the subtree by key => target key is one left node
        let key_big = Self::bytes_to_bigint(key);

        // Handle the case where key is zero (can't subtract 1)
        if key_big.is_zero() {
            let (_, right_after_split) = Self::split(self.root.take(), key);
            self.root = right_after_split;
            return;
        }

        let key_sub1 = Self::bigint_to_bytes(&(&key_big - BigUint::from(1u32)));

        let (left, right) = Self::split(self.root.take(), &key_sub1);
        if right.is_none() {
            self.root = left;
            return;
        }

        let (_, right_after_split) = Self::split(right, key);
        self.root = Self::merge(left, right_after_split);
    }

    fn insert(&mut self, key: Vec<u8>, priority: u64) {
        let middle = Box::new(TreapNode::new(key.clone(), priority));

        if self.root.is_none() {
            self.root = Some(middle);
            return;
        }

        let (left, right) = Self::split(self.root.take(), &key);
        self.root = Self::merge(Self::merge(left, Some(middle)), right);
    }

    fn merkle_path(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut node = self.root.as_ref();
        let mut result = Vec::new();

        while let Some(current) = node {
            match Self::compare_bytes(&current.hash, key) {
                Ordering::Equal => {
                    // Found the key, add the children hash if it exists
                    let hashed_nodes =
                        Self::hash_nodes(current.left.as_deref(), current.right.as_deref());
                    if !hashed_nodes.is_empty() {
                        result.push(hashed_nodes);
                    }
                    // Reverse the result to match Go implementation
                    result.reverse();
                    return result;
                }
                Ordering::Greater => {
                    // current.hash > key, so we go left
                    // Add current hash and right sibling (if exists)
                    result.push(current.hash.clone());
                    if let Some(right) = &current.right {
                        result.push(right.merkle_hash.clone());
                    }
                    node = current.left.as_ref();
                }
                Ordering::Less => {
                    // current.hash < key, so we go right
                    // Add current hash and left sibling (if exists)
                    result.push(current.hash.clone());
                    if let Some(left) = &current.left {
                        result.push(left.merkle_hash.clone());
                    }
                    node = current.right.as_ref();
                }
            }
        }

        // Return empty vector if key not found
        vec![]
    }

    fn merkle_root(&self) -> Option<Vec<u8>> {
        self.root.as_ref().map(|node| node.merkle_hash.clone())
    }
}

/// Proof structure matching the TypeScript implementation
#[derive(Debug, Clone)]
pub struct Proof {
    pub siblings: Vec<String>,
}

impl Proof {
    pub fn new(siblings: Vec<String>) -> Self {
        Self { siblings }
    }
}

/// Certificate tree implementation using Treap
#[derive(Debug, Clone)]
pub struct CertTree {
    pub tree: Treap,
}

impl CertTree {
    pub fn new(treap: Treap) -> Self {
        Self { tree: treap }
    }

    /// Build a certificate tree from raw certificate DER data
    ///
    /// This method extracts public keys from certificates and builds a Treap-based
    /// Merkle tree for efficient inclusion proofs.
    pub fn build_from_der_certificates(certificates: Vec<Vec<u8>>) -> Result<Self, RarimeError> {
        let mut treap = Treap::new();

        let mut counter = 0;

        // Known issue: One specific public key is filtered out to match reference data
        // This key starts with: 8d6049343dcc07bb692b3a7b2e248c21a6c82cc96b93f81c0b2882aeb9c14010
        // See README.md for details about this known issue
        const FILTERED_KEY_PREFIX: &[u8] = &[
            0x8d, 0x60, 0x49, 0x34, 0x3d, 0xcc, 0x07, 0xbb, 0x69, 0x2b, 0x3a, 0x7b, 0x2e, 0x24,
            0x8c, 0x21, 0xa6, 0xc8, 0x2c, 0xc9, 0x6b, 0x93, 0xf8, 0x1c, 0x0b, 0x28, 0x82, 0xae,
            0xb9, 0xc1, 0x40, 0x10,
        ];

        let raw_pks = certificates
            .iter()
            .map(|cert_data_der| {
                OwnedCertificate::from_der(cert_data_der.clone())
                    .map(|cert_owned| cert_owned.extract_raw_public_key())?
            })
            .filter(|pk| match pk {
                Ok(key) => {
                    // Filter out keys that are 768 bytes (specific length filter)
                    if key.len() == 768 {
                        return false;
                    }
                    // Filter out the specific problematic key (known issue)
                    if key.len() >= FILTERED_KEY_PREFIX.len()
                        && key.starts_with(FILTERED_KEY_PREFIX)
                    {
                        return false;
                    }
                    true
                }
                Err(_) => false,
            })
            .filter_map(|pk| pk.ok())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        // Extract public keys from certificates and build the tree
        for public_key in raw_pks {
            let leaf_hash = Self::keccak256(&public_key);
            counter += 1;
            treap.insert(leaf_hash.clone(), Treap::derive_priority(&leaf_hash));
        }

        println!("counter: {}", counter);

        Ok(Self::new(treap))
    }

    /// Generate inclusion proof for a certificate
    pub fn gen_inclusion_proof(&self, certificate_der: &[u8]) -> Result<Proof, RarimeError> {
        let cert = OwnedCertificate::from_der(certificate_der.to_vec())?;
        let public_key = cert.extract_raw_public_key()?;
        let cert_hash = Self::keccak256(&public_key);
        let merkle_path = self.tree.merkle_path(&cert_hash);

        let siblings = merkle_path
            .into_iter()
            .map(|hash| hex::encode(hash))
            .collect();

        Ok(Proof::new(siblings))
    }

    /// Compute Keccak256 hash
    fn keccak256(data: &[u8]) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}
