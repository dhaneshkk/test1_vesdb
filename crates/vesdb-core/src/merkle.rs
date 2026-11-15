//! RFC 9162 Merkle trees.
//!
//! [`MerkleTree`] stores every complete, aligned subtree hash level by level, so the root of any
//! prefix and any inclusion or consistency proof costs O(log² n) hash look-ups instead of
//! rehashing the log. The free functions [`mth`], [`verify_inclusion`] and
//! [`verify_consistency`] are transcriptions of RFC 9162 §2.1 and of the Lean definitions.

use crate::{sha256, Hash};

pub fn leaf_hash(x: &[u8]) -> Hash {
    sha256(&[&[0x00], x])
}

pub fn node_hash(l: &Hash, r: &Hash) -> Hash {
    sha256(&[&[0x01], l, r])
}

pub fn empty_root() -> Hash {
    sha256(&[])
}

/// Largest power of two strictly less than `n` (n ≥ 2).
pub fn split(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (63 - (n - 1).leading_zeros())
}

/// MTH over a slice of LEAF HASHES (reference implementation, O(n)).
pub fn mth(lh: &[Hash]) -> Hash {
    match lh.len() {
        0 => empty_root(),
        1 => lh[0],
        n => {
            let k = split(n as u64) as usize;
            node_hash(&mth(&lh[..k]), &mth(&lh[k..]))
        }
    }
}

/// Append-only Merkle tree over leaf hashes.
#[derive(Clone, Debug, Default)]
pub struct MerkleTree {
    /// `levels[l][i]` = hash of the complete subtree covering leaves `[i·2^l, (i+1)·2^l)`.
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            levels: vec![Vec::new()],
        }
    }

    pub fn from_leaves(lh: impl IntoIterator<Item = Hash>) -> Self {
        let mut t = Self::new();
        for h in lh {
            t.push(h);
        }
        t
    }

    pub fn size(&self) -> u64 {
        self.levels[0].len() as u64
    }

    pub fn leaf(&self, i: u64) -> Option<Hash> {
        self.levels[0].get(i as usize).copied()
    }

    pub fn push(&mut self, leaf: Hash) {
        self.levels[0].push(leaf);
        let mut level = 0;
        loop {
            let len = self.levels[level].len();
            if len % 2 == 1 {
                break;
            }
            let h = node_hash(&self.levels[level][len - 2], &self.levels[level][len - 1]);
            if self.levels.len() == level + 1 {
                self.levels.push(Vec::new());
            }
            self.levels[level + 1].push(h);
            level += 1;
        }
    }

    /// Remove all leaves at index ≥ `n` (used only to model tampering in tests and recovery).
    /// Drop leaves `n..`. Level `l` holds only complete subtrees, so it keeps `n >> l` nodes.
    pub fn truncate(&mut self, n: u64) {
        assert!(n <= self.size());
        for (l, level) in self.levels.iter_mut().enumerate() {
            level.truncate((n >> l) as usize);
        }
        while self.levels.len() > 1 && self.levels.last().is_some_and(|v| v.is_empty()) {
            self.levels.pop();
        }
    }

    /// MTH of leaves `[lo, hi)`. Requires the RFC 9162 alignment that every recursive call from
    /// `[0, n)` satisfies.
    fn range(&self, lo: u64, hi: u64) -> Hash {
        let n = hi - lo;
        if n == 0 {
            return empty_root();
        }
        if n.is_power_of_two() && lo.is_multiple_of(n) {
            let l = n.trailing_zeros() as usize;
            return self.levels[l][(lo >> l) as usize];
        }
        let k = split(n);
        node_hash(&self.range(lo, lo + k), &self.range(lo + k, hi))
    }

    /// Root of the tree of the first `n` leaves.
    pub fn root_at(&self, n: u64) -> Hash {
        assert!(n <= self.size(), "tree size {} < {}", self.size(), n);
        self.range(0, n)
    }

    pub fn root(&self) -> Hash {
        self.root_at(self.size())
    }

    /// PATH(i, D[n]) (RFC 9162 §2.1.3.1).
    pub fn inclusion_proof(&self, i: u64, n: u64) -> Vec<Hash> {
        assert!(i < n && n <= self.size());
        let mut out = Vec::new();
        self.path(i, 0, n, &mut out);
        out
    }

    fn path(&self, i: u64, lo: u64, hi: u64, out: &mut Vec<Hash>) {
        let n = hi - lo;
        if n <= 1 {
            return;
        }
        let k = split(n);
        if i < k {
            self.path(i, lo, lo + k, out);
            out.push(self.range(lo + k, hi));
        } else {
            self.path(i - k, lo + k, hi, out);
            out.push(self.range(lo, lo + k));
        }
    }

    /// PROOF(m, D[n]) (RFC 9162 §2.1.4.1); empty when `m == 0` or `m == n`.
    pub fn consistency_proof(&self, m: u64, n: u64) -> Vec<Hash> {
        assert!(m <= n && n <= self.size());
        let mut out = Vec::new();
        if m > 0 && m < n {
            self.subproof(m, 0, n, true, &mut out);
        }
        out
    }

    fn subproof(&self, m: u64, lo: u64, hi: u64, b: bool, out: &mut Vec<Hash>) {
        let n = hi - lo;
        if m == n {
            if !b {
                out.push(self.range(lo, hi));
            }
            return;
        }
        let k = split(n);
        if m <= k {
            self.subproof(m, lo, lo + k, b, out);
            out.push(self.range(lo + k, hi));
        } else {
            self.subproof(m - k, lo + k, hi, false, out);
            out.push(self.range(lo, lo + k));
        }
    }
}

/// RFC 9162 §2.1.3.2.
pub fn verify_inclusion(index: u64, size: u64, leaf: &Hash, proof: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

/// RFC 9162 §2.1.4.2. `m == 0` (empty old tree) is consistent with everything.
pub fn verify_consistency(
    m: u64,
    n: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if m > n {
        return false;
    }
    if m == n {
        return proof.is_empty() && old_root == new_root;
    }
    if m == 0 {
        return proof.is_empty();
    }
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if m.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    let Some((first, rest)) = path.split_first() else {
        return false;
    };
    let (mut fn_, mut sn) = (m - 1, n - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (*first, *first);
    for c in rest {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    fr == *old_root && sr == *new_root && sn == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize, tag: u8) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(&[tag, (i & 0xff) as u8, (i >> 8) as u8]))
            .collect()
    }

    #[test]
    fn tree_matches_reference_mth() {
        for n in 0..300 {
            let lh = leaves(n, 1);
            let t = MerkleTree::from_leaves(lh.clone());
            for m in 0..=n {
                assert_eq!(t.root_at(m as u64), mth(&lh[..m]), "n={n} m={m}");
            }
        }
    }

    /// Lean: `inclusion_complete`, `inclusion_sound` (empirical).
    #[test]
    fn inclusion_complete_and_sound() {
        for n in 1..130u64 {
            let lh = leaves(n as usize, 2);
            let t = MerkleTree::from_leaves(lh.clone());
            let root = t.root();
            for i in 0..n {
                let p = t.inclusion_proof(i, n);
                assert!(verify_inclusion(i, n, &lh[i as usize], &p, &root));
                assert!(!verify_inclusion(i, n, &leaf_hash(b"forged"), &p, &root));
                for j in 0..p.len() {
                    let mut q = p.clone();
                    q[j][0] ^= 1;
                    assert!(!verify_inclusion(i, n, &lh[i as usize], &q, &root));
                }
            }
        }
    }

    /// Lean: `consistency_complete`, `consistency_sound` (empirical).
    #[test]
    fn consistency_complete_and_sound() {
        for n in 1..70u64 {
            let lh = leaves(n as usize, 3);
            let t = MerkleTree::from_leaves(lh.clone());
            for m in 0..=n {
                let p = t.consistency_proof(m, n);
                assert!(
                    verify_consistency(m, n, &t.root_at(m), &t.root(), &p),
                    "m={m} n={n}"
                );
                if 0 < m && m < n {
                    for k in [0, m / 2, m - 1] {
                        let mut bad = lh.clone();
                        bad[k as usize] = leaf_hash(b"tampered");
                        let bt = MerkleTree::from_leaves(bad);
                        assert!(!verify_consistency(
                            m,
                            n,
                            &t.root_at(m),
                            &bt.root(),
                            &bt.consistency_proof(m, n)
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn rollback_rejected() {
        let lh = leaves(20, 4);
        let t = MerkleTree::from_leaves(lh);
        assert!(!verify_consistency(
            20,
            10,
            &t.root_at(20),
            &t.root_at(10),
            &[]
        ));
    }
}
