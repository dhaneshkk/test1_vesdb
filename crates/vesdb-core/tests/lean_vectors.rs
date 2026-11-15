//! Differential test against the Lean definitions that `consistency_sound` is proved about.
//!
//! `lean/Vectors.lean` evaluates the Lean `mth`, `consistencyProof`, `verifyConsistency`,
//! `inclusionProof` and `verifyInclusion` with real SHA-256 for every tree of up to 32 leaves, and
//! records the verdict for honest and tampered inputs. The Rust implementation must produce the
//! same roots and proofs and reach the same verdict in every case. This is exhaustive testing over
//! small trees, not a proof of equivalence.

use serde_json::Value;
use vesdb_core::merkle::{leaf_hash, verify_consistency, verify_inclusion, MerkleTree};
use vesdb_core::Hash;

fn h32(s: &str) -> Hash {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn hashes(v: &Value) -> Vec<Hash> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| h32(x.as_str().unwrap()))
        .collect()
}

fn tweak(mut h: Hash) -> Hash {
    h[0] ^= 1;
    h
}

/// Leaf `i` is the two bytes `[i / 256, i % 256]`, as in `Vectors.lean`.
fn tree(n: usize) -> MerkleTree {
    MerkleTree::from_leaves((0..n).map(|i| leaf_hash(&[(i / 256) as u8, (i % 256) as u8])))
}

#[test]
fn rust_agrees_with_the_lean_definitions() {
    let v: Value = serde_json::from_str(include_str!("lean_vectors.json")).unwrap();
    let big = v["N"].as_u64().unwrap() as usize;
    let roots = hashes(&v["roots"]);
    let t = tree(big + 1);
    for (n, r) in roots.iter().enumerate() {
        assert_eq!(
            t.root_at(n as u64),
            *r,
            "root of {n} leaves differs from Lean mth"
        );
    }
    let root = |k: u64| roots.get(k as usize).copied().unwrap_or([0; 32]);
    let mut checked = 0usize;

    for p in v["consistency"].as_array().unwrap() {
        let (m, n) = (p["m"].as_u64().unwrap(), p["n"].as_u64().unwrap());
        let proof = hashes(&p["proof"]);
        assert_eq!(
            t.consistency_proof(m, n),
            proof,
            "consistency proof ({m}, {n})"
        );
        for c in p["cases"].as_array().unwrap() {
            let (kind, want) = (
                c["kind"].as_str().unwrap(),
                c["expected"].as_bool().unwrap(),
            );
            let (mut mm, mut nn, mut old, mut new, mut q) = (m, n, root(m), root(n), proof.clone());
            match kind {
                "honest" => {}
                "flip" => {
                    let i = c["at"].as_u64().unwrap() as usize;
                    q[i] = tweak(q[i]);
                }
                "drop" => {
                    q.pop();
                }
                "extra" => q.push([0; 32]),
                "dup" => {
                    if let Some(&f) = proof.first() {
                        q.insert(0, f);
                    }
                }
                "old" => old = tweak(old),
                "new" => new = tweak(new),
                "m+1" => mm += 1,
                "n+1" => nn += 1,
                "m-1" => mm = mm.saturating_sub(1),
                k => panic!("unknown case {k}"),
            }
            let got = verify_consistency(mm, nn, &old, &new, &q);
            assert_eq!(
                got,
                want,
                "consistency ({m}, {n}) case {kind} {:?}",
                c.get("at")
            );
            checked += 1;
        }
    }

    for p in v["inclusion"].as_array().unwrap() {
        let (i, n) = (p["i"].as_u64().unwrap(), p["n"].as_u64().unwrap());
        let proof = hashes(&p["proof"]);
        assert_eq!(t.inclusion_proof(i, n), proof, "inclusion proof ({i}, {n})");
        let leaf = t.leaf(i).unwrap();
        for c in p["cases"].as_array().unwrap() {
            let (kind, want) = (
                c["kind"].as_str().unwrap(),
                c["expected"].as_bool().unwrap(),
            );
            let (mut ii, mut nn, mut lf, mut rt, mut q) = (i, n, leaf, root(n), proof.clone());
            match kind {
                "honest" => {}
                "flip" => {
                    let j = c["at"].as_u64().unwrap() as usize;
                    q[j] = tweak(q[j]);
                }
                "drop" => {
                    q.pop();
                }
                "extra" => q.push([0; 32]),
                "leaf" => lf = tweak(lf),
                "root" => rt = tweak(rt),
                "i+1" => ii += 1,
                "i-1" => ii = ii.saturating_sub(1),
                "n+1" => nn += 1,
                "n-1" => nn = nn.saturating_sub(1),
                k => panic!("unknown case {k}"),
            }
            let got = verify_inclusion(ii, nn, &lf, &q, &rt);
            assert_eq!(
                got,
                want,
                "inclusion ({i}, {n}) case {kind} {:?}",
                c.get("at")
            );
            checked += 1;
        }
    }
    assert!(checked > 14_000, "{checked} cases");
    eprintln!(
        "Rust agrees with Lean on {} roots and {checked} verdicts",
        roots.len()
    );
}
