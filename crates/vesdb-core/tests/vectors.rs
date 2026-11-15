//! Cross-implementation test vectors produced by the Python reference in the
//! `vesdb_vg360_incident_evidence_demo.ipynb` notebook. Rust must reproduce them byte for byte.

use serde_json::Value;
use vesdb_core::encoding::{commitment, compat_hash_v2, EventMeta};
use vesdb_core::merkle::{verify_consistency, verify_inclusion, MerkleTree};

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn python_reference_vectors() {
    let v: Value = serde_json::from_str(include_str!("vectors_python.json")).unwrap();
    let leaves: Vec<[u8; 32]> = v["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| h32(x.as_str().unwrap()))
        .collect();
    for (i, l) in leaves.iter().enumerate() {
        assert_eq!(*l, vesdb_core::merkle::leaf_hash(&[i as u8]));
    }
    let tree = MerkleTree::from_leaves(leaves.clone());
    for (n, r) in v["roots"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            hex::encode(tree.root_at(n as u64)),
            r.as_str().unwrap(),
            "root n={n}"
        );
    }
    let root37 = tree.root_at(37);
    for (i, p) in v["inclusion_n37"].as_array().unwrap().iter().enumerate() {
        let want: Vec<String> = p
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        let got: Vec<String> = tree
            .inclusion_proof(i as u64, 37)
            .iter()
            .map(hex::encode)
            .collect();
        assert_eq!(got, want, "inclusion i={i}");
        assert!(verify_inclusion(
            i as u64,
            37,
            &leaves[i],
            &tree.inclusion_proof(i as u64, 37),
            &root37
        ));
    }
    for (m, p) in v["consistency_n37"].as_array().unwrap().iter().enumerate() {
        let want: Vec<String> = p
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        let got: Vec<String> = tree
            .consistency_proof(m as u64, 37)
            .iter()
            .map(hex::encode)
            .collect();
        assert_eq!(got, want, "consistency m={m}");
        assert!(verify_consistency(
            m as u64,
            37,
            &tree.root_at(m as u64),
            &root37,
            &tree.consistency_proof(m as u64, 37)
        ));
    }

    let e = &v["event"];
    let salt = h32(e["salt"].as_str().unwrap());
    let data = e["data"].as_str().unwrap().as_bytes();
    let meta = EventMeta {
        id: e["id"].as_u64().unwrap(),
        time_ns: e["time_ns"].as_u64().unwrap(),
        source: e["source"].as_str().unwrap().into(),
        subject: e["subject"].as_str().unwrap().into(),
        ty: e["type"].as_str().unwrap().into(),
        traceparent: Some(e["traceparent"].as_str().unwrap().into()),
        tracestate: None,
        commit: commitment(&salt, data),
        predecessorhash: e["predecessorhash"].as_str().unwrap().into(),
        hash: String::new(),
    };
    assert_eq!(hex::encode(meta.commit), e["commit"].as_str().unwrap());
    assert_eq!(hex::encode(meta.enc()), e["enc"].as_str().unwrap());
    assert_eq!(hex::encode(meta.leaf()), e["leaf"].as_str().unwrap());
    let _ = compat_hash_v2; // compat hash is checked against the vendor vectors below
}

/// The three v2 events from the official `eventsourcingdb` 4.1.4 SDK's own tests (MIT): our compat
/// hash must reproduce EventSourcingDB's hashes exactly.
#[test]
fn eventsourcingdb_sdk_vectors() {
    let v: Value = serde_json::from_str(include_str!("vectors_esdb_sdk.json")).unwrap();
    for ev in v.as_array().unwrap() {
        let raw: &str = ev["raw"].as_str().unwrap();
        let full: Value = serde_json::from_str(raw).unwrap();
        // exact data bytes as they appear in the event JSON
        let rv: std::collections::HashMap<String, Box<serde_json::value::RawValue>> =
            serde_json::from_str(raw).unwrap();
        let data = rv["data"].get();
        let meta = EventMeta {
            id: full["id"].as_str().unwrap().parse().unwrap(),
            time_ns: vesdb_core::time::parse_rfc3339_ns(full["time"].as_str().unwrap()).unwrap(),
            source: full["source"].as_str().unwrap().into(),
            subject: full["subject"].as_str().unwrap().into(),
            ty: full["type"].as_str().unwrap().into(),
            traceparent: full
                .get("traceparent")
                .and_then(|x| x.as_str())
                .map(Into::into),
            tracestate: full
                .get("tracestate")
                .and_then(|x| x.as_str())
                .map(Into::into),
            commit: [0; 32],
            predecessorhash: full["predecessorhash"].as_str().unwrap().into(),
            hash: String::new(),
        };
        assert_eq!(
            compat_hash_v2(&meta, data.as_bytes()),
            full["hash"].as_str().unwrap(),
            "event {}",
            meta.id
        );
    }
}
