use super::*;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use vesdb_core::merkle::verify_consistency;

fn cfg(dir: &Path) -> StoreConfig {
    StoreConfig {
        dir: dir.to_path_buf(),
        origin: "test.example/log".into(),
        system_source: "https://test.example".into(),
        pii_types: ["io.example.test.person-identified".to_string()]
            .into_iter()
            .collect(),
        key: HybridKey::from_seed("test.example/log", &[5; 32]),
    }
}

fn c(subject: &str, ty: &str, data: &str) -> Candidate {
    Candidate {
        source: "https://test.example".into(),
        subject: subject.into(),
        ty: format!("io.example.test.{ty}"),
        data: data.into(),
        traceparent: None,
        tracestate: None,
    }
}

#[test]
fn write_read_reopen() {
    let d = tempfile::tempdir().unwrap();
    {
        let mut s = Store::open(cfg(d.path())).unwrap();
        let (m, r) = s
            .write(
                10,
                vec![
                    c("/a", "x", r#"{"k":1}"#),
                    c("/a/b", "y", r#"{ "spaced" : true }"#),
                ],
                &[],
            )
            .unwrap();
        assert_eq!((m[0].id, m[1].id, r.size), (0, 1, 2));
        assert!(
            Store::open(cfg(d.path())).is_err(),
            "second server must not open a locked directory"
        );
    }
    let s = Store::open(cfg(d.path())).unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(
        s.event(1).unwrap().payload.unwrap().1,
        r#"{ "spaced" : true }"#,
        "payload bytes kept exactly"
    );
    assert_eq!(
        s.read_ids(
            "/a",
            &ReadOptions {
                recursive: true,
                ..Default::default()
            }
        )
        .unwrap(),
        vec![0, 1]
    );
    assert_eq!(s.read_ids("/a", &ReadOptions::default()).unwrap(), vec![0]);
    assert!(s.verify().unwrap().is_empty());
}

/// Lean: `append_extends`, `no_lost_update`, all-or-nothing.
#[test]
fn preconditions_and_atomicity() {
    let d = tempfile::tempdir().unwrap();
    let mut s = Store::open(cfg(d.path())).unwrap();
    let pristine = Precondition::IsSubjectPristine {
        subject: "/inc/1".into(),
        recursive: false,
    };
    s.write(
        1,
        vec![c("/inc/1", "raised", "{}")],
        std::slice::from_ref(&pristine),
    )
    .unwrap();
    assert!(matches!(
        s.write(2, vec![c("/inc/1", "raised", "{}")], &[pristine]),
        Err(StoreError::PreconditionViolated { .. })
    ));
    let on0 = Precondition::IsSubjectOnEventId {
        subject: "/inc/1".into(),
        event_id: 0,
        recursive: false,
    };
    s.write(
        3,
        vec![c("/inc/1", "ack", "{}")],
        std::slice::from_ref(&on0),
    )
    .unwrap();
    assert!(matches!(
        s.write(4, vec![c("/inc/1", "ack", "{}")], &[on0]),
        Err(StoreError::PreconditionViolated { .. })
    ));
    // a batch with one invalid event writes nothing
    let before = s.len();
    assert!(s
        .write(
            5,
            vec![c("/ok", "a", "{}"), c("bad subject", "b", "{}")],
            &[]
        )
        .is_err());
    assert_eq!(s.len(), before);
    // time is clamped monotone
    s.write(1, vec![c("/t", "a", "{}")], &[]).unwrap();
    assert!(s.meta(s.len() - 1).unwrap().time_ns >= 3);
}

#[test]
fn torn_tail_is_truncated_damage_is_refused() {
    let d = tempfile::tempdir().unwrap();
    {
        let mut s = Store::open(cfg(d.path())).unwrap();
        s.write(1, vec![c("/a", "x", "{}")], &[]).unwrap();
    }
    // torn write: half a frame at the end of events.log
    OpenOptions::new()
        .append(true)
        .open(d.path().join("events.log"))
        .unwrap()
        .write_all(&[0, 0, 0, 40, 1, 2])
        .unwrap();
    let s = Store::open(cfg(d.path())).unwrap();
    assert_eq!(s.len(), 1);
    drop(s);
    // damage in the middle: flip a byte in the first event frame, then append a valid frame after it
    {
        let mut s = Store::open(cfg(d.path())).unwrap();
        s.write(2, vec![c("/a", "y", "{}")], &[]).unwrap();
    }
    let p = d.path().join("events.log");
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[20] ^= 0xff;
    std::fs::write(&p, &bytes).unwrap();
    assert!(matches!(
        Store::open(cfg(d.path())),
        Err(StoreError::Damaged(_))
    ));
}

/// An attacker with disk access rewrites an event AND its CRC: the store opens, but the signed
/// receipts and checkpoints no longer match, so verify-store reports it.
#[test]
fn disk_edit_with_valid_crc_is_detected() {
    let d = tempfile::tempdir().unwrap();
    {
        let mut s = Store::open(cfg(d.path())).unwrap();
        s.write(1_000, vec![c("/inc", "detected", "{}")], &[])
            .unwrap();
        s.write(25_000, vec![c("/inc", "acknowledged", "{}")], &[])
            .unwrap();
        s.checkpoint(30_000).unwrap();
    }
    let p = d.path().join("events.log");
    let mut f = File::open(&p).unwrap();
    let scan = frames::scan(&mut f).unwrap();
    let mut out = Vec::new();
    for (i, fr) in scan.frames.iter().enumerate() {
        let mut m: EventMeta = serde_json::from_slice(&fr.body).unwrap();
        if i == 1 {
            m.time_ns = 2_000; // "the supervisor reacted at once"
        }
        out.extend(frames::encode(&serde_json::to_vec(&m).unwrap()));
    }
    std::fs::write(&p, out).unwrap();
    let s = Store::open(cfg(d.path())).unwrap();
    let findings = s.verify().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("history changed")),
        "{findings:?}"
    );
    assert!(s.audit(None).is_err());
}

#[test]
fn redaction_keeps_roots_and_receipts() {
    let d = tempfile::tempdir().unwrap();
    let mut s = Store::open(cfg(d.path())).unwrap();
    s.write(1, vec![c("/inc", "detected", r#"{"score":0.97}"#)], &[])
        .unwrap();
    let (p, _) = s
        .write(
            2,
            vec![c("/inc", "person-identified", r#"{"badge":"B-1187"}"#)],
            &[],
        )
        .unwrap();
    assert!(
        p[0].hash.starts_with("vesdb:leaf:v1:"),
        "pii types get no unsalted compat hash"
    );
    let cp = s.checkpoint(3).unwrap();
    let root_before = s.tree().root_at(cp.size);
    s.redact(4, &[p[0].id], "retention expired").unwrap();
    assert!(s.event(p[0].id).unwrap().payload.is_none());
    assert_eq!(s.tree().root_at(cp.size), root_before);
    let n = s.len();
    assert!(verify_consistency(
        cp.size,
        n,
        &cp.root,
        &s.tree().root(),
        &s.tree().consistency_proof(cp.size, n)
    ));
    assert!(s.verify().unwrap().is_empty());
    drop(s);
    let s = Store::open(cfg(d.path())).unwrap();
    assert!(
        s.event(1).unwrap().payload.is_none(),
        "redaction is durable"
    );
    let raw = std::fs::read(d.path().join("payloads.log")).unwrap();
    assert!(
        !raw.windows(6).any(|w| w == b"B-1187"),
        "erased bytes are gone from disk"
    );
}
