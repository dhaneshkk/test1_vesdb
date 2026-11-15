//! End-to-end: vesdb server + two witnesses, driven by the OFFICIAL `eventsourcingdb` Rust SDK
//! (4.1.4) for the compatible API and by plain HTTP for the transparency-log API.
//! Scenario: VisionGuard360 incident evidence (see the design doc), with a witness outage,
//! tampering attempts and day-90 redaction.

use axum::{extract::Request, http::StatusCode, middleware::Next, response::IntoResponse, Router};
use eventsourcingdb::{
    request_options::{ObserveEventsOptions, ReadEventsOptions},
    Client, EventCandidate, Precondition,
};
use futures::StreamExt;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vesdb_core::{
    bundle::{verify_bundle, Bundle},
    checkpoint::Checkpoint,
    crypto::{HybridKey, PublicKey},
    merkle::verify_consistency,
    witness::AddCheckpoint,
};
use vesdb_server::{new_app, router, spawn_checkpointer, Scope, ServerConfig, WitnessConfig};
use vesdb_store::{Candidate, Store, StoreConfig};

const ADMIN: &str = "admin-token-0123456789-0123456789-abcdef";
const WRITER: &str = "writer-token-0123456789-0123456789-abcdef";
const AUDITOR: &str = "auditor-token-0123456789-0123456789-abcdef";
const LOG_SEED: [u8; 32] = [7; 32];
const ORIGIN: &str = "rig-07.vg360.example/log";
const SRC: &str = "https://rig-07.vg360.example";
const INC: &str = "/rigs/rig-07/incidents/inc-0412";
const PII: &str = "ai.innoura.vg360.person-identified";

async fn serve(r: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    format!("http://{addr}")
}

struct TestWitness {
    url: String,
    key: PublicKey,
    offline: Arc<AtomicBool>,
    state_file: std::path::PathBuf,
}

async fn start_witness(name: &str, seed: u8, dir: &std::path::Path) -> TestWitness {
    let key = HybridKey::from_seed(name, &[seed; 32]);
    let pk = key.public();
    let log = HybridKey::from_seed(ORIGIN, &LOG_SEED).public();
    let state_file = dir.join(format!("{name}.json"));
    let w =
        Arc::new(vesdb_witness::Witness::new(key, vec![log], Some(state_file.clone())).unwrap());
    let offline = Arc::new(AtomicBool::new(false));
    let off = offline.clone();
    // test-only switch that simulates the satellite link being down
    let r = vesdb_witness::router(w).layer(axum::middleware::from_fn(
        move |req: Request, next: Next| {
            let off = off.clone();
            async move {
                if off.load(Ordering::SeqCst) {
                    return (StatusCode::SERVICE_UNAVAILABLE, "link down").into_response();
                }
                next.run(req).await
            }
        },
    ));
    TestWitness {
        url: serve(r).await,
        key: pk,
        offline,
        state_file,
    }
}

fn cand(subject: &str, ty: &str, data: Value) -> EventCandidate {
    EventCandidate::builder()
        .source(SRC)
        .subject(subject)
        .ty(format!("ai.innoura.vg360.{ty}"))
        .data(data)
        .build()
}

async fn cosigned(http: &reqwest::Client, base: &str) -> Option<Checkpoint> {
    let r = http
        .get(format!("{base}/tlog/checkpoint"))
        .send()
        .await
        .unwrap();
    if r.status().is_success() {
        Some(r.json().await.unwrap())
    } else {
        None
    }
}

async fn wait_cosigned(http: &reqwest::Client, base: &str, size: u64) -> Checkpoint {
    for _ in 0..200 {
        if let Some(cp) = cosigned(http, base).await {
            if cp.size >= size {
                return cp;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no cosigned checkpoint of size >= {size}");
}

async fn bundle(http: &reqwest::Client, base: &str, ids: &[u64], size: Option<u64>) -> Bundle {
    let ids: Vec<String> = ids.iter().map(u64::to_string).collect();
    let r = http
        .request(
            reqwest::Method::from_bytes(b"QUERY").unwrap(),
            format!("{base}/api/v2/tlog/bundle"),
        )
        .bearer_auth(AUDITOR)
        .json(&json!({"ids": ids, "checkpointSize": size}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "bundle: {}", r.status());
    r.json().await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vg360_incident_evidence_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let hse = start_witness("hse.operator.example", 11, dir.path()).await;
    let innoura = start_witness("witness.innoura.example", 12, dir.path()).await;
    let witness_keys = vec![hse.key.clone(), innoura.key.clone()];

    let mut tokens: HashMap<String, BTreeSet<Scope>> = HashMap::new();
    tokens.insert(ADMIN.into(), [Scope::Admin].into());
    tokens.insert(WRITER.into(), [Scope::Read, Scope::Write].into());
    tokens.insert(AUDITOR.into(), [Scope::Read, Scope::Audit].into());
    let store = Store::open(StoreConfig {
        dir: dir.path().join("data"),
        origin: ORIGIN.into(),
        system_source: SRC.into(),
        pii_types: [PII.to_string()].into(),
        key: HybridKey::from_seed(ORIGIN, &LOG_SEED),
    })
    .unwrap();
    let app = new_app(
        store,
        ServerConfig {
            tokens,
            witnesses: vec![
                WitnessConfig {
                    url: hse.url.clone(),
                    key: hse.key.clone(),
                },
                WitnessConfig {
                    url: innoura.url.clone(),
                    key: innoura.key.clone(),
                },
            ],
            quorum: 2,
            checkpoint_interval: Duration::from_millis(100),
            checkpoint_max_events: 4096,
            compat_server_header: true,
            compat_signatures: true,
            compat_key: Some(HybridKey::from_seed(ORIGIN, &LOG_SEED)),
            ts: None,
        },
    );
    spawn_checkpointer(app.clone());
    let base = serve(router(app.clone())).await;
    let http = reqwest::Client::new();
    let log_key = HybridKey::from_seed(ORIGIN, &LOG_SEED).public();
    let ed_vk =
        ed25519_dalek::VerifyingKey::from_bytes(&log_key.ed25519.clone().try_into().unwrap())
            .unwrap();

    // ---- official SDK: ping, token, writes with preconditions -----------------------------
    let client = Client::new(url::Url::parse(&base).unwrap(), WRITER);
    client.ping().await.expect("SDK ping");
    client.verify_api_token().await.expect("SDK verify token");

    let model = client
        .write_events(
            vec![cand("/rigs/rig-07/models/hazard", "model-deployed", json!({"model_sha256": "ab".repeat(32), "mcc": 0.8397, "training": {"optimizer": "SAM", "rho": 0.05}}))],
            vec![Precondition::is_subject_pristine("/rigs/rig-07/models/hazard", None)],
        )
        .await
        .expect("model-deployed");
    assert_eq!(model[0].id(), "0");

    let det = client
        .write_events(
            vec![EventCandidate::builder()
                .source(SRC)
                .subject(INC)
                .ty("ai.innoura.vg360.hazard-detected")
                .data(json!({"camera": "cam-12", "class": "no-harness-at-height", "score": 0.97}))
                .traceinfo(eventsourcingdb::TraceInfo::Traceparent {
                    traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into(),
                })
                .build()],
            vec![Precondition::is_subject_pristine(INC, None)],
        )
        .await
        .expect("hazard-detected")
        .remove(0);
    let clip = vec![42u8; 200_000];
    let clip_sha = hex::encode(<sha2_shim::Sha256>::digest(&clip));
    let ev2 = client
        .write_events(
            vec![
                cand(INC, "clip-sealed", json!({"sha256": clip_sha, "codec": "av1", "seconds": 20})),
                cand(INC, "alert-raised", json!({"rule": "IOGP-LSR-working-at-height", "severity": "critical", "detection_id": det.id()})),
            ],
            vec![Precondition::is_subject_on_event_id(INC, det.id(), None)],
        )
        .await
        .expect("clip + alert");
    let person = client
        .write_events(
            vec![cand(
                INC,
                "person-identified",
                json!({"badge": "B-1187", "name": "A. Worker (synthetic)"}),
            )],
            vec![Precondition::is_subject_on_event_id(INC, ev2[1].id(), None)],
        )
        .await
        .expect("person")
        .remove(0);
    let ack = client
        .write_events(
            vec![cand(
                INC,
                "alert-acknowledged",
                json!({"role": "control-room supervisor", "action": "stop-work"}),
            )],
            vec![Precondition::is_subject_on_event_id(INC, person.id(), None)],
        )
        .await
        .expect("ack")
        .remove(0);
    // a second supervisor acting on the same stale read must be refused (Lean: no_lost_update)
    let stale = client
        .write_events(
            vec![cand(
                INC,
                "alert-acknowledged",
                json!({"role": "second supervisor"}),
            )],
            vec![Precondition::is_subject_on_event_id(INC, person.id(), None)],
        )
        .await;
    assert!(stale.is_err(), "stale acknowledgement must be refused");

    // ---- official SDK: read back, verify hashes and signatures --------------------------------
    let mut stream = client
        .read_events(
            "/rigs/rig-07",
            Some(ReadEventsOptions {
                recursive: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    let mut n_read = 0;
    while let Some(ev) = stream.next().await {
        let ev = ev.expect("read event");
        n_read += 1;
        if ev.ty() == PII {
            assert!(
                ev.verify_hash().is_err(),
                "personal-data events carry no unsalted compat hash"
            );
        } else {
            ev.verify_hash()
                .unwrap_or_else(|e| panic!("SDK verify_hash failed for #{}: {e}", ev.id()));
            ev.verify_signature(&ed_vk)
                .unwrap_or_else(|e| panic!("SDK verify_signature failed for #{}: {e}", ev.id()));
        }
    }
    assert_eq!(n_read, 6);

    // ---- official SDK: observe history then live --------------------------------------------
    let mut obs = client
        .observe_events(
            INC,
            Some(ObserveEventsOptions {
                recursive: false,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    let mut seen = Vec::new();
    for _ in 0..5 {
        seen.push(obs.next().await.unwrap().unwrap().id().to_string());
    }
    let stop = client
        .write_events(
            vec![cand(
                INC,
                "stop-work-issued",
                json!({"scope": "drill floor", "issuer_role": "OIM"}),
            )],
            vec![Precondition::is_subject_on_event_id(INC, ack.id(), None)],
        )
        .await
        .unwrap()
        .remove(0);
    let live = tokio::time::timeout(Duration::from_secs(5), obs.next())
        .await
        .expect("live event")
        .unwrap()
        .unwrap();
    assert_eq!(
        live.id(),
        stop.id(),
        "observer gets the live event after history"
    );
    drop(obs);

    // ---- official SDK: EventQL (compiled to DataFusion) ----------------------------------------
    let mut rows = client
        .run_eventql_query(&format!(
            r#"FROM e IN events WHERE e.subject == "{INC}" GROUP BY e.type PROJECT INTO {{ type: UNIQUE(e.type), n: COUNT() }}"#
        ))
        .await
        .expect("eventql query");
    let mut per_type = Vec::new();
    while let Some(r) = rows.next().await {
        per_type.push(r.expect("row"));
    }
    assert_eq!(
        per_type[0],
        json!({"type": "ai.innoura.vg360.hazard-detected", "n": 1}),
        "groups in order of first row"
    );
    assert_eq!(per_type.len(), 6);
    let mut lat = client
        .run_eventql_query(&format!(
            r#"FROM d IN events FROM a IN events
               WHERE d.subject == "{INC}" AND a.subject == "{INC}"
                 AND d.type == "ai.innoura.vg360.hazard-detected" AND a.type == "ai.innoura.vg360.alert-acknowledged"
               PROJECT INTO {{ detected: d.id, acknowledged: a.id, ordered: (d.id AS INT) < (a.id AS INT) }}"#
        ))
        .await
        .unwrap();
    let pair = lat.next().await.unwrap().unwrap();
    assert_eq!(pair["ordered"], true, "evidence_order via EventQL: {pair}");

    // ---- dynamic consistency boundary: one acknowledgement per incident, whatever the subject -----
    let once = format!(
        r#"FROM e IN events WHERE e.type == "ai.innoura.vg360.alert-acknowledged" AND e.data.incident != NULL AND e.data.incident == "{INC}" PROJECT INTO COUNT() == 0"#
    );
    client
        .write_events(
            vec![cand(
                "/rigs/rig-07/shift-log",
                "alert-acknowledged",
                json!({"incident": INC, "via": "shift log"}),
            )],
            vec![Precondition::is_eventql_query_true(once.clone())],
        )
        .await
        .expect("first acknowledgement through another subject passes the DCB rule");
    let second = client
        .write_events(
            vec![cand(
                "/rigs/rig-07/radio-log",
                "alert-acknowledged",
                json!({"incident": INC, "via": "radio"}),
            )],
            vec![Precondition::is_eventql_query_true(once)],
        )
        .await;
    assert!(
        second.is_err(),
        "DCB rule refuses a second acknowledgement on a different subject"
    );
    let bad = client
        .write_events(
            vec![cand("/x", "zone-status", json!({}))],
            vec![Precondition::is_eventql_query_true(
                "FROM e IN events PROJECT INTO e.id",
            )],
        )
        .await;
    assert!(
        bad.is_err(),
        "a precondition query must return exactly one boolean"
    );

    // ---- scoped tokens -------------------------------------------------------------------------
    let q = reqwest::Method::from_bytes(b"QUERY").unwrap();
    let r = http
        .request(q.clone(), format!("{base}/api/v2/tlog/bundle"))
        .bearer_auth(WRITER)
        .json(&json!({"ids": ["0"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "writer token cannot export evidence");
    let r = http
        .post(format!("{base}/api/v2/data/write-events"))
        .bearer_auth(AUDITOR)
        .json(&json!({"events": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "auditor token cannot write");

    // ---- witnesses cosign; evidence bundle verifies offline -------------------------------------
    let incident_size = stop.id().parse::<u64>().unwrap() + 1;
    let cp1 = wait_cosigned(&http, &base, incident_size).await;
    let ids: Vec<u64> = [
        model[0].id(),
        det.id(),
        ev2[0].id(),
        ev2[1].id(),
        ack.id(),
        stop.id(),
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    let b1 = bundle(&http, &base, &ids, Some(cp1.size)).await;
    let rep = verify_bundle(&b1, &log_key, &witness_keys, 2);
    assert!(rep.ok, "insurer bundle: {:?}", rep.problems);
    let clip_event = b1
        .items
        .iter()
        .find(|i| i.event.ty.ends_with("clip-sealed"))
        .unwrap();
    let clip_field: Value = serde_json::from_str(clip_event.data.as_ref().unwrap()).unwrap();
    assert_eq!(clip_field["sha256"], clip_sha.as_str());
    let d = b1
        .items
        .iter()
        .find(|i| i.event.ty.ends_with("hazard-detected"))
        .unwrap();
    let a = b1
        .items
        .iter()
        .find(|i| i.event.ty.ends_with("alert-acknowledged"))
        .unwrap();
    assert!(
        d.event.id < a.event.id && d.event.time_ns <= a.event.time_ns,
        "evidence_order"
    );

    // ---- satellite outage: one witness unreachable, events keep landing ---------------------------
    hse.offline.store(true, Ordering::SeqCst);
    let mut last_id = stop.id().to_string();
    for i in 0..24 {
        let e = client
            .write_events(
                vec![cand(
                    "/rigs/rig-07/zones/drill-floor",
                    "zone-status",
                    json!({"state": "stopped", "link": "down", "i": i}),
                )],
                vec![],
            )
            .await
            .unwrap();
        last_id = e[0].id().to_string();
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    let during = cosigned(&http, &base).await.unwrap();
    assert!(
        during.size < last_id.parse::<u64>().unwrap() + 1,
        "no quorum while a witness is down"
    );
    hse.offline.store(false, Ordering::SeqCst);
    let after = wait_cosigned(&http, &base, last_id.parse::<u64>().unwrap() + 1).await;
    let wstate: Value = serde_json::from_slice(&std::fs::read(&hse.state_file).unwrap()).unwrap();
    assert_eq!(
        wstate["latest"][ORIGIN]["size"], after.size,
        "HSE witness caught up with ONE consistency proof"
    );
    let r: Value = http
        .request(q.clone(), format!("{base}/api/v2/tlog/consistency"))
        .bearer_auth(AUDITOR)
        .json(&json!({"from": cp1.size, "to": after.size}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let proof: Vec<[u8; 32]> = r["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            vesdb_core::b64::decode(x.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    assert!(verify_consistency(
        cp1.size,
        after.size,
        &cp1.root,
        &after.root,
        &proof
    ));

    // ---- tampering: operator with the log key rewrites history and re-signs ---------------------
    let forged_dir = tempfile::tempdir().unwrap();
    let mut forged = Store::open(StoreConfig {
        dir: forged_dir.path().to_path_buf(),
        origin: ORIGIN.into(),
        system_source: SRC.into(),
        pii_types: [PII.to_string()].into(),
        key: HybridKey::from_seed(ORIGIN, &LOG_SEED),
    })
    .unwrap();
    for i in 0..=after.size {
        let ty = if i == 5 {
            "ai.innoura.vg360.alert-acknowledged"
        } else {
            "ai.innoura.vg360.zone-status"
        };
        forged
            .write(
                1_000 + i,
                vec![Candidate {
                    source: SRC.into(),
                    subject: INC.into(),
                    ty: ty.into(),
                    data: r#"{"forged":true}"#.into(),
                    traceparent: None,
                    tracestate: None,
                }],
                &[],
            )
            .unwrap();
    }
    let fcp = forged.checkpoint(9_999).unwrap();
    for w in [&hse, &innoura] {
        let size = serde_json::from_slice::<Value>(&std::fs::read(&w.state_file).unwrap()).unwrap()
            ["latest"][ORIGIN]["size"]
            .as_u64()
            .unwrap();
        let req = AddCheckpoint {
            old_size: size,
            proof: forged.tree().consistency_proof(size, fcp.size),
            checkpoint: fcp.clone(),
        };
        let r = http
            .post(format!("{}/add-checkpoint", w.url))
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            422,
            "witness must refuse a rewritten history: {}",
            r.text().await.unwrap()
        );
    }
    // rollback to before the acknowledgement
    let mut short = Store::open(StoreConfig {
        dir: tempfile::tempdir().unwrap().keep(),
        origin: ORIGIN.into(),
        system_source: SRC.into(),
        pii_types: Default::default(),
        key: HybridKey::from_seed(ORIGIN, &LOG_SEED),
    })
    .unwrap();
    short
        .write(
            1,
            vec![Candidate {
                source: SRC.into(),
                subject: INC.into(),
                ty: "ai.innoura.vg360.zone-status".into(),
                data: "{}".into(),
                traceparent: None,
                tracestate: None,
            }],
            &[],
        )
        .unwrap();
    let scp = short.checkpoint(2).unwrap();
    let r = http
        .post(format!("{}/add-checkpoint", innoura.url))
        .json(&AddCheckpoint {
            old_size: 0,
            proof: vec![],
            checkpoint: scp,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422, "witness must refuse a rollback");

    // ---- day 90: redact the worker's identity ----------------------------------------------------
    let r: Value = serde_json::from_str(
        http.post(format!("{base}/api/v2/management/redact-events"))
            .bearer_auth(ADMIN)
            .json(&json!({"ids": [person.id()], "reason": "retention expired"}))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r["type"], "redacted");
    assert!(
        verify_bundle(&b1, &log_key, &witness_keys, 2).ok,
        "bundle exported before redaction still verifies"
    );
    let size_now = app.store.lock().unwrap().len();
    let cp90 = wait_cosigned(&http, &base, size_now).await;
    let pid: u64 = person.id().parse().unwrap();
    let b2 = bundle(
        &http,
        &base,
        &[pid, ack.id().parse().unwrap()],
        Some(cp90.size),
    )
    .await;
    let rep2 = verify_bundle(&b2, &log_key, &witness_keys, 2);
    assert!(
        rep2.ok && rep2.items[0].redacted,
        "redacted event still provable: {:?}",
        rep2
    );
    let mut s = client.read_events(INC, None).await.unwrap();
    while let Some(ev) = s.next().await {
        let ev = ev.unwrap();
        if ev.id() == person.id() {
            assert!(ev.data().is_null(), "payload erased");
        }
    }
    let raw = std::fs::read(dir.path().join("data/payloads.log")).unwrap();
    assert!(
        !raw.windows(6).any(|w| w == b"B-1187"),
        "badge id gone from disk"
    );

    // ---- verify-store and audit-history -----------------------------------------------------------
    let vs = http
        .post(format!("{base}/api/v2/management/verify-store"))
        .bearer_auth(AUDITOR)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        vs.trim(),
        r#"{"type":"end","data":{}}"#,
        "no findings: {vs}"
    );
    let au = http
        .post(format!("{base}/api/v2/management/audit-history"))
        .bearer_auth(AUDITOR)
        .json(&json!({"lastAuditedEvent": null}))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let anchor: Value = serde_json::from_str(au.lines().next().unwrap()).unwrap();
    assert_eq!(anchor["type"], "lastAuditedEvent");
    let au2 = http
        .post(format!("{base}/api/v2/management/audit-history"))
        .bearer_auth(AUDITOR)
        .json(&json!({"lastAuditedEvent": anchor["data"]}))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(au2.starts_with(r#"{"type":"lastAuditedEvent""#), "{au2}");

    println!(
        "e2e ok: {} events, cosigned size {}, witnesses {:?}, outage proof {} hashes",
        size_now,
        cp90.size,
        cp90.cosigs.keys().collect::<Vec<_>>(),
        proof.len()
    );
}

mod sha2_shim {
    pub struct Sha256;
    impl Sha256 {
        pub fn digest(b: &[u8]) -> [u8; 32] {
            vesdb_core::sha256(&[b])
        }
    }
}
