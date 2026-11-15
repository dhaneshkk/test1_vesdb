//! Time series end to end over HTTP: a rig's H2S sensor at 1 Hz, sealed into the witnessed log,
//! queried raw and per minute, one reading proven offline, a rewritten chunk detected, retention
//! applied, and a restart that recovers unsealed points.

use axum::Router;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use vesdb_core::{
    crypto::{HybridKey, PublicKey},
    time::rfc3339_ns,
    ts::{verify_point_proof, PointProof},
};
use vesdb_server::{router, spawn_checkpointer, try_new_app, Scope, ServerConfig, WitnessConfig};
use vesdb_store::{Store, StoreConfig};
use vesdb_ts::TsConfig;

const ADMIN: &str = "admin-token-0123456789-0123456789-abcdef";
const ORIGIN: &str = "rig-07.vg360.example/log";
const SEED: [u8; 32] = [7; 32];
const S: i64 = 1_000_000_000;
const T0: i64 = 1_762_000_020 * S; // minute boundary
const H2S: &str = "rig-07/gas/h2s";

struct Server {
    url: String,
    stop: tokio::sync::oneshot::Sender<()>,
    done: tokio::task::JoinHandle<()>,
    cp: tokio::task::JoinHandle<()>,
}

async fn start(dir: &Path, witness: &(String, PublicKey)) -> Server {
    let store = Store::open(StoreConfig {
        dir: dir.to_path_buf(),
        origin: ORIGIN.into(),
        system_source: "https://rig-07.vg360.example".into(),
        pii_types: Default::default(),
        key: HybridKey::from_seed(ORIGIN, &SEED),
    })
    .unwrap();
    let mut tokens: HashMap<String, BTreeSet<Scope>> = HashMap::new();
    tokens.insert(ADMIN.into(), [Scope::Admin].into_iter().collect());
    let app = try_new_app(
        store,
        ServerConfig {
            tokens,
            witnesses: vec![WitnessConfig {
                url: witness.0.clone(),
                key: witness.1.clone(),
            }],
            quorum: 1,
            checkpoint_interval: Duration::from_millis(100),
            checkpoint_max_events: 4096,
            compat_server_header: true,
            compat_signatures: false,
            compat_key: None,
            ts: Some(TsConfig {
                fsync: false,
                ..TsConfig::new(dir.join("ts"))
            }),
        },
    )
    .unwrap();
    let cp = spawn_checkpointer(app.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let r: Router = router(app);
    let done = tokio::spawn(async move {
        axum::serve(l, r)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap()
    });
    Server {
        url,
        stop,
        done,
        cp,
    }
}

impl Server {
    async fn shutdown(self) {
        self.cp.abort();
        let _ = self.cp.await;
        let _ = self.stop.send(());
        self.done.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn post(url: &str, path: &str, body: Value) -> (u16, Value) {
    let r = reqwest::Client::new()
        .post(format!("{url}{path}"))
        .bearer_auth(ADMIN)
        .json(&body)
        .send()
        .await
        .unwrap();
    let code = r.status().as_u16();
    let text = r.text().await.unwrap();
    (
        code,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// 1 Hz H2S around 2 ppm with a 14.2 ppm spike at minute 1, second 37.
fn readings(from_s: i64, n: i64) -> (Vec<Value>, Vec<f64>) {
    let mut t = Vec::new();
    let mut v = Vec::new();
    for i in from_s..from_s + n {
        // mix integer ns, decimal strings and RFC 3339
        t.push(match i % 3 {
            0 => json!(T0 + i * S),
            1 => json!((T0 + i * S).to_string()),
            _ => json!(rfc3339_ns((T0 + i * S) as u64)),
        });
        v.push(if i == 97 {
            14.2
        } else {
            2.0 + ((i % 7) as f64) / 10.0
        });
    }
    (t, v)
}

fn chunk_files(dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for d in std::fs::read_dir(dir.join("ts/chunks")).unwrap() {
        for f in std::fs::read_dir(d.unwrap().path()).unwrap() {
            v.push(f.unwrap().path());
        }
    }
    v.sort();
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn time_series_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("db");
    // one witness
    let wkey = HybridKey::from_seed("witness-a", &[11; 32]);
    let wpub = wkey.public();
    let log_pub = HybridKey::from_seed(ORIGIN, &SEED).public();
    let w = Arc::new(vesdb_witness::Witness::new(wkey, vec![log_pub.clone()], None).unwrap());
    let wl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wurl = format!("http://{}", wl.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(wl, vesdb_witness::router(w)).await.unwrap() });
    let witness = (wurl, wpub.clone());

    let srv = start(&dir, &witness).await;
    let u = srv.url.clone();

    // ---- write 3 minutes in two requests, the second one out of order
    let (t1, v1) = readings(0, 120);
    let (mut t2, mut v2) = readings(120, 60);
    t2.reverse();
    v2.reverse();
    let (c, r) = post(
        &u,
        "/api/v2/ts/write",
        json!({ "series": [{ "name": H2S, "times": t1, "values": v1 }] }),
    )
    .await;
    assert_eq!((c, r["accepted"].as_u64()), (200, Some(120)), "{r}");
    let (c, _) = post(
        &u,
        "/api/v2/ts/write",
        json!({ "series": [{ "name": H2S, "times": t2, "values": v2 }] }),
    )
    .await;
    assert_eq!(c, 200);
    // bad input
    let (c, r) = post(
        &u,
        "/api/v2/ts/write",
        json!({ "series": [{ "name": "rig 07", "times": [T0], "values": [1.0] }] }),
    )
    .await;
    assert_eq!((c, r["error"].as_str()), (400, Some("invalid-argument")));

    // ---- seal: one chunk event per minute
    let (c, r) = post(&u, "/api/v2/ts/flush", json!({})).await;
    assert_eq!(c, 200, "{r}");
    let sealed = r["sealed"].as_array().unwrap().clone();
    assert_eq!(sealed.len(), 3);
    assert!(sealed.iter().all(|s| s["count"] == 60));

    // ---- queries: raw (sealed points, sorted) and per minute
    let (c, r) = post(
        &u,
        "/api/v2/ts/query",
        json!({ "series": H2S, "from": T0, "to": rfc3339_ns((T0 + 179 * S) as u64) }),
    )
    .await;
    assert_eq!(c, 200);
    let pts = r["points"].as_array().unwrap();
    assert_eq!(pts.len(), 180);
    assert!(pts.windows(2).all(|w| w[0][0].as_i64() < w[1][0].as_i64()));
    let (_, r) = post(
        &u,
        "/api/v2/ts/query",
        json!({ "series": H2S, "from": T0, "to": T0 + 179 * S, "step": "1m" }),
    )
    .await;
    let b = r["buckets"].as_array().unwrap();
    assert_eq!(b.len(), 3);
    assert_eq!(b[1]["max"], 14.2);
    assert_eq!(b[1]["count"], 60);

    // ---- the chunk summaries are ordinary events: EventQL can find the worst minute
    let (_, r) = post(&u, "/api/v2/data/run-eventql-query", json!({ "query":
        "FROM e IN events WHERE e.type == \"io.vesdb.ts.chunk-sealed\" AND e.data.series == \"rig-07/gas/h2s\" \
         ORDER BY e.data.max AS FLOAT64 DESC TOP 1 PROJECT INTO { from: e.data.from, max: e.data.max }" })).await;
    let line = r.as_str().unwrap().lines().next().unwrap().to_string();
    let row: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(row["data"]["value"]["max"], 14.2, "{line}");
    assert_eq!(
        row["data"]["value"]["from"],
        rfc3339_ns((T0 + 60 * S) as u64)
    );

    // ---- prove the spike reading offline once a witnessed checkpoint covers its chunk
    let spike = T0 + 97 * S;
    let mut proof = None;
    for _ in 0..100 {
        let (c, r) = post(
            &u,
            "/api/v2/ts/proof",
            json!({ "series": H2S, "time": spike }),
        )
        .await;
        if c == 200 {
            proof = Some(r);
            break;
        }
        assert_eq!(c, 409, "{r}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let p: PointProof = serde_json::from_value(proof.expect("cosigned in time")).unwrap();
    assert_eq!((p.value, p.index, p.count), (14.2, 37, 60));
    let rep = verify_point_proof(&p, &log_pub, std::slice::from_ref(&wpub), 1);
    assert!(rep.ok, "{:?}", rep.problems);
    // an altered value, a moved index, or a stranger's witness key all fail
    let mut forged = p.clone();
    forged.value = 4.2;
    assert!(!verify_point_proof(&forged, &log_pub, std::slice::from_ref(&wpub), 1).ok);
    let mut moved = p.clone();
    moved.index = 36;
    assert!(!verify_point_proof(&moved, &log_pub, std::slice::from_ref(&wpub), 1).ok);
    let other = HybridKey::from_seed("witness-x", &[99; 32]).public();
    assert!(!verify_point_proof(&p, &log_pub, &[other], 1).ok);
    let (c, _) = post(
        &u,
        "/api/v2/ts/proof",
        json!({ "series": H2S, "time": spike + 1 }),
    )
    .await;
    assert_eq!(c, 404);

    // ---- an insider rewrites minute 1 to remove the spike
    let files = chunk_files(&dir);
    assert_eq!(files.len(), 3);
    let spike_file = files
        .iter()
        .find(|f| {
            f.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&(T0 + 60 * S).to_string())
        })
        .unwrap()
        .clone();
    let original = std::fs::read(&spike_file).unwrap();
    let pts: Vec<(i64, f64)> = (60..120)
        .map(|i| (T0 + i * S, 2.0 + ((i % 7) as f64) / 10.0))
        .collect();
    let (forged_bytes, _) = vesdb_ts::chunk::build(H2S, T0 + 60 * S, &pts, 1, false);
    std::fs::write(&spike_file, forged_bytes).unwrap();
    let (c, r) = post(
        &u,
        "/api/v2/ts/query",
        json!({ "series": H2S, "from": T0, "to": T0 + 179 * S, "step": "1m" }),
    )
    .await;
    assert_eq!(
        (c, r["error"].as_str()),
        (500, Some("integrity-violation")),
        "{r}"
    );
    let (_, r) = post(&u, "/api/v2/management/verify-store", json!({})).await;
    assert!(r.to_string().contains("file hash differs"), "{r}");
    std::fs::write(&spike_file, original).unwrap();
    let (_, r) = post(&u, "/api/v2/management/verify-store", json!({})).await;
    assert!(!r.to_string().contains("time series:"), "{r}");

    // ---- retention: minute 0 deleted, deletion logged, aggregates still answered
    let (c, r) = post(
        &u,
        "/api/v2/ts/expire",
        json!({ "before": T0 + 60 * S, "reason": "90-day retention" }),
    )
    .await;
    assert_eq!(c, 200, "{r}");
    assert_eq!(r["expired"].as_array().unwrap().len(), 1);
    assert_eq!(chunk_files(&dir).len(), 2);
    let (_, r) = post(
        &u,
        "/api/v2/ts/query",
        json!({ "series": H2S, "from": T0, "to": T0 + 179 * S }),
    )
    .await;
    assert_eq!(r["points"].as_array().unwrap().len(), 120);
    assert_eq!(r["expired"].as_array().unwrap().len(), 1);
    let (_, r) = post(
        &u,
        "/api/v2/ts/query",
        json!({ "series": H2S, "from": T0, "to": T0 + 179 * S, "step": "1m" }),
    )
    .await;
    assert_eq!(r["buckets"][0]["count"], 60);
    assert_eq!(r["buckets"][0]["fromSummaries"], true);
    let (c, _) = post(
        &u,
        "/api/v2/ts/proof",
        json!({ "series": H2S, "time": T0 + 5 * S }),
    )
    .await;
    assert_eq!(c, 404);

    // ---- unsealed points survive a restart (WAL), sealed state is rebuilt from the log
    let (t3, v3) = readings(180, 10);
    let (c, _) = post(
        &u,
        "/api/v2/ts/write",
        json!({ "series": [{ "name": H2S, "times": t3, "values": v3 }] }),
    )
    .await;
    assert_eq!(c, 200);
    srv.shutdown().await;
    let srv = start(&dir, &witness).await;
    let u = srv.url.clone();
    let r = reqwest::Client::new()
        .get(format!("{u}/api/v2/ts/series"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let s = &r["series"][0];
    assert_eq!(
        (s["chunks"].as_u64(), s["expiredChunks"].as_u64()),
        (Some(3), Some(1)),
        "{r}"
    );
    assert_eq!(
        (s["sealedPoints"].as_u64(), s["openPoints"].as_u64()),
        (Some(180), Some(10))
    );
    let (_, r) = post(
        &u,
        "/api/v2/ts/query",
        json!({ "series": H2S, "from": T0, "to": T0 + 999 * S }),
    )
    .await;
    assert_eq!(r["points"].as_array().unwrap().len(), 130);
    let (c, r) = post(
        &u,
        "/api/v2/ts/proof",
        json!({ "series": H2S, "time": spike }),
    )
    .await;
    assert_eq!(c, 200, "{r}");
    srv.shutdown().await;
}
