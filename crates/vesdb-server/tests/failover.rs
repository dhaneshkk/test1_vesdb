//! Gate 3 of the high-availability plan: two vesdb servers share one bucket (the in-memory store,
//! which supports create-only-if-new and conditional replace like S3). A client writes with
//! idempotency keys and fails over between them while the writer is killed, or paused while it
//! keeps answering. Afterwards every acknowledged write is in the log exactly once, in order.

use axum::Router;
use object_store::{memory::InMemory, ObjectStore};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vesdb_core::crypto::HybridKey;
use vesdb_server::{
    ha::{ha_round, HaConfig, Role},
    router, try_new_app, Scope, ServerConfig, Shared,
};
use vesdb_store::{ObjectBackend, Store, StoreConfig};

const TOKEN: &str = "admin-token-0123456789-0123456789-abcdef";
const ORIGIN: &str = "ha.example/log";

fn backend(bucket: &Arc<InMemory>) -> ObjectBackend {
    ObjectBackend::new(
        bucket.clone() as Arc<dyn ObjectStore>,
        "vesdb",
        "memory:///vesdb",
    )
}

struct Node {
    url: String,
    app: Shared,
    ha: Option<tokio::task::JoinHandle<()>>,
    http: tokio::task::JoinHandle<()>,
}

async fn node(bucket: &Arc<InMemory>, name: &str, role: Role) -> Node {
    node_ts(bucket, name, role, None).await
}

async fn node_ts(
    bucket: &Arc<InMemory>,
    name: &str,
    role: Role,
    ts_dir: Option<&std::path::Path>,
) -> Node {
    let b = backend(bucket);
    let store = tokio::task::spawn_blocking(move || {
        Store::open_with(
            StoreConfig {
                dir: "/nonexistent".into(),
                origin: ORIGIN.into(),
                system_source: "https://ha.example".into(),
                pii_types: Default::default(),
                key: HybridKey::from_seed(ORIGIN, &[3; 32]),
            },
            Box::new(b),
        )
    })
    .await
    .unwrap()
    .unwrap();
    let mut tokens = HashMap::new();
    tokens.insert(
        TOKEN.to_string(),
        [Scope::Admin].into_iter().collect::<BTreeSet<_>>(),
    );
    let app = try_new_app(
        store,
        ServerConfig {
            tokens,
            witnesses: vec![],
            quorum: 0,
            checkpoint_interval: Duration::from_millis(200),
            checkpoint_max_events: 4096,
            compat_server_header: true,
            compat_signatures: false,
            compat_key: None,
            ts: ts_dir.map(|d| vesdb_ts::TsConfig {
                fsync: false,
                mirror: Some(Arc::new(vesdb_server::ha::BucketChunks(backend(bucket)))),
                ..vesdb_ts::TsConfig::new(d)
            }),
            ha: Some((
                HaConfig {
                    role,
                    identity: name.into(),
                    tail_interval: Duration::from_millis(50),
                    heartbeat_interval: Duration::from_millis(200),
                    stale_after: Duration::from_millis(1_000),
                },
                backend(bucket),
            )),
        },
    )
    .unwrap();
    let ha = Some(vesdb_server::ha::spawn_ha(app.clone()));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let r: Router = router(app.clone());
    let http = tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    Node { url, app, ha, http }
}

fn is_writer(n: &Node) -> bool {
    !n.app.store.lock().unwrap().is_standby()
}

async fn wait_writer(nodes: &[&Node], limit: Duration) -> (usize, Duration) {
    let t = Instant::now();
    loop {
        if let Some(i) = nodes.iter().position(|n| is_writer(n)) {
            return (i, t.elapsed());
        }
        assert!(t.elapsed() < limit, "no writer within {limit:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Write one event with key `k`, trying each server until one acknowledges (the client side of a
/// load balancer with retries). Returns the acknowledged event id.
async fn write(http: &reqwest::Client, urls: &[String], k: &str, deadline: Duration) -> u64 {
    let body = json!({ "events": [{
        "source": "https://client.example", "subject": "/orders",
        "type": "io.example.order-placed", "data": { "key": k }
    }]});
    let t = Instant::now();
    loop {
        for u in urls {
            let r = http
                .post(format!("{u}/api/v2/data/write-events"))
                .bearer_auth(TOKEN)
                .header("idempotency-key", k)
                .json(&body)
                .timeout(Duration::from_millis(500))
                .send()
                .await;
            if let Ok(r) = r {
                if r.status() == 200 {
                    let text = r.text().await.unwrap();
                    let line: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
                    assert_eq!(line["type"], "event", "{text}");
                    return line["data"]["id"].as_str().unwrap().parse().unwrap();
                }
                assert_eq!(r.status(), 503, "only retryable refusals expected");
            }
        }
        assert!(
            t.elapsed() < deadline,
            "write {k} not acknowledged within {deadline:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Every acknowledged key is in the log exactly once, and in acknowledgement order.
fn check_log(bucket: &Arc<InMemory>, acked: &[(String, u64)]) {
    let s = Store::open_with(
        StoreConfig {
            dir: "/nonexistent".into(),
            origin: ORIGIN.into(),
            system_source: "https://ha.example".into(),
            pii_types: Default::default(),
            key: HybridKey::from_seed(ORIGIN, &[3; 32]),
        },
        Box::new(backend(bucket)),
    )
    .unwrap();
    let mut seen: HashMap<String, Vec<u64>> = HashMap::new();
    for i in 0..s.len() {
        let e = s.event(i).unwrap();
        let v: Value = serde_json::from_str(&e.payload.unwrap().1).unwrap();
        seen.entry(v["key"].as_str().unwrap().to_string())
            .or_default()
            .push(i);
    }
    for (k, id) in acked {
        assert_eq!(
            seen.get(k),
            Some(&vec![*id]),
            "key {k}: acknowledged as {id}, log has {:?}",
            seen.get(k)
        );
    }
    let ids: Vec<u64> = acked.iter().map(|a| a.1).collect();
    assert!(
        ids.windows(2).all(|w| w[0] < w[1]),
        "acknowledged out of order: {ids:?}"
    );
    assert!(s.verify().unwrap().is_empty());
    let mut b = backend(bucket);
    let pk = HybridKey::from_seed(ORIGIN, &[3; 32]).public();
    let r = vesdb_store::bucket::verify_bucket(&mut b, ORIGIN, &pk, &[], 0).unwrap();
    assert!(r.ok, "{:?}", r.problems);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writer_killed_standby_takes_over() {
    let bucket = Arc::new(InMemory::new());
    let a = node(&bucket, "a", Role::Writer).await;
    let (w, _) = wait_writer(&[&a], Duration::from_secs(5)).await;
    assert_eq!(w, 0);
    let b = node(&bucket, "b", Role::Auto).await;
    let urls = vec![a.url.clone(), b.url.clone()];
    let http = reqwest::Client::new();
    // health endpoints for the load balancer
    assert_eq!(
        http.get(format!("{}/health/writer", a.url))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        http.get(format!("{}/health/writer", b.url))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        http.get(format!("{}/health/ready", b.url))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let mut acked = Vec::new();
    for i in 0..60 {
        let k = format!("k{i:03}");
        acked.push((
            k.clone(),
            write(&http, &urls, &k, Duration::from_secs(10)).await,
        ));
    }
    // reads keep working on the standby, which is caught up
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(b.app.store.lock().unwrap().len(), 60);

    // kill the writer: no heartbeats, no HTTP
    let killed = Instant::now();
    a.ha.as_ref().unwrap().abort();
    a.http.abort();
    let (w, _) = wait_writer(&[&b], Duration::from_secs(10)).await;
    assert_eq!(w, 0);
    let takeover = killed.elapsed();
    let urls = vec![b.url.clone()];
    let first_after = Instant::now();
    for i in 60..120 {
        let k = format!("k{i:03}");
        acked.push((
            k.clone(),
            write(&http, &urls, &k, Duration::from_secs(10)).await,
        ));
    }
    eprintln!(
        "takeover after {takeover:?} (stale after 1 s, tail every 50 ms); 60 writes after it in {:?}",
        first_after.elapsed()
    );
    assert!(takeover < Duration::from_secs(5), "{takeover:?}");
    // a retry of an already acknowledged write is answered from the log, not written again
    let again = write(&http, &urls, "k010", Duration::from_secs(5)).await;
    assert_eq!(again, acked[10].1);
    check_log(&bucket, &acked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paused_writer_cannot_fork_the_log() {
    let bucket = Arc::new(InMemory::new());
    let mut a = node(&bucket, "a", Role::Writer).await;
    wait_writer(&[&a], Duration::from_secs(5)).await;
    let b = node(&bucket, "b", Role::Auto).await;
    let http = reqwest::Client::new();
    let mut acked = Vec::new();
    for i in 0..20 {
        let k = format!("p{i:03}");
        acked.push((
            k.clone(),
            write(&http, &[a.url.clone()], &k, Duration::from_secs(5)).await,
        ));
    }
    // a pauses: its role loop stops (no heartbeat) but it still answers HTTP and still thinks it
    // is the writer
    a.ha.take().unwrap().abort();
    wait_writer(&[&b], Duration::from_secs(10)).await;
    assert!(is_writer(&a), "a does not know yet");
    // b writes; then the client, routed to the stale a, is refused (a's create loses) and retries
    let urls_b = vec![b.url.clone()];
    for i in 20..30 {
        let k = format!("p{i:03}");
        acked.push((
            k.clone(),
            write(&http, &urls_b, &k, Duration::from_secs(5)).await,
        ));
    }
    let both = vec![a.url.clone(), b.url.clone()];
    for i in 30..40 {
        let k = format!("p{i:03}");
        acked.push((
            k.clone(),
            write(&http, &both, &k, Duration::from_secs(5)).await,
        ));
    }
    assert!(!is_writer(&a), "a stepped down after its refused create");
    // a resumes and catches up as a standby
    let a2 = a.app.clone();
    tokio::task::spawn_blocking(move || ha_round(&a2, false))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.app.store.lock().unwrap().len(), 40);
    check_log(&bucket, &acked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sealed_time_series_survive_failover() {
    let bucket = Arc::new(InMemory::new());
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = node_ts(&bucket, "a", Role::Writer, Some(da.path())).await;
    wait_writer(&[&a], Duration::from_secs(5)).await;
    let b = node_ts(&bucket, "b", Role::Auto, Some(db.path())).await;
    let http = reqwest::Client::new();
    let t0: i64 = 1_762_000_020 * 1_000_000_000;
    let times: Vec<i64> = (0..120).map(|i| t0 + i * 1_000_000_000).collect();
    let values: Vec<f64> = (0..120).map(|i| if i == 97 { 14.2 } else { 2.0 }).collect();
    let post = |u: String, path: &str, body: Value| {
        let http = http.clone();
        let path = path.to_string();
        async move {
            http.post(format!("{u}{path}"))
                .bearer_auth(TOKEN)
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };
    let r = post(
        a.url.clone(),
        "/api/v2/ts/write",
        json!({"series": [{"name": "rig-07/gas/h2s", "times": times, "values": values}]}),
    )
    .await;
    assert_eq!(r.status(), 200);
    let r = post(a.url.clone(), "/api/v2/ts/flush", json!({})).await;
    assert_eq!(r.status(), 200);
    // the standby rejects time-series writes, and absorbs the sealed chunks as it tails
    let r = post(
        b.url.clone(),
        "/api/v2/ts/write",
        json!({"series": [{"name": "x", "times": [t0], "values": [1.0]}]}),
    )
    .await;
    assert_eq!(r.status(), 503);
    tokio::time::sleep(Duration::from_millis(300)).await;
    a.ha.as_ref().unwrap().abort();
    a.http.abort();
    wait_writer(&[&b], Duration::from_secs(10)).await;
    // b reads chunks sealed by a, from the shared copies, checked against the sealed events
    let r = post(b.url.clone(), "/api/v2/ts/query", json!({"series": "rig-07/gas/h2s", "from": t0, "to": t0 + 200_000_000_000i64, "step": "1m"})).await;
    let v: Value = r.json().await.unwrap();
    let buckets = v["buckets"].as_array().unwrap_or_else(|| panic!("{v}"));
    assert_eq!(buckets.len(), 2);
    assert_eq!(buckets[1]["max"], 14.2);
    assert_eq!(
        buckets
            .iter()
            .map(|b| b["count"].as_u64().unwrap())
            .sum::<u64>(),
        120
    );
    // and b keeps taking points after the takeover
    let r = post(b.url.clone(), "/api/v2/ts/write", json!({"series": [{"name": "rig-07/gas/h2s", "times": [t0 + 130_000_000_000i64], "values": [3.0]}]})).await;
    assert_eq!(r.status(), 200);
}
