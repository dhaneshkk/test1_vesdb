//! `vesdb-verify`: checks evidence without contacting the database.
//!
//! * `bundle`      – checkpoint signatures, witness quorum, each event's commitment, inclusion and
//!   write-time receipt; optional file hash against a payload field (e.g. a clip).
//! * `consistency` – a newer checkpoint extends an older one, given a consistency proof.
//! * `point`       – one time-series reading: its inclusion in a sealed chunk's `pointsRoot`, and
//!   that chunk's `chunk-sealed` event in a cosigned checkpoint.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use vesdb_core::{
    b64,
    bundle::{verify_bundle, Bundle},
    checkpoint::Checkpoint,
    crypto::load_public,
    merkle::verify_consistency,
    time::rfc3339_ns,
    ts::{verify_point_proof, PointProof},
};

#[derive(Parser)]
#[command(
    name = "vesdb-verify",
    version,
    about = "Verify vesdb evidence offline"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Bundle {
        bundle: PathBuf,
        #[arg(long)]
        log_key: PathBuf,
        #[arg(long = "witness-key")]
        witness_keys: Vec<PathBuf>,
        /// Minimum valid witness cosignatures (default: all given witness keys).
        #[arg(long)]
        quorum: Option<usize>,
        /// `FILE=EVENT_ID:FIELD`: SHA-256 of FILE must equal the hex in data.FIELD of that event.
        #[arg(long = "file-hash")]
        file_hashes: Vec<String>,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a time-series point proof (from /api/v2/ts/proof).
    Point {
        proof: PathBuf,
        #[arg(long)]
        log_key: PathBuf,
        #[arg(long = "witness-key")]
        witness_keys: Vec<PathBuf>,
        #[arg(long)]
        quorum: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    Consistency {
        #[arg(long)]
        old: PathBuf,
        #[arg(long)]
        new: PathBuf,
        /// JSON `{"proof": [base64, ...]}` as returned by /api/v2/tlog/consistency
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        log_key: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Bundle {
            bundle,
            log_key,
            witness_keys,
            quorum,
            file_hashes,
            json,
        } => {
            let b: Bundle = serde_json::from_slice(&std::fs::read(&bundle)?)?;
            let log = load_public(&log_key)?;
            let wk = witness_keys
                .iter()
                .map(|p| load_public(p))
                .collect::<Result<Vec<_>, _>>()?;
            let k = quorum.unwrap_or(wk.len());
            let mut rep = verify_bundle(&b, &log, &wk, k);
            for spec in &file_hashes {
                let (file, sel) = spec
                    .split_once('=')
                    .ok_or("--file-hash FILE=EVENT_ID:FIELD")?;
                let (id, field) = sel
                    .split_once(':')
                    .ok_or("--file-hash FILE=EVENT_ID:FIELD")?;
                let id: u64 = id.parse()?;
                let digest =
                    hex::encode(<sha2::Sha256 as sha2::Digest>::digest(std::fs::read(file)?));
                let want = b
                    .items
                    .iter()
                    .find(|i| i.event.id == id)
                    .and_then(|i| i.data.as_ref())
                    .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
                    .and_then(|v| v.get(field).and_then(|x| x.as_str()).map(str::to_string));
                if want.as_deref() != Some(digest.as_str()) {
                    rep.problems.push(format!(
                        "{file}: SHA-256 {digest} does not match event #{id} data.{field}"
                    ));
                    rep.ok = false;
                } else if !json {
                    println!("file {file}: SHA-256 matches event #{id} data.{field}");
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&rep)?);
            } else {
                let cp = &b.checkpoint;
                println!(
                    "checkpoint {} size {} at {}",
                    cp.origin,
                    cp.size,
                    rfc3339_ns(cp.time_ns)
                );
                println!(
                    "  log signature (Ed25519 + ML-DSA-65): {}",
                    rep.log_signature_ok
                );
                println!(
                    "  witness cosignatures {}/{}: {:?}",
                    rep.cosigners.len(),
                    rep.required_cosigners,
                    rep.cosigners
                );
                for it in &rep.items {
                    let ev = b
                        .items
                        .iter()
                        .find(|i| i.event.id == it.id)
                        .map(|i| &i.event);
                    println!(
                        "  #{:<5} {:<45} {}  commitment={} inclusion={} receipt={}{}",
                        it.id,
                        it.ty,
                        ev.map(|e| rfc3339_ns(e.time_ns)).unwrap_or_default(),
                        it.commitment_ok,
                        it.inclusion_ok,
                        it.receipt_ok,
                        if it.redacted { "  [REDACTED]" } else { "" }
                    );
                }
                for p in &rep.problems {
                    println!("  PROBLEM: {p}");
                }
                println!("{}", if rep.ok { "VERIFIED" } else { "NOT VERIFIED" });
            }
            Ok(rep.ok)
        }
        Cmd::Point {
            proof,
            log_key,
            witness_keys,
            quorum,
            json,
        } => {
            let p: PointProof = serde_json::from_slice(&std::fs::read(&proof)?)?;
            let log = load_public(&log_key)?;
            let wk = witness_keys
                .iter()
                .map(|p| load_public(p))
                .collect::<Result<Vec<_>, _>>()?;
            let k = quorum.unwrap_or(wk.len());
            let rep = verify_point_proof(&p, &log, &wk, k);
            if json {
                println!("{}", serde_json::to_string_pretty(&rep)?);
            } else {
                let cp = &p.bundle.checkpoint;
                println!(
                    "reading {} = {} at {}",
                    p.series,
                    p.value,
                    rfc3339_ns(p.time.max(0) as u64)
                );
                println!(
                    "  in chunk event #{} (point {} of {}): {}",
                    rep.chunk_event.map(|i| i.to_string()).unwrap_or("?".into()),
                    p.index + 1,
                    p.count,
                    rep.point_inclusion_ok
                );
                println!(
                    "  chunk event in checkpoint {} size {}: log signature {}, witnesses {}/{} {:?}",
                    cp.origin,
                    cp.size,
                    rep.bundle.log_signature_ok,
                    rep.bundle.cosigners.len(),
                    rep.bundle.required_cosigners,
                    rep.bundle.cosigners
                );
                for x in &rep.problems {
                    println!("  PROBLEM: {x}");
                }
                println!("{}", if rep.ok { "VERIFIED" } else { "NOT VERIFIED" });
            }
            Ok(rep.ok)
        }
        Cmd::Consistency {
            old,
            new,
            proof,
            log_key,
        } => {
            let log = load_public(&log_key)?;
            let o: Checkpoint = serde_json::from_slice(&std::fs::read(old)?)?;
            let n: Checkpoint = serde_json::from_slice(&std::fs::read(new)?)?;
            let p: serde_json::Value = serde_json::from_slice(&std::fs::read(proof)?)?;
            let hashes = p["proof"]
                .as_array()
                .ok_or("proof must be {\"proof\": [...]}")?
                .iter()
                .map(|x| -> Result<[u8; 32], Box<dyn std::error::Error>> {
                    Ok(
                        b64::decode(x.as_str().ok_or("proof entries are base64 strings")?)?
                            .try_into()
                            .map_err(|_| "32-byte hashes")?,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let sigs = o.verify_log_sig(&log) && n.verify_log_sig(&log);
            let same_origin = o.origin == n.origin;
            let cons = verify_consistency(o.size, n.size, &o.root, &n.root, &hashes);
            println!(
                "signatures {sigs}, same origin {same_origin}, {} -> {} consistent {cons}",
                o.size, n.size
            );
            Ok(sigs && same_origin && cons)
        }
    }
}
