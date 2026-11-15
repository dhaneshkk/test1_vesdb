# vesdb

A verifiable, tamper-evident event store in Rust. It speaks the **EventSourcingDB 1.3 v2 HTTP API**
(the official `eventsourcingdb` Rust SDK 4.1.4 works against it unchanged) and adds an open
**transparency log**: an RFC 9162 Merkle tree, write-time receipts, signed checkpoints, independent
witnesses, offline evidence bundles and redaction that keeps every proof valid. All signatures are
**hybrid Ed25519 + ML-DSA-65 (FIPS 204)**.

Status: Phases 1–2 of the design doc, minus the items under *Not yet implemented*. Not audited.

## Crates

| crate | what |
|---|---|
| `vesdb-core` | encodings, compat `esdb:hash:v2`, RFC 9162 Merkle proofs, hybrid signatures, checkpoints, receipts, witness state machine, evidence bundles. No I/O. |
| `vesdb-store` | single-writer engine: framed append-only files with CRC32C, fsync before ack, torn-tail recovery, preconditions, receipts, in-place redaction, `verify`/`audit`. |
| `vesdb-server` | `vesdb` binary: axum HTTP server, scoped tokens, observe (history then live), checkpointer that collects witness cosignatures. |
| `vesdb-witness` | `vesdb-witness` binary: cosigns a checkpoint only if a consistency proof shows it extends what it cosigned before; state persisted atomically before answering. |
| `vesdb-verify` | `vesdb-verify` binary: verifies bundles and consistency offline, without contacting the database. |
| `vesdb-eventql` | EventQL parser and compiler to **Apache DataFusion logical plans** (no hand-written engine); powers `run-eventql-query` and `isEventQlQueryTrue`. |
| `vesdb-ts` | time series: write-ahead log, Gorilla-compressed chunks, one sealed chunk = one log event, retention with logged deletions, raw and downsampled queries, per-reading proofs. |

## Quick start

```bash
cargo build --release
B=target/release
$B/vesdb keygen --name rig-07.vg360.example/log --out log.key        # log origin = key name
$B/vesdb keygen --name hse.operator.example     --out hse.key
$B/vesdb-witness run --key-file hse.key --log-key log.key.pub --state-file hse.state --listen 127.0.0.1:3101 &
$B/vesdb run --data-directory data --signing-key-file log.key \
  --token "$(openssl rand -hex 24)=read,write" --token "$(openssl rand -hex 24)=read,audit" \
  --witness http://127.0.0.1:3101=hse.key.pub \
  --pii-type ai.innoura.vg360.person-identified
```

Write and read exactly as with EventSourcingDB (`POST /api/v2/data/write-events`,
`QUERY /api/v2/data/read-events`, `QUERY /api/v2/data/observe-events`, ...). Then:

```bash
curl -s localhost:3000/tlog/checkpoint                         # latest checkpoint with a witness quorum
curl -s -X QUERY localhost:3000/api/v2/tlog/bundle -H "authorization: Bearer $AUDIT" \
     -H 'content-type: application/json' -d '{"ids":["0","1","2"]}' > bundle.json
$B/vesdb-verify bundle bundle.json --log-key log.key.pub --witness-key hse.key.pub --file-hash clip.mkv=1:sha256
```

## API

EventSourcingDB-compatible: `GET /api/v2/system/ping`, `POST /api/v2/system/verify-token`,
`GET /api/v2/system/health`, `POST /api/v2/data/write-events` (preconditions `isSubjectPristine`,
`isSubjectPopulated`, `isSubjectOnEventId`, each with `options.recursive`), `QUERY read-events`
(`recursive`, `order`, `lowerBound`, `upperBound`, `fromLatestEvent`), `QUERY observe-events`,
`QUERY read-subjects`, `QUERY read-event-types`, `QUERY run-eventql-query`,
`isEventQlQueryTrue` preconditions (dynamic consistency boundaries), `POST /api/v2/management/verify-store`,
`POST audit-history`, `POST enable-read-only-mode`.

vesdb additions: `POST /api/v2/management/redact-events` `{ids, reason}` (scope `redact`),
`QUERY /api/v2/tlog/receipt` `{id}`, `QUERY /api/v2/tlog/consistency` `{from, to}`,
`QUERY /api/v2/tlog/bundle` `{ids, checkpointSize?}` (scope `audit`), `GET /tlog/checkpoint`,
`GET /tlog/key`. Events carry two CloudEvents extensions: `vesdbleaf` (hex leaf hash) and
`vesdbredacted`.

Time series (`vesdb-ts`, on by default, `--no-time-series` turns it off):
`POST /api/v2/ts/write` `{series: [{name, times, values}]}` (times as integer ns, decimal strings or
RFC 3339; scope `write`), `POST /api/v2/ts/query` `{series, from, to, step?}` (raw points, or buckets
with count/min/max/sum/avg/first/last for `step` like `"1m"`; scope `read`), `GET /api/v2/ts/series`,
`POST /api/v2/ts/flush` (seal every open window now), `POST /api/v2/ts/expire` `{before, reason?}`
(scope `admin`), `POST /api/v2/ts/proof` `{series, time}` (scope `audit`), checked offline with
`vesdb-verify point`.

Token scopes: `read`, `write`, `audit`, `redact`, `admin`. `--api-token` is an `admin` token
(EventSourcingDB behaviour).

## Integrity model

* **Leaf** = `SHA256(0x00 ‖ enc(event))`, where `enc` is the length-prefixed metadata plus
  `c = SHA256("vesdb/payload/v1" ‖ salt ‖ data)`. Payload bytes are never in the tree, so
  redaction erases `salt` and `data` on disk and every leaf, root, receipt and checkpoint stays valid.
* **Receipt** (per write batch, fsynced before the write is acknowledged): hybrid signature over
  `(origin, size, root)`. A leaf below `size` must appear at its index in every later tree.
* **Checkpoint** (C2SP checkpoint body; every 1 s or 4,096 events): signed by the log, sent to each
  witness with a consistency proof from that witness's last size, published once `--witness-quorum`
  cosignatures arrive. After an outage, one proof covers the whole gap.
* **Compat hash** `esdb:hash:v2:` is byte-identical to EventSourcingDB (checked against the SDK's own
  test events). The read-time `signature` (`esdb:signature:v1:`, Ed25519 over the hash) is offered
  for SDK compatibility only; it has EventSourcingDB's weakness (computed at read time), which the
  receipts fix.
* **Personal-data types** (`--pii-type`) get `hash = vesdb:leaf:v1:<leaf>` instead of an unsalted hash
  over `data`, so redacted values cannot be guessed. The official SDK's `verify_hash` fails for these
  events by design; verify them with receipts and bundles.

## Time series

Raw readings are not log entries: one event per reading would cost a JSON envelope, a Merkle leaf
and the write lock for every point. Instead:

1. **Write**: points go to a CRC-framed write-ahead log (fsynced before the answer, unless
   `--ts-no-fsync`) and a buffer per `(series, window)`. Out-of-order points are fine.
2. **Seal**: when a window closes (`--ts-window-ms`, default 1 minute, plus `--ts-grace-ms`, default
   5 s), its points are sorted and Gorilla-compressed (delta-of-delta times, XOR values) into a chunk
   file. The chunk is committed as one `io.vesdb.ts.chunk-sealed` event on subject `/ts/<series>`
   with the time range, count, min/max/sum/first/last, the file's SHA-256 and `pointsRoot`, the
   RFC 9162 Merkle root over the points. That event gets a receipt and witness cosignatures like any
   other. Points that arrive after their window was sealed become a second chunk marked `late`.
3. **Read**: every chunk read is checked against its sealed event (file hash, header, point count,
   `pointsRoot`), so a rewritten chunk file fails the query with `integrity-violation`, and
   `verify-store` reports it.
4. **Prove one reading**: `/api/v2/ts/proof` returns the reading, its inclusion proof in
   `pointsRoot`, and an evidence bundle for the chunk event against a cosigned checkpoint.
   `vesdb-verify point` checks both inclusions, the log signature and the witness quorum offline.
5. **Retention** (`--ts-retention-secs` or `/api/v2/ts/expire`): the deletion is logged first as
   `io.vesdb.ts.chunk-expired`, then the file is removed. The `chunk-sealed` event stays, so the
   log is unchanged and aggregate queries over whole expired chunks are still exact
   (`fromSummaries: true`); buckets finer than a chunk are marked `partial`.
6. **Recovery**: on start the chunk index is rebuilt from the log and the write-ahead log is replayed,
   skipping points a committed chunk already holds (`walHi`). Crash tests cover a crash before the
   chunk event is appended (points kept, orphan file removed) and after it but before WAL compaction
   (no point sealed twice).

Chunk summaries are ordinary events, so EventQL can query them, for example the worst minute:

```
FROM e IN events WHERE e.type == "io.vesdb.ts.chunk-sealed" AND e.data.series == "rig-07/gas/h2s"
ORDER BY e.data.max AS FLOAT64 DESC TOP 1 PROJECT INTO { from: e.data.from, max: e.data.max }
```

Measured in the test suite (debug build with optimized dependencies, 100 series × 1 Hz × 1 hour,
0.01 resolution): 4.45 bytes per point on disk against 16 raw, 6,000 log events for 360,000 points,
in-memory ingest above 10 M points/s without fsync, a one-hour raw query in about 10 ms. With fsync
on, write throughput is set by the disk's fsync rate: send points in batches.

Limits: values must be finite, times at or after the Unix epoch, series names are subject paths of
`[A-Za-z0-9_-]` segments. EventQL cannot read raw points yet, only chunk summaries.

## EventQL on DataFusion

`vesdb-eventql` parses EventQL (FROM … IN events/subjects/eventtypes/(subquery), WHERE, ORDER BY,
GROUP BY … HAVING, SKIP, TOP, PROJECT INTO [DISTINCT], AS casts, string/math/date functions, IF,
COUNT/SUM/AVG/MIN/MAX/MEDIAN/STDDEV/VARIANCE/UNIQUE) and compiles each query level into one
DataFusion `LogicalPlan`:

```text
scan(alias₁) × scan(alias₂) … → Filter(WHERE) → WindowAggr(row_number ORDER BY …) as _ord
  → [Aggregate(GROUP BY; aggregates, min(_ord)) → Filter(HAVING)] → Projection(PROJECT INTO)
  → [DISTINCT: Aggregate(min(_ord))] → Sort(_ord) → Limit(SKIP, TOP)
```

EventQL is dynamically typed: each compiled expression carries a kind (typed column, JSON value,
whole event) and operators coerce by kind; JSON access runs through small Rust UDFs (`jget`,
`jnum`, …) over canonical JSON text. Subqueries run first and become in-memory tables. The event
table is a columnar copy of the log, appended as events are written and rebuilt after a redaction.
`isEventQlQueryTrue` is evaluated under the write lock with a 5-second budget, after the other
preconditions, as EventSourcingDB documents. Limits: 100 KiB queries, nesting 256, 1,000 binary
operators, 1,000,000 rows, 1 GiB memory (DataFusion memory pool).

Stack safety: the parser and compiler grow their stack on demand (`stacker`), and queries plan and
run on a dedicated two-thread runtime with 256 MiB stacks, because DataFusion's optimizer recurses
over the expression tree. The timeout is enforced on the caller's side, so a slow planning step
cannot hold the write lock past its budget. The operator cap exists because planning time grows
quickly with expression size (10,000 operators took over a minute in a debug build).

Deviations from EventSourcingDB's EventQL (`vesdb_eventql::DEVIATIONS`): 64-bit integers instead of
1,000 digits; `/` is floating-point; aggregates skip NULL inputs; ORDER BY on JSON fields orders
numbers; INSTR/SUBSTRING use 0-based byte offsets; two JSON fields compare by canonical text; objects
and arrays only in PROJECT INTO. The rest of the documented semantics (strict booleans in
WHERE/HAVING, NULL guards, groups in first-row order, UNIQUE and empty-set failures, subquery
sources, cartesian joins) is implemented and tested.

## Verification status

| check | how |
|---|---|
| Merkle roots, inclusion, consistency proofs | byte-identical to the Python reference in the demo notebook (`tests/vectors_python.json`); exhaustive completeness/soundness tests n ≤ 130 |
| compat hash | reproduces the three v2 events from the official SDK's tests |
| hybrid signature | rejects a valid Ed25519 half with a wrong ML-DSA half and vice versa |
| store | atomic batches, preconditions, torn-tail truncation, damaged-file refusal, disk edit with recomputed CRC detected by `verify`, durable redaction with bytes gone from disk |
| EventQL | 18 tests: the documentation's example queries, guards, grouping order, HAVING with date buckets, aggregates and their failure cases, paths, casts, functions, DISTINCT/SKIP/TOP, subjects/eventtypes sources, boolean preconditions, plan shape |
| time series (`crates/vesdb-ts`, `crates/vesdb-server/tests/ts.rs`) | Gorilla round trip for arbitrary bit patterns (proptest, incl. NaN payloads, ±0, i64 extremes) and rejection of truncated input; sealing, late and out-of-order points; crash before and after the chunk event; torn and damaged WAL; a rewritten chunk detected on read and by verify-store; retention with exact aggregates from summaries and a restart; over HTTP with a witness, a point proof that verifies and fails for a changed value, a moved index or a foreign witness key |
| end to end (`crates/vesdb-server/tests/e2e.rs`) | official SDK: ping, token, writes with preconditions, stale write refused, read + `verify_hash` + `verify_signature`, observe history→live, `run_eventql_query`, `is_eventql_query_true` (a DCB rule across subjects); scoped tokens; 2 witnesses; outage and catch-up with one proof; rewritten history with the real log key refused by both witnesses; rollback refused; redaction; bundles verify offline; verify-store; audit-history |

| Lean 4 (`lean/`) | `consistency_sound` and `receipt_binding` **proved**, checked by official Lean 4.25.0 with the core library only (no Mathlib, no `sorry`, standard axioms only; `lean/check.sh`). `lean/Tests.lean` runs the definitions with a toy hash so the theorems are not vacuous: honest proofs verify for every m ≤ n ≤ 24, forked histories fail, RFC 9162 example proof lengths match |

| Rust ↔ Lean (`crates/vesdb-core/tests/lean_vectors.rs`) | the Lean definitions the proof is about, run with SHA-256 (`lean/Sha256.lean`, FIPS 180-4 vectors), produce `lean_vectors.json` (`lean/Vectors.lean`): every root for 0–33 leaves, every consistency and inclusion proof for trees up to 32 leaves, and Lean's verdict on 14,376 honest and tampered cases (flipped, dropped, extra or duplicated proof hashes, wrong roots, leaves, indices and sizes). Rust must match all of them; a deliberately broken Rust verifier fails the test. `lean/check.sh` regenerates the file and fails if the committed copy is stale |

`consistency_sound` is about the Lean verifier. The Rust verifier is a separate implementation of
the same algorithm; the differential test ties them together on every tree up to 32 leaves, which is
strong evidence but not a proof of equivalence for larger trees. Both verifiers accept some proofs
for a size one larger than the tree's real size: the algorithm binds a size only through its root,
and vesdb never trusts a bare size (checkpoints and receipts sign size and root together).

The remaining Lean theorems in the design doc (inclusion, `consistency_complete`, encoding, store,
witness, redaction, time series) are stated but not yet proved; for those, the tests are evidence,
not proofs.

## Not yet implemented (vs. the design doc)

* Event schemas (`register-event-schema` answers an error); an MCP server.
* C2SP tlog-tiles static serving (proofs are served by API instead), RFC 3161 timestamping, TLS
  (terminate at a proxy), Raft/HA, group commit across requests (each request is one fsynced batch),
  redb indexes (indexes are rebuilt in memory on start), Windows support (uses Unix file APIs).
* Key rotation, access events in the log, rate limiting, OpenTelemetry export.

## Caveats

* `ml-dsa` (RustCrypto) is unaudited; so is this code.
* The `Server: EventSourcingDB/1.3 (compatible; vesdb/…)` header exists only because the official SDKs
  require it; turn it off with `--no-compat-server-header`. "EventSourcingDB" is the native web GmbH's
  product name. Get legal advice before claiming compatibility publicly.

## License

MIT OR Apache-2.0.
