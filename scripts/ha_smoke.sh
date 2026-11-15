#!/usr/bin/env bash
# High availability with the real binaries: two servers share one bucket (here a local
# directory through object_store; the same flags take s3://bucket/prefix). The writer is killed
# with SIGKILL, the standby takes over, retries are idempotent, and the bucket verifies offline.
# A file store is migrated into a second bucket. Run from the repository root after
# `cargo build --workspace --all-targets`.
set -euo pipefail
B=${B:-${CARGO_TARGET_DIR:-$(pwd)/target}/debug}
W=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
cd "$W"
T=ha-smoke-token-0123456789-0123456789-abcdef
BUCKET="file://$W/bucket"
mkdir -p bucket
$B/vesdb keygen --name ha.example/log --out log.key >/dev/null

declare -A PID
run() { # name port
  $B/vesdb run --storage "$BUCKET" --data-directory "$W/$1" --identity "$1" --role auto \
    --signing-key-file log.key --api-token $T --listen 127.0.0.1:$2 \
    --tail-interval-ms 100 --heartbeat-interval-ms 500 --stale-after-ms 3000 \
    --snapshot-every 50 >"$1.log" 2>&1 &
  PID[$1]=$!
}
code() { curl -s -o /dev/null -w '%{http_code}' "$1"; }
wait_for() { # url code seconds
  for _ in $(seq 1 $(( $3 * 20 ))); do [ "$(code "$1")" = "$2" ] && return 0; sleep 0.05; done
  echo "timeout waiting for $1 -> $2"; tail -20 *.log; exit 1
}
write() { # port key n
  curl -s -X POST "http://127.0.0.1:$1/api/v2/data/write-events" -H "authorization: Bearer $T" \
    -H "idempotency-key: $2" -H 'content-type: application/json' -D hdr.txt \
    -d "{\"events\":[{\"source\":\"https://ha.example\",\"subject\":\"/orders\",\"type\":\"io.example.order-placed\",\"data\":{\"n\":$3}}]}" \
    | head -1 | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["data"]["id"])'
}

run a 3101; wait_for http://127.0.0.1:3101/health/writer 200 10
run b 3102; wait_for http://127.0.0.1:3102/health/ready 200 10
echo "a: writer ($(code http://127.0.0.1:3101/health/writer)), b: standby ($(code http://127.0.0.1:3102/health/writer)), ready ($(code http://127.0.0.1:3102/health/ready))"
for i in $(seq 1 5); do write 3101 key-$i $i >/dev/null; done
echo "a acknowledged 5 writes; standby refuses writes: HTTP $(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:3102/api/v2/data/write-events -H "authorization: Bearer $T" -H 'content-type: application/json' -d '{"events":[{"source":"https://ha.example","subject":"/x","type":"io.example.x","data":{}}]}')"

sleep 1.5 # let a sign a checkpoint
kill -9 ${PID[a]}; t0=$(date +%s.%N)
wait_for http://127.0.0.1:3102/health/writer 200 20
t1=$(date +%s.%N)
python3 -c "print(f'writer killed; b took over after {$t1-$t0:.1f} s (stale after 3 s)')"
for i in $(seq 6 8); do write 3102 key-$i $i >/dev/null; done
id=$(write 3102 key-2 2)
echo "retry of key-2 on b: event #$id, $(grep -i '^idempotent-replayed' hdr.txt | tr -d '\r' || echo 'NOT replayed')"
n=$(curl -s -X POST http://127.0.0.1:3102/api/v2/data/read-events -H "authorization: Bearer $T" -H 'content-type: application/json' -d '{"subject":"/orders","options":{"recursive":false}}' | grep -c '"type":"event"')
echo "b holds $n order events (5 from a, 3 from b, no duplicates)"
[ "$n" = 8 ]
sleep 1.5 # b checkpoints its writes
kill ${PID[b]}; wait ${PID[b]} 2>/dev/null || true

echo -n "bucket: "; $B/vesdb-verify bucket "$BUCKET" --log-key log.key.pub | tee bucket.out | tail -1
head -1 bucket.out | sed 's/^/  /'
echo -n "race test, local directory: "; $B/vesdb-verify race-test "file://$W/race" --rounds 2000 | tail -1
echo -n "race test, in-memory store: "; $B/vesdb-verify race-test memory:/// --rounds 2000 | tail -1

# migrate a file store into a second bucket
$B/vesdb run --data-directory "$W/files" --signing-key-file log.key --api-token $T --listen 127.0.0.1:3103 >files.log 2>&1 &
FP=$!
wait_for http://127.0.0.1:3103/api/v2/system/ping 200 10
for i in $(seq 1 7); do write 3103 m-$i $i >/dev/null; done
sleep 1.5; kill $FP; wait $FP 2>/dev/null || true
mkdir -p bucket2
echo "migrate: $($B/vesdb migrate --from "$W/files" --to "file://$W/bucket2" --signing-key-file log.key)"
echo -n "migrated bucket: "; $B/vesdb-verify bucket "file://$W/bucket2" --log-key log.key.pub | tail -1
