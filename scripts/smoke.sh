#!/usr/bin/env bash
# Smoke test of the real binaries: keygen, two witnesses, server, curl writes, evidence bundle, offline verify.
set -euo pipefail
B=${B:-${CARGO_TARGET_DIR:-$(cd "$(dirname "$0")/.." && pwd)/target}/debug}
W=$(mktemp -d); cd "$W"
$B/vesdb keygen --name rig-07.vg360.example/log --out log.key
$B/vesdb keygen --name hse.operator.example --out hse.key
$B/vesdb keygen --name witness.innoura.example --out inn.key
$B/vesdb-witness run --key-file hse.key --log-key log.key.pub --state-file hse.state --listen 127.0.0.1:3101 >hse.log 2>&1 &
$B/vesdb-witness run --key-file inn.key --log-key log.key.pub --state-file inn.state --listen 127.0.0.1:3102 >inn.log 2>&1 &
T=writer-0123456789-0123456789-0123456789; A=auditor-0123456789-0123456789-01234567
$B/vesdb run --data-directory data --signing-key-file log.key --token "$T=read,write" --token "$A=read,audit" \
  --witness http://127.0.0.1:3101=hse.key.pub --witness http://127.0.0.1:3102=inn.key.pub \
  --pii-type ai.innoura.vg360.person-identified --listen 127.0.0.1:3000 >server.log 2>&1 &
trap 'kill $(jobs -p) 2>/dev/null' EXIT
sleep 1.5
curl -sf -i http://127.0.0.1:3000/api/v2/system/ping | grep -i '^server:'
head -c 200000 /dev/urandom > clip.mkv; SHA=$(sha256sum clip.mkv | cut -d' ' -f1)
w() { curl -sf -X POST http://127.0.0.1:3000/api/v2/data/write-events -H "authorization: Bearer $T" -H 'content-type: application/json' -d "$1"; }
w '{"events":[{"source":"https://rig-07.vg360.example","subject":"/rigs/rig-07/incidents/inc-0412","type":"ai.innoura.vg360.hazard-detected","data":{"camera":"cam-12","score":0.97}}],"preconditions":[{"type":"isSubjectPristine","payload":{"subject":"/rigs/rig-07/incidents/inc-0412"}}]}' | head -c 300; echo
w '{"events":[{"source":"https://rig-07.vg360.example","subject":"/rigs/rig-07/incidents/inc-0412","type":"ai.innoura.vg360.clip-sealed","data":{"sha256":"'$SHA'","codec":"av1"}},{"source":"https://rig-07.vg360.example","subject":"/rigs/rig-07/incidents/inc-0412","type":"ai.innoura.vg360.alert-acknowledged","data":{"role":"supervisor"}}],"preconditions":[{"type":"isSubjectOnEventId","payload":{"subject":"/rigs/rig-07/incidents/inc-0412","eventId":"0"}}]}' >/dev/null
echo "stale write -> $(w '{"events":[{"source":"https://rig-07.vg360.example","subject":"/rigs/rig-07/incidents/inc-0412","type":"ai.innoura.vg360.alert-acknowledged","data":{}}],"preconditions":[{"type":"isSubjectOnEventId","payload":{"subject":"/rigs/rig-07/incidents/inc-0412","eventId":"0"}}]}' | head -1 | cut -c1-110)"
echo "--- EventQL (compiled to DataFusion):"
curl -sf -X QUERY http://127.0.0.1:3000/api/v2/data/run-eventql-query -H "authorization: Bearer $T" -H 'content-type: application/json' \
  -d '{"query":"FROM e IN events GROUP BY e.type PROJECT INTO { type: UNIQUE(e.type), n: COUNT() }"}'
echo "--- DCB precondition (at most one acknowledgement per incident, any subject):"
echo "  $(w '{"events":[{"source":"https://rig-07.vg360.example","subject":"/rigs/rig-07/radio-log","type":"ai.innoura.vg360.alert-acknowledged","data":{}}],"preconditions":[{"type":"isEventQlQueryTrue","payload":{"query":"FROM e IN events WHERE e.type == \"ai.innoura.vg360.alert-acknowledged\" PROJECT INTO COUNT() == 0"}}]}' | head -1 | cut -c1-100)"
sleep 1.5
curl -sf http://127.0.0.1:3000/tlog/checkpoint > cp.json; python3 -c "import json;c=json.load(open('cp.json'));print('cosigned checkpoint size',c['size'],'by',sorted(c['cosigs']))"
curl -sf -X QUERY http://127.0.0.1:3000/api/v2/tlog/bundle -H "authorization: Bearer $A" -H 'content-type: application/json' -d '{"ids":["0","1","2"]}' > bundle.json
$B/vesdb-verify bundle bundle.json --log-key log.key.pub --witness-key hse.key.pub --witness-key inn.key.pub --file-hash clip.mkv=1:sha256
python3 - <<'PY'
import json; b=json.load(open("bundle.json")); b["items"][2]["event"]["time_ns"] -= 20_000_000_000; json.dump(b, open("tampered.json","w"))
PY
echo "--- tampered bundle (ack time moved 20 s earlier):"; $B/vesdb-verify bundle tampered.json --log-key log.key.pub --witness-key hse.key.pub --witness-key inn.key.pub | tail -3 || true
echo "--- time series: 3 minutes of 1 Hz H2S, sealed into the log (one event per minute)"
python3 - <<'PY'
import json
t0 = 1_762_000_020 * 10**9
pts = [(t0 + i * 10**9, 14.2 if i == 97 else round(2.0 + (i % 7) / 10, 1)) for i in range(180)]
json.dump({"series": [{"name": "rig-07/gas/h2s", "times": [t for t, _ in pts], "values": [v for _, v in pts]}]}, open("ts.json", "w"))
PY
j() { curl -sf -X POST "http://127.0.0.1:3000/api/v2/ts/$1" -H "authorization: Bearer $2" -H 'content-type: application/json' -d "$3"; }
echo "  write: $(j write $T @ts.json)"
j flush $T '{}' | python3 -c "import json,sys;r=json.load(sys.stdin)['sealed'];print('  sealed',len(r),'chunks:',', '.join(f\"#{c['chunk']} {c['from'][11:19]} n={c['count']} {c['bytes']}B\" for c in r))"
j query $T '{"series":"rig-07/gas/h2s","from":"2025-11-01T12:27:00Z","to":"2025-11-01T12:29:59Z","step":"1m"}' \
  | python3 -c "import json,sys;[print('  ',b['start'],'n',b['count'],'avg',round(b['avg'],3),'max',b['max']) for b in json.load(sys.stdin)['buckets']]"
sleep 1.5
j proof $A '{"series":"rig-07/gas/h2s","time":"2025-11-01T12:28:37Z"}' > point.json
echo -n "point proof: "; $B/vesdb-verify point point.json --log-key log.key.pub --witness-key hse.key.pub --witness-key inn.key.pub | tee point.out | tail -1
sed 's/^/    /' point.out | head -3
python3 -c "import json;p=json.load(open('point.json'));p['value']=4.2;json.dump(p,open('forged-point.json','w'))"
echo -n "forged point (14.2 ppm reported as 4.2): "; $B/vesdb-verify point forged-point.json --log-key log.key.pub --witness-key hse.key.pub --witness-key inn.key.pub | tail -1 || true
