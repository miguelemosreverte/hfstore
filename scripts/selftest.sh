#!/bin/bash
# Fresh-machine test of hfstore, following its README, isolated from the real backup:
# own buckets, key, state, test folder and raw view. Run as root:
#   OWNER=your-hf-user [HF=/path/to/hf] scripts/selftest.sh
# Afterwards delete the two $OWNER/hfstore-selftest-* buckets and /root/hfstore-selftest.
set -euo pipefail
export PATH=$PATH:/usr/local/go/bin HOME=/root HF_HUB_DISABLE_PROGRESS_BARS=1 HF_XET_LOG_DEST=/dev/null
T=/root/hfstore-selftest
HF=${HF:-$(command -v hf)}
OWNER=${OWNER:?set OWNER to your Hugging Face user, e.g. OWNER=me}
step() { echo; echo "== $*"; }

step "1. clone from GitHub and build"
mkdir -p "$T"
git clone -q https://github.com/miguelemosreverte/hfstore "$T/src"
(cd "$T/src" && go build -o "$T/hfstore" .)
H="$T/hfstore"

step "2. sample data: 31 files in two folders, plus one credential"
mkdir -p "$T/data/photos" "$T/data/notes"
head -c 3000000 /dev/urandom > "$T/data/photos/big.bin"
for i in $(seq -w 1 30); do head -c 20000 /dev/urandom > "$T/data/photos/p$i.bin"; done
echo "meeting notes" > "$T/data/notes/notes.txt"
echo "API_KEY=selftest" > "$T/data/notes/.env"
(cd "$T/data" && find . -type f | sort | xargs sha256sum) > "$T/original.sha"

step "3. config, as the README says"
cat > "$T/config.json" <<EOF
{
  "publicBucket": "$OWNER/hfstore-selftest-blobs",
  "privateBucket": "$OWNER/hfstore-selftest-vault",
  "hf": "$HF",
  "keyFile": "$T/key",
  "stateDir": "$T/state",
  "roots": ["$T/data"],
  "exclude": [],
  "evictable": ["$T/data"],
  "vaultInPublic": true
}
EOF
$H --config "$T/config.json" init

step "4. back up"
$H --config "$T/config.json" flush --apply | tail -1
$H --config "$T/config.json" check "$T/data" | tail -2

step "5. free the disk"
$H --config "$T/config.json" evict "$T/data" --apply --key-is-off-machine | tail -1
echo "files left on disk: $(find "$T/data" -type f | wc -l)"

step "6. mount and read through it with ordinary commands"
python3 - "$T" <<'P'
import json,sys
t=sys.argv[1]; p=t+"/config.json"; c=json.load(open(p))
c.update(rawRoot="/mnt/hfstore-selftest-raw", mounts=[t+"/data"], keyIsOffMachine=True)
json.dump(c,open(p,"w"),indent=2)
P
$H --config "$T/config.json" serve > "$T/serve.log" 2>&1 &
SERVE=$!
for _ in $(seq 30); do findmnt "$T/data" >/dev/null && break; sleep 1; done
echo "ls: $(ls "$T/data/photos" | wc -l) files in photos, du: $(du -sh --apparent-size "$T/data" | cut -f1)"
(cd "$T/data" && sha256sum -c --quiet "$T/original.sha") && echo "all 33 files read back through the mount: hashes OK"
grep -rl selftest "$T/data" && echo "grep through the mount works"
echo "files back on real disk after reading: $(find /mnt/hfstore-selftest-raw$T/data -type f | wc -l)"
kill $SERVE; wait $SERVE || true
umount "$T/data" 2>/dev/null || true
umount /mnt/hfstore-selftest-raw
rmdir /mnt/hfstore-selftest-raw

step "7. second machine: only the key, rebuild the index from the bucket"
python3 - "$T" <<'P'
import json,sys
t=sys.argv[1]; c=json.load(open(t+"/config.json"))
for k in ("rawRoot","mounts","keyIsOffMachine"): c.pop(k)
c["stateDir"]=t+"/state2"
json.dump(c,open(t+"/config2.json","w"),indent=2)
P
$H --config "$T/config2.json" pull-index | tail -1
$H --config "$T/config2.json" ls "$T/data/notes"
$H --config "$T/config2.json" get "$T/data/notes/.env" --out "$T/env.restored"
[ "$(cat "$T/env.restored")" = "API_KEY=selftest" ] && echo "credential restored on the second machine"

step "8. what is in the public bucket"
$HF buckets list --format json | python3 -c "
import json,sys
for b in json.load(sys.stdin):
    if 'selftest' in b['id']: print(b['id'], 'private' if b.get('private') else 'public', b.get('total_files'), 'files')"
echo "plaintext 'API_KEY' in bucket blobs: $($HF buckets sync hf://buckets/$OWNER/hfstore-selftest-blobs "$T/bucket-copy" >/dev/null 2>&1; grep -rl API_KEY "$T/bucket-copy" | wc -l)"
echo; echo "SELFTEST PASSED"
