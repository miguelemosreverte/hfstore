package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHF is a real executable that stores buckets in a directory, so tests cover
// the exact argv and file behaviour without credentials or network.
const fakeHF = `#!/bin/sh
map() { echo "$FAKE_ROOT/${1#hf://buckets/}"; }
[ "$1" = buckets ] || exit 9
case "$2" in
info) [ -d "$FAKE_ROOT/$3" ] || { echo missing >&2; exit 1; }
  p=false; [ "$3" = me/vault ] && p=$FAKE_PRIVATE
  echo "hint: noise"; echo "{\"id\":\"$3\",\"private\":$p,\"size\":1,\"total_files\":1}";;
create) mkdir -p "$FAKE_ROOT/$3";;
sync) case "$3" in
  hf://*) cp -R "$(map "$3")/." "$4";;
  *) [ -n "$FAKE_FAIL_UPLOAD" ] && exit 7
     case "$4" in *me/vault*) [ -n "$FAKE_PRIVATE_FULL" ] && { echo "403 Forbidden: Private storage limit reached" >&2; exit 1; };; esac
     mkdir -p "$(map "$4")"; cp -R "$3/." "$(map "$4")/"
     [ -z "$FAKE_CORRUPT" ] || for f in "$(map "$4")"/*; do printf x >> "$f"; done;;
  esac;;
cp) case "$3" in
  hf://*) cp "$(map "$3")" "$4";;
  *) mkdir -p "$(dirname "$(map "$4")")"; cp "$3" "$(map "$4")";;
  esac;;
*) exit 9;;
esac
`

type fixture struct {
	store *Store
	root  string
	fake  string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	base := t.TempDir()
	fake := filepath.Join(base, "remote")
	bin := filepath.Join(base, "hf")
	if err := os.WriteFile(bin, []byte(fakeHF), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, bucket := range []string{"me/vault", "me/blobs"} {
		if err := os.MkdirAll(filepath.Join(fake, bucket), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("FAKE_ROOT", fake)
	t.Setenv("FAKE_PRIVATE", "true")
	root := filepath.Join(base, "machine")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		PublicBucket: "me/blobs", PrivateBucket: "me/vault", Host: "vps", HF: bin, KeyFile: filepath.Join(base, "key"), StateDir: filepath.Join(base, "state"),
		Roots: []string{root}, Exclude: []string{filepath.Join(root, "skip")},
		MaxBatchBytes: 1 << 20, MaxBatchFiles: 2, MinFreeBytes: 0, MaxFlushBytes: 1 << 40,
		PrivateBudget: 1 << 40, Sensitive: defaultSensitive,
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	keys, err := deriveKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := loadIndex(filepath.Join(cfg.StateDir, "index.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return fixture{&Store{cfg: cfg, public: HF{bin: bin, bucket: cfg.PublicBucket}, private: HF{bin: bin, bucket: cfg.PrivateBucket}, keys: keys, idx: idx}, root, fake}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) reload(t *testing.T) *Store {
	t.Helper()
	idx, err := loadIndex(f.store.idx.path)
	if err != nil {
		t.Fatal(err)
	}
	copy := *f.store
	copy.idx = idx
	return &copy
}

func remoteFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	filepath.WalkDir(root, func(path string, item os.DirEntry, err error) error {
		if err == nil && !item.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files
}

func TestEncryptionRoundTripAndTamper(t *testing.T) {
	keys, _ := deriveKeys(bytes.Repeat([]byte{7}, 32))
	for _, size := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 5} {
		plain := make([]byte, size)
		rand.Read(plain)
		var sealed bytes.Buffer
		sha, n, err := keys.encrypt(&sealed, bytes.NewReader(plain), "id")
		if err != nil || int(n) != size {
			t.Fatalf("encrypt %d: %v %d", size, err, n)
		}
		var opened bytes.Buffer
		gotSHA, _, err := keys.decrypt(&opened, bytes.NewReader(sealed.Bytes()), "id")
		if err != nil || gotSHA != sha || !bytes.Equal(opened.Bytes(), plain) {
			t.Fatalf("decrypt %d: %v", size, err)
		}
		if _, _, err := keys.decrypt(&opened, bytes.NewReader(sealed.Bytes()), "other"); err == nil {
			t.Fatalf("object opened under another id, size %d", size)
		}
		flipped := bytes.Clone(sealed.Bytes())
		flipped[len(flipped)-1] ^= 1
		if _, _, err := keys.decrypt(&opened, bytes.NewReader(flipped), "id"); err == nil {
			t.Fatalf("tamper accepted, size %d", size)
		}
		if size >= chunkSize+1 {
			overhead := len(magic) + saltBytes
			cut := sealed.Bytes()[:overhead+chunkSize+16]
			if _, _, err := keys.decrypt(&opened, bytes.NewReader(cut), "id"); err == nil {
				t.Fatalf("truncation at chunk boundary accepted, size %d", size)
			}
		}
	}
}

func TestFlushRoundTripAndNothingPlainReachesBucket(t *testing.T) {
	f := newFixture(t)
	secret := "SUPER-SECRET-TOKEN-VALUE"
	write(t, filepath.Join(f.root, "etc/token"), secret)
	write(t, filepath.Join(f.root, "a/one.txt"), "same bytes")
	write(t, filepath.Join(f.root, "b/two.txt"), "same bytes")
	write(t, filepath.Join(f.root, "skip/never.txt"), "excluded")
	if err := os.Symlink("a/one.txt", filepath.Join(f.root, "link")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	report, err := f.store.Flush(ctx, true, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 4 || report.Links != 1 || report.NewFiles != 3 {
		t.Fatalf("report %+v", report)
	}
	store := f.reload(t)
	if len(store.idx.Objects) != 2 {
		t.Fatalf("dedupe failed: %d objects", len(store.idx.Objects))
	}
	for _, path := range remoteFiles(t, f.fake) {
		raw, _ := os.ReadFile(path)
		if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("same bytes")) || strings.Contains(path, "token") {
			t.Fatalf("plaintext in bucket: %s", path)
		}
	}
	again, err := store.Flush(ctx, true, 1<<40)
	if err != nil || again.Current != 4 || again.Batches != 0 {
		t.Fatalf("second flush %+v %v", again, err)
	}
	token := filepath.Join(f.root, "etc/token")
	if err := os.Remove(token); err != nil {
		t.Fatal(err)
	}
	rows, err := store.idx.list(filepath.Join(f.root, "etc"))
	if err != nil || len(rows) != 1 || rows[0].State != "remote" {
		t.Fatalf("ls remote-only: %+v %v", rows, err)
	}
	object := store.idx.Objects[store.idx.Entries[token].SHA]
	if err := store.Get(ctx, object, token); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(token); string(raw) != secret {
		t.Fatalf("restored %q", raw)
	}
	if err := store.Get(ctx, object, token); err == nil {
		t.Fatal("restore overwrote an existing file")
	}
}

func TestRefusesPublicBucket(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.root, "deploy.key"), "bytes")
	t.Setenv("FAKE_PRIVATE", "false")
	_, err := f.store.Flush(context.Background(), true, 1<<40)
	if err == nil || !strings.Contains(err.Error(), "is public") {
		t.Fatalf("got %v", err)
	}
	if files := remoteFiles(t, f.fake); len(files) != 0 {
		t.Fatalf("uploaded to public bucket: %v", files)
	}
}

func TestDryRunUploadsNothing(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.root, "file"), "bytes")
	report, err := f.store.Flush(context.Background(), false, 1<<40)
	if err != nil || report.NewFiles != 1 || report.UploadedBytes != 0 {
		t.Fatalf("%+v %v", report, err)
	}
	if files := remoteFiles(t, f.fake); len(files) != 0 {
		t.Fatalf("dry run uploaded %v", files)
	}
	if _, err := os.Stat(f.store.idx.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run wrote the index")
	}
}

func TestCorruptRemoteIsNeverRecorded(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.root, "file"), "bytes")
	t.Setenv("FAKE_CORRUPT", "1")
	if _, err := f.store.Flush(context.Background(), true, 1<<40); err == nil {
		t.Fatal("corrupt upload accepted")
	}
	if len(f.reload(t).idx.Objects) != 0 {
		t.Fatal("corrupt object recorded")
	}
	if raw, _ := os.ReadFile(filepath.Join(f.root, "file")); string(raw) != "bytes" {
		t.Fatal("local file altered")
	}
}

func TestFailedUploadRetriesCleanly(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.root, "file"), "bytes")
	ctx := context.Background()
	t.Setenv("FAKE_FAIL_UPLOAD", "1")
	if _, err := f.store.Flush(ctx, true, 1<<40); err == nil {
		t.Fatal("failed upload reported success")
	}
	t.Setenv("FAKE_FAIL_UPLOAD", "")
	report, err := f.reload(t).Flush(ctx, true, 1<<40)
	if err != nil || report.Batches != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.store.cfg.StateDir, "stage")); len(entries) != 0 {
		t.Fatalf("staging left behind: %v", entries)
	}
}

func TestBudgetStopsAndResumes(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		write(t, filepath.Join(f.root, name), name+name)
	}
	ctx := context.Background()
	first, err := f.store.Flush(ctx, true, 1)
	if err != nil || first.Batches != 1 || first.RemainingBytes == 0 {
		t.Fatalf("%+v %v", first, err)
	}
	second, err := f.reload(t).Flush(ctx, true, 1<<40)
	if err != nil || second.RemainingBytes != 0 {
		t.Fatalf("%+v %v", second, err)
	}
	if got := len(f.reload(t).idx.Entries); got != 5 {
		t.Fatalf("entries %d", got)
	}
}

func TestDuplicateAcrossBatchBoundaryIsRecorded(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"a", "b", "c", "d"} {
		write(t, filepath.Join(f.root, name), name)
	}
	write(t, filepath.Join(f.root, "e"), "a") // same bytes as a, walked after the first batch
	if _, err := f.store.Flush(context.Background(), true, 1<<40); err != nil {
		t.Fatal(err)
	}
	store := f.reload(t)
	if len(store.idx.Entries) != 5 || len(store.idx.Objects) != 4 {
		t.Fatalf("entries %d objects %d", len(store.idx.Entries), len(store.idx.Objects))
	}
	if !store.idx.current(mustEntry(t, filepath.Join(f.root, "e"), store)) {
		t.Fatal("duplicate path not protected")
	}
}

func mustEntry(t *testing.T, path string, store *Store) Entry {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := entryFor(path, info)
	return entry
}

func TestSensitiveRoutingAndTransparentRead(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.root, "app/deploy.key")
	plain := filepath.Join(f.root, "img/photo.png")
	write(t, secret, "private bytes")
	write(t, plain, "public bytes")
	ctx := context.Background()
	if _, err := f.store.Flush(ctx, true, 1<<40); err != nil {
		t.Fatal(err)
	}
	store := f.reload(t)
	secretObject := store.idx.Objects[store.idx.Entries[secret].SHA]
	plainObject := store.idx.Objects[store.idx.Entries[plain].SHA]
	if secretObject.Tier != tierPrivate || plainObject.Tier != tierPublic {
		t.Fatalf("tiers %q %q", secretObject.Tier, plainObject.Tier)
	}
	if _, err := os.Stat(filepath.Join(f.fake, "me/blobs/batches", secretObject.Batch, secretObject.ID)); err == nil {
		t.Fatal("sensitive object reached the public bucket")
	}
	for _, path := range remoteFiles(t, filepath.Join(f.fake, "me/blobs/log")) {
		if raw, _ := os.ReadFile(path); bytes.Contains(raw, []byte("deploy.key")) {
			t.Fatal("plaintext log in the public bucket")
		}
	}
	for _, name := range []string{secret, plain} {
		object := store.idx.Objects[store.idx.Entries[name].SHA]
		out := name + ".restored"
		if err := store.Get(ctx, object, out); err != nil {
			t.Fatal(err)
		}
		want, _ := os.ReadFile(name)
		if got, _ := os.ReadFile(out); !bytes.Equal(got, want) {
			t.Fatalf("%s restored wrong", name)
		}
	}
}

func TestPrivateBudgetNeverSpillsToPublic(t *testing.T) {
	f := newFixture(t)
	f.store.cfg.PrivateBudget = 10
	write(t, filepath.Join(f.root, "a.key"), "tiny")
	write(t, filepath.Join(f.root, "b.key"), strings.Repeat("x", 100))
	report, err := f.store.Flush(context.Background(), true, 1<<40)
	if err != nil || report.PrivateFull != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	store := f.reload(t)
	if len(store.idx.Objects) != 1 || store.idx.Objects[store.idx.Entries[filepath.Join(f.root, "a.key")].SHA].Tier != tierPrivate {
		t.Fatalf("%+v", store.idx.Objects)
	}
	if len(remoteFiles(t, filepath.Join(f.fake, "me/blobs/batches"))) != 0 {
		t.Fatal("over-budget sensitive file spilled to public")
	}
}

func TestFullPrivateQuotaDoesNotBlockPublic(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.root, "deploy.key")
	plain := filepath.Join(f.root, "photo.png")
	write(t, secret, "private bytes")
	write(t, plain, "public bytes")
	t.Setenv("FAKE_PRIVATE_FULL", "1")
	report, err := f.store.Flush(context.Background(), true, 1<<40)
	if err != nil || report.PrivateFull != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	store := f.reload(t)
	if _, ok := store.idx.Entries[secret]; ok {
		t.Fatal("unstored sensitive file was recorded as protected")
	}
	if !store.idx.current(mustEntry(t, plain, store)) {
		t.Fatal("public file was held back")
	}
	if got := len(remoteFiles(t, filepath.Join(f.fake, "me/blobs/batches"))); got != 1 {
		t.Fatalf("public objects %d", got)
	}
}

func TestSensitiveRules(t *testing.T) {
	s := Store{cfg: Config{Sensitive: defaultSensitive}}
	for path, want := range map[string]bool{
		"/root/.ssh/id_rsa": true, "/home/pinpin-claude/.ssh/config": true, "/etc/shadow": true,
		"/root/.codex/sessions/2026/a.jsonl": false, "/root/.codex/thread_history_1.sqlite": false,
		"/root/.codex/auth.json": true, "/root/.claude/.credentials.json": true, "/root/.config/pinpin-connect/x.json": true,
		"/root/.cache/huggingface/token": true, "/root/.cache/huggingface/xet/logs/a.log": false, "/srv/app/.env": true, "/x/client_secret.txt": true,
		"/root/.codex/worktrees/a/image.png": false, "/usr/bin/ls": false, "/root/work/a/README.md": false,
	} {
		if got := s.sensitive(path); got != want {
			t.Errorf("%s: got %v", path, got)
		}
	}
}

func TestReplayDetectsMissingSegment(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	write(t, filepath.Join(f.root, "one"), "1")
	if _, err := f.store.Flush(ctx, true, 1<<40); err != nil {
		t.Fatal(err)
	}
	store := f.reload(t)
	write(t, filepath.Join(f.root, "two"), "2")
	if _, err := store.Flush(ctx, true, 1<<40); err != nil {
		t.Fatal(err)
	}
	segments := remoteFiles(t, filepath.Join(f.fake, "me/blobs/log/vps"))
	if len(segments) != 2 {
		t.Fatalf("segments %v", segments)
	}
	os.Remove(segments[0])
	os.Remove(store.idx.path)
	if err := store.Replay(ctx); err == nil || !strings.Contains(err.Error(), "gap") {
		t.Fatalf("got %v", err)
	}
}

func TestEvictFreesOnlyProvenFilesAndRestores(t *testing.T) {
	f := newFixture(t)
	f.store.cfg.Evictable = []string{filepath.Join(f.root, "data")}
	proven := filepath.Join(f.root, "data/proven.png")
	edited := filepath.Join(f.root, "data/edited.png")
	outside := filepath.Join(f.root, "system/lib.so")
	write(t, proven, "proven")
	write(t, edited, "before")
	write(t, outside, "needed")
	ctx := context.Background()
	if _, err := f.store.Flush(ctx, true, 1<<40); err != nil {
		t.Fatal(err)
	}
	store := f.reload(t)
	info, _ := os.Stat(edited)
	write(t, edited, "after!") // same size
	os.Chtimes(edited, info.ModTime(), info.ModTime())
	write(t, filepath.Join(f.root, "data/new.png"), "unsynced")
	if _, err := store.Evict(filepath.Join(f.root, "system"), true); err == nil {
		t.Fatal("evicted outside the evictable tree")
	}
	dry, err := store.Evict(filepath.Join(f.root, "data"), false)
	if err != nil || dry.Files != 1 {
		t.Fatalf("%+v %v", dry, err)
	}
	if _, err := os.Stat(proven); err != nil {
		t.Fatal("dry run removed a file")
	}
	report, err := store.Evict(filepath.Join(f.root, "data"), true)
	if err != nil || report.Files != 1 || report.Kept != 2 {
		t.Fatalf("%+v %v", report, err)
	}
	if raw, _ := os.ReadFile(edited); string(raw) != "after!" {
		t.Fatal("silently edited file was evicted")
	}
	rows, _ := store.idx.list(filepath.Join(f.root, "data"))
	states := map[string]string{}
	for _, row := range rows {
		states[row.Name] = row.State
	}
	if states["proven.png"] != "remote" {
		t.Fatalf("%v", states)
	}
	second, err := store.Flush(ctx, true, 1<<40)
	if err != nil || second.Batches != 1 { // only new.png: same size and mtime reads as unchanged
		t.Fatalf("flush after evict %+v %v", second, err)
	}
	store = f.reload(t)
	restored, _, err := store.GetTree(ctx, filepath.Join(f.root, "data"))
	if err != nil || restored != 1 {
		t.Fatalf("%d %v", restored, err)
	}
	if raw, _ := os.ReadFile(proven); string(raw) != "proven" {
		t.Fatalf("restored %q", raw)
	}
}

func TestIndexRecoversFromBucket(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.root, "file"), "bytes")
	ctx := context.Background()
	if _, err := f.store.Flush(ctx, true, 1<<40); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(f.store.idx.path)
	if err := os.Remove(f.store.idx.path); err != nil {
		t.Fatal(err)
	}
	os.Remove(f.store.idx.path + ".published")
	if err := f.store.Replay(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(f.store.idx.path); !bytes.Equal(got, want) {
		t.Fatal("index differs after recovery")
	}
}

func TestInterruptedIndexAppendIsIgnored(t *testing.T) {
	f := newFixture(t)
	write(t, f.store.idx.path, "{\"entry\":{\"path\":\"/a\"}}\n{\"entry\":{\"pa")
	idx, err := loadIndex(f.store.idx.path)
	if err != nil || len(idx.Entries) != 1 {
		t.Fatalf("%d %v", len(idx.Entries), err)
	}
}

func TestVaultInPublicEncryptsCredentials(t *testing.T) {
	f := newFixture(t)
	f.store.cfg.VaultInPublic = true
	f.store.cfg.PrivateBudget = 0 // the vault must not depend on the private quota
	secret := filepath.Join(f.root, "app/deploy.key")
	write(t, secret, "vault bytes")
	ctx := context.Background()
	if _, err := f.store.Flush(ctx, true, 1<<40); err != nil {
		t.Fatal(err)
	}
	store := f.reload(t)
	store.cfg.VaultInPublic = true
	object := store.idx.Objects[store.idx.Entries[secret].SHA]
	if object.Tier != tierVault {
		t.Fatalf("tier %q", object.Tier)
	}
	blob := filepath.Join(f.fake, "me/blobs/batches", object.Batch, object.ID)
	raw, err := os.ReadFile(blob)
	if err != nil {
		t.Fatal("vault object not in the public bucket:", err)
	}
	if bytes.Contains(raw, []byte("vault bytes")) {
		t.Fatal("credential stored in plaintext")
	}
	out := secret + ".restored"
	if err := store.Get(ctx, object, out); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); string(got) != "vault bytes" {
		t.Fatal("vault object restored wrong")
	}
}
