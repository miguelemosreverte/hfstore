package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Store struct {
	cfg             Config
	public, private HF
	keys            Keys
	idx             *Index
}

const (
	tierPublic  = "public"
	tierPrivate = "private"
	// tierVault holds credentials in the public bucket, under the same encryption as
	// everything else. Used only when the owner sets vaultInPublic.
	tierVault = "vault"
)

func (s *Store) bucket(tier string) HF {
	if tier == tierPrivate {
		return s.private
	}
	return s.public
}

// defaultSensitive covers credentials only: everything else is public by policy,
// sessions included. A leading slash matches a path prefix, one * per segment;
// anything else matches a basename in any directory.
var defaultSensitive = []string{
	"/etc/shadow", "/etc/gshadow", "/etc/ssh", "/etc/pinpin-store",
	"/root/.ssh", "/home/*/.ssh", "/root/.gnupg", "/root/.cache/huggingface/token",
	"/root/.cache/huggingface/stored_tokens",
	"/root/.config/pinpin-*", "/root/.local/share/pinpin-access", "/root/.codex/auth.json",
	".credentials.json", ".env", ".env.*", "*.pem", "*.key", "*.p12", "id_rsa*", "id_ed25519*",
	"token", "*token*.json", "*credential*", "*secret*", ".netrc", ".git-credentials",
}

func (s *Store) sensitive(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	parts := strings.Split(path, "/")
	for _, rule := range s.cfg.Sensitive {
		if !strings.HasPrefix(rule, "/") {
			if ok, _ := filepath.Match(rule, base); ok {
				return true
			}
			continue
		}
		want := strings.Split(rule, "/")
		if len(parts) < len(want) {
			continue
		}
		if ok, _ := filepath.Match(rule, strings.Join(parts[:len(want)], "/")); ok {
			return true
		}
	}
	return false
}

type candidate struct {
	entry Entry
	sha   string
	tier  string
}

type Report struct {
	Scanned, Current, NewFiles, Links, Skipped, Raced, TooLarge, PrivateFull, Batches int
	NewBytes, UniqueBytes, SensitiveBytes, UploadedBytes, RemainingBytes              int64
}

// real maps a logical path to the disk beneath any mount.
func (s *Store) real(path string) string {
	if s.cfg.RawRoot == "" {
		return path
	}
	return filepath.Join(s.cfg.RawRoot, path)
}

func (s *Store) logical(path string) string {
	if s.cfg.RawRoot == "" {
		return path
	}
	if rest := strings.TrimPrefix(path, s.cfg.RawRoot); rest != "" {
		return rest
	}
	return "/"
}

func restoreMeta(path string, entry Entry) {
	os.Chmod(path, os.FileMode(entry.Mode).Perm())
	os.Chown(path, int(entry.UID), int(entry.GID))
	mtime := time.Unix(0, entry.MtimeNS)
	os.Chtimes(path, mtime, mtime)
}

func (s *Store) excluded(path string) bool {
	for _, skip := range append(s.cfg.Exclude, s.cfg.StateDir, s.cfg.KeyFile) {
		if path == skip || strings.HasPrefix(path, strings.TrimRight(skip, "/")+"/") {
			return true
		}
	}
	return false
}

// walk visits regular files and symlinks. It stays on each root's filesystem, so
// pseudo filesystems and other mounts are never read.
func (s *Store) walk(root string, visit func(path string, info os.FileInfo) error) error {
	if s.cfg.RawRoot != "" {
		if _, err := os.Stat(filepath.Join(s.cfg.RawRoot, "etc/hostname")); err != nil {
			return fmt.Errorf("raw view %s is not mounted: %w", s.cfg.RawRoot, err)
		}
	}
	rootInfo, err := os.Lstat(s.real(root))
	if err != nil {
		return err
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unsupported filesystem metadata")
	}
	return filepath.WalkDir(s.real(root), func(raw string, item fs.DirEntry, err error) error {
		path := s.logical(raw)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
				return nil // a racing delete; the next flush sees the settled tree
			}
			return err
		}
		if s.excluded(path) {
			if item.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := item.Info()
		if err != nil {
			return nil
		}
		if item.IsDir() {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Dev != rootStat.Dev {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return visit(path, info)
		}
		return nil
	})
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func freeBytes(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

// plan scans the roots and splits changes into records that need no upload and
// candidates whose bytes are not yet in the bucket.
func (s *Store) plan(report *Report) ([]candidate, []record, error) {
	var work []candidate
	var ready []record
	seen := map[string]bool{}
	for _, root := range s.cfg.Roots {
		err := s.walk(root, func(path string, info os.FileInfo) error {
			report.Scanned++
			entry, ok := entryFor(path, info)
			if !ok {
				report.Skipped++
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(s.real(path))
				if err != nil {
					report.Skipped++
					return nil
				}
				entry.Link = target
				if s.idx.current(entry) {
					report.Current++
					return nil
				}
				report.Links++
				ready = append(ready, record{Entry: &entry})
				return nil
			}
			if s.idx.current(entry) {
				report.Current++
				return nil
			}
			sha, err := hashFile(s.real(path))
			if err != nil {
				report.Skipped++
				return nil
			}
			entry.SHA = sha
			report.NewFiles++
			report.NewBytes += entry.Size
			if _, stored := s.idx.Objects[sha]; stored {
				ready = append(ready, record{Entry: &entry})
				return nil
			}
			tier := tierPublic
			if s.sensitive(path) {
				tier = s.secretTier()
			}
			if !seen[sha] {
				seen[sha] = true
				report.UniqueBytes += entry.Size
				if tier != tierPublic {
					report.SensitiveBytes += entry.Size
				}
			}
			work = append(work, candidate{entry: entry, sha: sha, tier: tier})
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	return work, ready, nil
}

func (s *Store) stageObject(dir string, c candidate, id string) error {
	source, err := os.Open(s.real(c.entry.Path))
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.OpenFile(filepath.Join(dir, id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer target.Close()
	sha, _, err := s.keys.encrypt(target, source, id)
	if err != nil {
		return err
	}
	if sha != c.sha {
		return errRaced
	}
	return target.Sync()
}

var errRaced = errors.New("file changed while being read")

func newBatchID() string {
	suffix := make([]byte, 4)
	rand.Read(suffix)
	return time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(suffix)
}

// commit uploads a staged batch, frees the staging copy, then proves every object
// from a fresh download. Nothing reaches the index until that proof succeeds, so
// a crash leaves at worst an unreferenced remote batch.
func (s *Store) commit(ctx context.Context, tier, batch, stage string, pending []candidate) ([]record, error) {
	hf := s.bucket(tier)
	if tier == tierPrivate {
		if err := hf.requirePrivate(ctx); err != nil {
			return nil, err
		}
	}
	remote := "batches/" + batch
	if err := hf.syncUp(ctx, stage, remote); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(stage); err != nil {
		return nil, err
	}
	check := filepath.Join(s.cfg.StateDir, "verify", batch)
	defer os.RemoveAll(check)
	if err := os.MkdirAll(check, 0o700); err != nil {
		return nil, err
	}
	if err := hf.syncDown(ctx, remote, check); err != nil {
		return nil, err
	}
	now := stamp()
	var recs []record
	proved := map[string]bool{}
	for _, c := range pending {
		id := s.keys.objectID(c.sha)
		if !proved[c.sha] {
			if err := s.proveObject(filepath.Join(check, id), id, c); err != nil {
				return nil, fmt.Errorf("verify %s: %w", c.entry.Path, err)
			}
			proved[c.sha] = true
			object := Object{SHA: c.sha, ID: id, Tier: tier, Batch: batch, Bytes: c.entry.Size, Verified: now}
			recs = append(recs, record{Object: &object})
		}
		entry := c.entry
		recs = append(recs, record{Entry: &entry})
	}
	return recs, nil
}

func (s *Store) proveObject(path, id string, c candidate) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	sha, size, err := s.keys.decrypt(io.Discard, file, id)
	if err != nil {
		return err
	}
	if sha != c.sha || size != c.entry.Size {
		return errors.New("remote bytes do not match the local hash")
	}
	return nil
}

func (s *Store) secretTier() string {
	if s.cfg.VaultInPublic {
		return tierVault
	}
	return tierPrivate
}

// Flush uploads changes up to maxBytes. It never deletes or alters local files.
// Sensitive files go first and smallest first, so credentials are safe before
// large session logs use up the private budget. Files that do not fit stay
// unprotected and are reported: they never spill into the public bucket, and a
// full private tier does not hold back the public one.
func (s *Store) Flush(ctx context.Context, apply bool, maxBytes int64) (Report, error) {
	var report Report
	work, ready, err := s.plan(&report)
	if err != nil {
		return report, err
	}
	report.RemainingBytes = report.UniqueBytes
	if !apply {
		return report, nil
	}
	// A killed run leaves staged ciphertext behind, and the disk may have no room for it.
	for _, leftover := range []string{"stage", "verify"} {
		if err := os.RemoveAll(filepath.Join(s.cfg.StateDir, leftover)); err != nil {
			return report, err
		}
	}
	if err := s.idx.append(ready); err != nil {
		return report, err
	}
	var secret, open []candidate
	for _, c := range work {
		if c.tier != tierPublic {
			secret = append(secret, c)
		} else {
			open = append(open, c)
		}
	}
	// Smallest first, so one oversized file cannot hold back everything behind it.
	sort.SliceStable(secret, func(a, b int) bool { return secret[a].entry.Size < secret[b].entry.Size })
	sort.SliceStable(open, func(a, b int) bool { return open[a].entry.Size < open[b].entry.Size })
	if err := s.uploadTier(ctx, s.secretTier(), secret, maxBytes, &report); err != nil {
		return report, err
	}
	if err := s.uploadTier(ctx, tierPublic, open, maxBytes, &report); err != nil {
		return report, err
	}
	return report, s.publishLog(ctx)
}

func (s *Store) uploadTier(ctx context.Context, tier string, work []candidate, maxBytes int64, report *Report) error {
	staged := map[string]bool{}
	for next := 0; next < len(work) && report.UploadedBytes < maxBytes; {
		batch := newBatchID()
		stage := filepath.Join(s.cfg.StateDir, "stage", batch)
		if err := os.MkdirAll(stage, 0o700); err != nil {
			return err
		}
		var pending []candidate
		var batchBytes int64
		count := 0
		for next < len(work) && count < s.cfg.MaxBatchFiles && batchBytes < s.cfg.MaxBatchBytes {
			c := work[next]
			free, err := freeBytes(s.cfg.StateDir)
			if err != nil {
				return err
			}
			if free-c.entry.Size < s.cfg.MinFreeBytes {
				if len(pending) > 0 {
					break // commit frees the staged bytes, then this file gets a retry
				}
				report.TooLarge++
				next++
				continue
			}
			next++
			if _, stored := s.idx.Objects[c.sha]; stored {
				if err := s.idx.append([]record{{Entry: &c.entry}}); err != nil {
					return err
				}
				continue
			}
			if staged[c.sha] {
				pending = append(pending, c)
				continue
			}
			if tier == tierPrivate && s.idx.tierBytes(tierPrivate)+batchBytes+c.entry.Size > s.cfg.PrivateBudget {
				report.PrivateFull++
				continue
			}
			id := s.keys.objectID(c.sha)
			switch err := s.stageObject(stage, c, id); {
			case errors.Is(err, errRaced), errors.Is(err, os.ErrNotExist):
				os.Remove(filepath.Join(stage, id))
				report.Raced++
				continue
			case err != nil:
				return err
			}
			staged[c.sha] = true
			pending = append(pending, c)
			batchBytes += c.entry.Size
			count++
		}
		if len(pending) == 0 {
			os.RemoveAll(stage)
			continue
		}
		recs, err := s.commit(ctx, tier, batch, stage, pending)
		if err != nil {
			os.RemoveAll(stage)
			if tier == tierPrivate && strings.Contains(err.Error(), "storage limit") {
				report.PrivateFull += len(pending) + len(work) - next
				return nil
			}
			return err
		}
		if err := s.idx.append(recs); err != nil {
			return err
		}
		clear(staged)
		report.Batches++
		report.UploadedBytes += batchBytes
		report.RemainingBytes -= batchBytes
		if err := s.publishLog(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) logPrefix() string { return "log/" + s.cfg.Host }

// publishLog uploads the log bytes not yet in the bucket as one immutable segment
// named by its start offset, so a retry rewrites the same segment and replaying
// segments in name order rebuilds the log exactly. Segments are encrypted, so the
// public bucket works and the log survives a full private quota.
func (s *Store) publishLog(ctx context.Context) error {
	cursor := s.idx.path + ".published"
	var offset int64
	if raw, err := os.ReadFile(cursor); err == nil {
		if offset, err = strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err != nil {
			return fmt.Errorf("%s: %w", cursor, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	source, err := os.Open(s.idx.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	if info.Size() <= offset {
		return nil
	}
	if _, err := source.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	name := fmt.Sprintf("%020d.enc", offset)
	remote := s.logPrefix() + "/" + name
	temp := filepath.Join(s.cfg.StateDir, "segment.upload")
	target, err := os.OpenFile(temp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	defer target.Close()
	end := info.Size()
	if _, _, err := s.keys.encrypt(target, io.LimitReader(source, end-offset), remote); err != nil {
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	if err := s.public.put(ctx, temp, remote); err != nil {
		return err
	}
	return os.WriteFile(cursor, []byte(strconv.FormatInt(end, 10)), 0o600)
}

// Replay rebuilds the local log from the bucket after losing the disk.
func (s *Store) Replay(ctx context.Context) error {
	if _, err := os.Stat(s.idx.path); err == nil {
		return fmt.Errorf("refusing to replace existing log %s", s.idx.path)
	}
	temp := filepath.Join(s.cfg.StateDir, "replay")
	defer os.RemoveAll(temp)
	if err := os.MkdirAll(temp, 0o700); err != nil {
		return err
	}
	if err := s.public.syncDown(ctx, s.logPrefix(), temp); err != nil {
		return err
	}
	segments, err := os.ReadDir(temp)
	if err != nil {
		return err
	}
	rebuilt := s.idx.path + ".replay"
	defer os.Remove(rebuilt)
	out, err := os.OpenFile(rebuilt, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	var end int64
	for _, segment := range segments { // ReadDir sorts; names are zero-padded offsets
		start, err := strconv.ParseInt(strings.TrimSuffix(segment.Name(), ".enc"), 10, 64)
		if err != nil || start != end {
			return fmt.Errorf("log segment gap at %s", segment.Name())
		}
		file, err := os.Open(filepath.Join(temp, segment.Name()))
		if err != nil {
			return err
		}
		_, size, err := s.keys.decrypt(out, file, s.logPrefix()+"/"+segment.Name())
		file.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", segment.Name(), err)
		}
		end += size
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := os.WriteFile(s.idx.path+".published", []byte(strconv.FormatInt(end, 10)), 0o600); err != nil {
		return err
	}
	return os.Link(rebuilt, s.idx.path)
}

type EvictReport struct {
	Files, Kept      int
	Bytes, KeptBytes int64
}

// Evict removes local copies of files proven in the bucket. It is limited to the
// configured evictable trees, because a running system needs most of its files
// on the real disk. Each file is re-hashed first, so a change that left the size
// and mtime alone can never lose data. ls then reports the file as remote.
func (s *Store) Evict(dir string, apply bool) (EvictReport, error) {
	var report EvictReport
	if !underAny(dir, append(s.cfg.Evictable, s.cfg.Mounts...)) {
		return report, fmt.Errorf("%s is not under a configured evictable tree", dir)
	}
	err := s.walk(dir, func(path string, info os.FileInfo) error {
		entry, ok := entryFor(path, info)
		if !ok || !info.Mode().IsRegular() {
			return nil
		}
		object, proven := s.idx.Objects[s.idx.Entries[path].SHA]
		if !proven || !s.idx.current(entry) {
			report.Kept++
			report.KeptBytes += info.Size()
			return nil
		}
		if sha, err := hashFile(s.real(path)); err != nil || sha != object.SHA {
			report.Kept++
			report.KeptBytes += info.Size()
			return nil
		}
		report.Files++
		report.Bytes += info.Size()
		if apply {
			return os.Remove(s.real(path))
		}
		return nil
	})
	return report, err
}

func underAny(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, strings.TrimRight(root, "/")+"/") {
			return true
		}
	}
	return false
}

// GetTree restores every remote-only file under dir, skipping files on disk.
func (s *Store) GetTree(ctx context.Context, dir string) (int, int64, error) {
	prefix := strings.TrimRight(dir, "/") + "/"
	var paths []string
	for path, entry := range s.idx.Entries {
		if strings.HasPrefix(path, prefix) && entry.SHA != "" {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	var restored int
	var total int64
	for _, path := range paths {
		real := s.real(path)
		if _, err := os.Lstat(real); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		entry := s.idx.Entries[path]
		object, ok := s.idx.Objects[entry.SHA]
		if !ok {
			return restored, total, fmt.Errorf("no verified object for %s", path)
		}
		if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
			return restored, total, err
		}
		if err := s.Get(ctx, object, real); err != nil {
			return restored, total, err
		}
		restoreMeta(real, entry)
		restored++
		total += object.Bytes
	}
	return restored, total, nil
}

// Get downloads one object and materializes it at out without overwriting.
func (s *Store) Get(ctx context.Context, object Object, out string) error {
	temp := out + ".pinpin-store-enc"
	defer os.Remove(temp)
	if err := s.bucket(object.Tier).fetch(ctx, "batches/"+object.Batch+"/"+object.ID, temp); err != nil {
		return err
	}
	return decryptTo(s.keys, temp, object.ID, out, object.SHA, object.Bytes)
}

// decryptTo verifies before publishing: the plaintext only appears at out, by
// hard link, once it passes, and an existing file is never replaced.
func decryptTo(keys Keys, source, id, out, wantSHA string, wantSize int64) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temp := out + ".pinpin-store-tmp"
	defer os.Remove(temp)
	output, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer output.Close()
	sha, size, err := keys.decrypt(output, input, id)
	if err != nil {
		return err
	}
	if wantSHA != "" && (sha != wantSHA || size != wantSize) {
		return errors.New("downloaded bytes do not match the index")
	}
	if err := output.Sync(); err != nil {
		return err
	}
	return os.Link(temp, out)
}
