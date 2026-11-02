// hfstore backs up a whole machine to Hugging Face as client-side encrypted,
// content-addressed blobs: public by default, private for sensitive paths. An
// append-only log is the source of truth, so readers never need to know the tier.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

type Config struct {
	PublicBucket  string   `json:"publicBucket"`
	PrivateBucket string   `json:"privateBucket"`
	Host          string   `json:"host"`
	HF            string   `json:"hf"`
	KeyFile       string   `json:"keyFile"`
	StateDir      string   `json:"stateDir"`
	Roots         []string `json:"roots"`
	Exclude       []string `json:"exclude"`
	Sensitive     []string `json:"sensitive"`
	Evictable     []string `json:"evictable"`
	Mounts        []string `json:"mounts"`
	RawRoot       string   `json:"rawRoot"`
	ViewBytes     int64    `json:"viewBytes"`
	KeepFreeBytes int64    `json:"keepFreeBytes"`
	// ReadCacheBytes bounds the copies that read-only opens of remote files use.
	ReadCacheBytes int64 `json:"readCacheBytes"`
	// VaultInPublic sends credentials to the public bucket, encrypted, instead of the
	// private one. The key file is always excluded from the backup.
	VaultInPublic bool `json:"vaultInPublic"`
	// IdleDays moves files nobody opened or modified for this long off the disk even
	// when there is room. 0 turns it off.
	IdleDays int `json:"idleDays"`

	// KeyIsOffMachine enables automatic eviction. Set it only after copying the key.
	KeyIsOffMachine bool  `json:"keyIsOffMachine"`
	MaxBatchBytes   int64 `json:"maxBatchBytes"`
	MaxBatchFiles   int   `json:"maxBatchFiles"`
	MinFreeBytes    int64 `json:"minFreeBytes"`
	MaxFlushBytes   int64 `json:"maxFlushBytes"`
	PrivateBudget   int64 `json:"privateBudgetBytes"`
}

const gib = int64(1) << 30

func loadConfig(path string) (Config, error) {
	cfg := Config{
		MaxBatchBytes: 256 << 20, MaxBatchFiles: 2000, MinFreeBytes: 2 * gib, MaxFlushBytes: 200 * gib, PrivateBudget: 4 * gib, ViewBytes: 4e12, KeepFreeBytes: 20 * gib, ReadCacheBytes: 2 * gib, IdleDays: 14,
		Roots:     []string{"/"},
		Exclude:   []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/var/cache", "/lost+found", "/swapfile", "/swap.img", "/root/.cache/huggingface/xet"},
		Sensitive: defaultSensitive,
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.PublicBucket == "" || cfg.PrivateBucket == "" || cfg.HF == "" || cfg.KeyFile == "" || cfg.StateDir == "" {
		return cfg, errors.New("config needs publicBucket, privateBucket, hf, keyFile and stateDir")
	}
	if cfg.PublicBucket == cfg.PrivateBucket {
		return cfg, errors.New("publicBucket and privateBucket must differ")
	}
	if cfg.Host == "" {
		if cfg.Host, err = os.Hostname(); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: hfstore [--config FILE] COMMAND

  init                     create the key and both buckets
  status                   bucket usage, index totals, local free space
  flush [--apply]          back up changes (default: report only)
  ls [DIR]                 list a directory from the index, offline
  check [DIR]              what is protected; exits 1 if anything is not
  get PATH|SHA [--out F]   download, verify and restore one file
  evict DIR [--apply --key-is-off-machine]
                           free local bytes already proven in the bucket
  serve                    mount the configured trees for ordinary commands
  pull-index               rebuild the index by replaying the bucket log
`)
	os.Exit(2)
}

func main() {
	config := "/etc/pinpin-store/config.json"
	args := os.Args[1:]
	if len(args) > 1 && args[0] == "--config" {
		config, args = args[1], args[2:]
	}
	if len(args) == 0 {
		usage()
	}
	if err := run(config, args[0], args[1:]); err != nil {
		var exit exitCode
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		fmt.Fprintln(os.Stderr, "hfstore:", err)
		os.Exit(1)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func run(config, command string, args []string) error {
	cfg, err := loadConfig(config)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	// Readers replay the append-only log, so they stay usable during a long flush.
	if command != "status" && command != "ls" && command != "check" && command != "serve" {
		lock, err := os.OpenFile(filepath.Join(cfg.StateDir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		defer lock.Close()
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return errors.New("another hfstore is running")
		}
	}
	ctx := context.Background()
	public := HF{bin: cfg.HF, bucket: cfg.PublicBucket, web: "https://huggingface.co"}
	private := HF{bin: cfg.HF, bucket: cfg.PrivateBucket}
	if command == "init" {
		return initStore(ctx, cfg, public, private)
	}
	keys, keyErr := loadKeys(cfg.KeyFile)
	idx, err := loadIndex(filepath.Join(cfg.StateDir, "index.jsonl"))
	if err != nil {
		return err
	}
	store := &Store{cfg: cfg, public: public, private: private, keys: keys, idx: idx}
	idx.resolve = store.real
	switch command {
	case "status":
		return store.status(ctx)
	case "ls":
		return store.ls(args)
	case "check":
		return store.check(args)
	}
	if keyErr != nil {
		return fmt.Errorf("key: %w", keyErr)
	}
	switch command {
	case "flush":
		return store.flush(ctx, args)
	case "get":
		return store.get(ctx, args)
	case "serve":
		ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return store.Serve(ctx)
	case "evict":
		return store.evict(args)
	case "pull-index":
		return store.Replay(ctx)
	}
	usage()
	return nil
}

func initStore(ctx context.Context, cfg Config, public, private HF) error {
	if err := os.MkdirAll(filepath.Dir(cfg.KeyFile), 0o700); err != nil {
		return err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	file, err := os.OpenFile(cfg.KeyFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	switch {
	case errors.Is(err, os.ErrExist):
		fmt.Println("key: kept existing", cfg.KeyFile)
	case err != nil:
		return err
	default:
		defer file.Close()
		if _, err := file.Write(key); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		fmt.Println("key: created", cfg.KeyFile, "(copy it off this machine: without it nothing can be restored)")
	}
	if err := public.create(ctx, false); err != nil {
		return err
	}
	if err := private.create(ctx, true); err != nil {
		return err
	}
	if err := private.requirePrivate(ctx); err != nil {
		return err
	}
	fmt.Println("buckets: public", cfg.PublicBucket, "and private", cfg.PrivateBucket)
	return nil
}

func human(n int64) string {
	value, units := float64(n), []string{"B", "KB", "MB", "GB", "TB"}
	unit := 0
	for value >= 1000 && unit < len(units)-1 {
		value /= 1000
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}

func (s *Store) status(ctx context.Context) error {
	for _, hf := range []HF{s.public, s.private} {
		info, err := hf.info(ctx)
		if err != nil {
			fmt.Println("bucket: unavailable:", err)
			continue
		}
		visibility := "public"
		if info.Private {
			visibility = "private"
		}
		fmt.Printf("bucket: %s (%s), %s in %d files\n", info.ID, visibility, human(info.Size), info.TotalFiles)
	}
	fmt.Printf("index: %d paths, %d verified objects, %s public, %s vault, %s private of %s budget\n", len(s.idx.Entries), len(s.idx.Objects),
		human(s.idx.tierBytes(tierPublic)), human(s.idx.tierBytes(tierVault)), human(s.idx.tierBytes(tierPrivate)), human(s.cfg.PrivateBudget))
	if free, err := freeBytes(s.cfg.StateDir); err == nil {
		fmt.Println("local free:", human(free))
	}
	return nil
}

func (s *Store) flush(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("flush", flag.ContinueOnError)
	apply := flags.Bool("apply", false, "upload; without this only report")
	maxBytes := flags.Int64("max-bytes", s.cfg.MaxFlushBytes, "stop after uploading this many bytes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	report, err := s.Flush(ctx, *apply, *maxBytes)
	mode := "dry run"
	if *apply {
		mode = "applied"
	}
	fmt.Printf("%s: scanned %d, current %d, changed %d (%s), links %d, to upload %s, uploaded %s in %d batches, remaining %s, sensitive %s, private full %d, skipped %d, raced %d, too large %d\n",
		mode, report.Scanned, report.Current, report.NewFiles, human(report.NewBytes), report.Links,
		human(report.UniqueBytes), human(report.UploadedBytes), report.Batches, human(report.RemainingBytes),
		human(report.SensitiveBytes), report.PrivateFull, report.Skipped, report.Raced, report.TooLarge)
	return err
}

func (s *Store) ls(args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	rows, err := s.idx.list(abs)
	if err != nil {
		return err
	}
	for _, row := range rows {
		name, state := row.Name, row.State
		if row.Dir {
			name += "/"
			if state == "" {
				state = "dir"
			}
		}
		fmt.Printf("%-8s %10s  %s\n", state, human(row.Bytes), name)
	}
	return nil
}

func (s *Store) check(args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	var safeFiles, riskFiles int
	var safeBytes, riskBytes int64
	err = s.walk(abs, func(path string, info os.FileInfo) error {
		entry, ok := entryFor(path, info)
		if ok && info.Mode()&os.ModeSymlink != 0 {
			entry.Link, _ = os.Readlink(s.real(path))
		}
		if ok && s.idx.current(entry) {
			safeFiles++
			safeBytes += info.Size()
			return nil
		}
		riskFiles++
		riskBytes += info.Size()
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("protected %d files (%s), not protected %d files (%s)\n", safeFiles, human(safeBytes), riskFiles, human(riskBytes))
	if riskFiles > 0 {
		return exitCode(1)
	}
	return nil
}

func (s *Store) evict(args []string) error {
	if len(args) == 0 {
		usage()
	}
	flags := flag.NewFlagSet("evict", flag.ContinueOnError)
	apply := flags.Bool("apply", false, "remove local copies; without this only report")
	keySafe := flags.Bool("key-is-off-machine", false, "confirm the key has a copy outside this machine")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	abs, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}
	if *apply && !*keySafe {
		return errors.New("evict --apply needs --key-is-off-machine: evicted files can only be read with the key")
	}
	report, err := s.Evict(abs, *apply)
	if err != nil {
		return err
	}
	verb := "would free"
	if *apply {
		verb = "freed"
	}
	fmt.Printf("%s %s from %d files; kept %d files (%s) not proven in the bucket\n",
		verb, human(report.Bytes), report.Files, report.Kept, human(report.KeptBytes))
	return nil
}

func (s *Store) get(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("get", flag.ContinueOnError)
	out := flags.String("out", "", "destination (default: the original path)")
	if len(args) == 0 {
		usage()
	}
	target := args[0]
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if abs, err := filepath.Abs(target); err == nil && *out == "" {
		if _, isFile := s.idx.Entries[abs]; !isFile {
			if restored, bytes, err := s.GetTree(ctx, abs); err != nil {
				return err
			} else if restored > 0 {
				fmt.Println("restored", restored, "files,", human(bytes))
				return nil
			}
		}
	}
	sha, dest := target, *out
	entry, known := s.idx.Entries[target]
	if abs, err := filepath.Abs(target); !known && err == nil {
		entry, known = s.idx.Entries[abs]
	}
	if known {
		if entry.SHA == "" {
			return fmt.Errorf("%s is a symlink to %s", entry.Path, entry.Link)
		}
		sha = entry.SHA
		if dest == "" {
			dest = entry.Path
		}
	}
	object, stored := s.idx.Objects[strings.ToLower(sha)]
	if !stored {
		return fmt.Errorf("not in the index: %s", target)
	}
	if dest == "" {
		return errors.New("get by hash needs --out")
	}
	if dest == entry.Path {
		dest = s.real(dest)
	}
	if err := s.Get(ctx, object, dest); err != nil {
		return err
	}
	if known {
		restoreMeta(dest, entry)
	}
	fmt.Println("restored", dest, human(object.Bytes))
	return nil
}
