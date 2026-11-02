//go:build linux

package main

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUseLogScoresDecayAndPersist(t *testing.T) {
	file := filepath.Join(t.TempDir(), "usage.json")
	start := time.Unix(1_800_000_000, 0)
	u := loadUseLog(file, start)
	for i := 0; i < 5; i++ {
		u.touch("/a", start.Add(time.Duration(i)*time.Minute)) // one window: one use
	}
	u.touch("/a", start.Add(2*time.Hour))
	if score, _ := u.score("/a", start.Add(2*time.Hour)); math.Abs(score-2) > 0.01 {
		t.Fatalf("score %v, want about 2", score)
	}
	if score, _ := u.score("/a", start.Add(2*time.Hour+usageHalfLife)); math.Abs(score-1) > 0.01 {
		t.Fatalf("score after a half-life %v, want about 1", score)
	}
	if err := u.save(start.Add(3 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	again := loadUseLog(file, start.Add(time.Hour*100))
	if again.Since != start.Unix() {
		t.Fatalf("tracking start lost: %d", again.Since)
	}
	if score, last := again.score("/a", start.Add(2*time.Hour)); math.Abs(score-2) > 0.01 || last != start.Add(2*time.Hour).Unix() {
		t.Fatalf("reloaded score %v last %d", score, last)
	}
}

// An idle sweep moves only files nobody opened or modified for IdleDays, and no sweep
// ever removes a file the daemon holds open.
func TestReclaimIdleAndOpenFiles(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	old := now.Add(-20 * 24 * time.Hour)
	idle := filepath.Join(f.root, "idle.bin")
	used := filepath.Join(f.root, "used.bin")
	fresh := filepath.Join(f.root, "fresh.bin")
	held := filepath.Join(f.root, "held.bin")
	for _, path := range []string{idle, used, fresh, held} {
		write(t, path, path)
	}
	for _, path := range []string{idle, used, held} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.Flush(context.Background(), true, 1<<40); err != nil {
		t.Fatal(err)
	}
	store := f.reload(t)
	store.cfg.Mounts, store.cfg.IdleDays, store.cfg.KeepFreeBytes = []string{f.root}, 14, 0
	uses := loadUseLog(filepath.Join(t.TempDir(), "usage.json"), now)
	uses.Since = now.Add(-30 * 24 * time.Hour).Unix()
	uses.touch(used, now.Add(-time.Hour))
	handle, err := os.Open(held)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	if freed, _, err := store.Reclaim(uses, now, false); err != nil || freed != 0 {
		t.Fatalf("no sweep and room to spare must free nothing: %d %v", freed, err)
	}
	if _, _, err := store.Reclaim(uses, now, true); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{idle: false, used: true, fresh: true, held: true} {
		if _, err := os.Stat(path); (err == nil) != want {
			t.Errorf("%s on disk = %v, want %v", filepath.Base(path), err == nil, want)
		}
	}

	// Under pressure everything proven goes, except what is open.
	store.cfg.KeepFreeBytes = 1 << 62
	if _, _, err := store.Reclaim(uses, now, false); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{used: false, fresh: false, held: true} {
		if _, err := os.Stat(path); (err == nil) != want {
			t.Errorf("under pressure %s on disk = %v, want %v", filepath.Base(path), err == nil, want)
		}
	}
}

// Tracking that began recently protects files whose use was never observed.
func TestReclaimWaitsForUsageHistory(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	old := now.Add(-60 * 24 * time.Hour)
	path := filepath.Join(f.root, "old.bin")
	write(t, path, "old")
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Flush(context.Background(), true, 1<<40); err != nil {
		t.Fatal(err)
	}
	store := f.reload(t)
	store.cfg.Mounts, store.cfg.IdleDays, store.cfg.KeepFreeBytes = []string{f.root}, 14, 0
	uses := loadUseLog(filepath.Join(t.TempDir(), "usage.json"), now.Add(-2*24*time.Hour))
	if _, _, err := store.Reclaim(uses, now, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("evicted a file before 14 days of usage history existed")
	}
}
