package main

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"sync"
	"time"
)

// useLog records opens through the mounts, which is how hfstore knows what is in use:
// the kernel's atime is useless here, because the nightly flush reads every file.
// Each file keeps a score that halves every usageHalfLife and grows by one per use,
// counting at most one use per usageWindow so a build reading a file ten times is
// one use. Saved under the state directory, so restarts keep the history.
const (
	usageHalfLife = 7 * 24 * time.Hour
	usageWindow   = time.Hour
	promoteScore  = 3 // used in three separate hours within about a week
)

type use struct {
	Score float64 `json:"s"`
	Last  int64   `json:"l"` // unix seconds
}

type useLog struct {
	mu    sync.Mutex
	file  string
	Since int64           `json:"since"` // when tracking began, unix seconds
	Files map[string]*use `json:"files"`
	dirty bool
}

func loadUseLog(file string, now time.Time) *useLog {
	u := &useLog{file: file, Files: map[string]*use{}}
	if raw, err := os.ReadFile(file); err == nil && json.Unmarshal(raw, u) == nil && u.Files != nil {
		return u
	}
	u.Since, u.Files, u.dirty = now.Unix(), map[string]*use{}, true
	return u
}

func decayed(score float64, from, to int64) float64 {
	if to <= from {
		return score
	}
	return score * math.Exp2(-float64(to-from)/usageHalfLife.Seconds())
}

func (u *useLog) touch(path string, now time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	at := now.Unix()
	item := u.Files[path]
	if item == nil {
		item = &use{}
		u.Files[path] = item
	} else if at-item.Last < int64(usageWindow.Seconds()) {
		return
	}
	item.Score = decayed(item.Score, item.Last, at) + 1
	item.Last = at
	u.dirty = true
}

// score is the decayed use count now, and last the time of the latest use, or zero.
func (u *useLog) score(path string, now time.Time) (float64, int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	item := u.Files[path]
	if item == nil {
		return 0, 0
	}
	return decayed(item.Score, item.Last, now.Unix()), item.Last
}

// save writes the history if it changed, dropping files unused for ten half-lives.
func (u *useLog) save(now time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.dirty {
		return nil
	}
	for path, item := range u.Files {
		if now.Unix()-item.Last > int64(10*usageHalfLife.Seconds()) {
			delete(u.Files, path)
		}
	}
	raw, err := json.Marshal(u)
	if err != nil {
		return err
	}
	temp := u.file + ".tmp"
	if err := os.WriteFile(temp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temp, u.file); err != nil {
		return errors.Join(err, os.Remove(temp))
	}
	u.dirty = false
	return nil
}
