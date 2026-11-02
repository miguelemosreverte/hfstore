//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Prefetch is read-ahead driven by the index. One cold read fetches one file; a
// second cold read in the same directory within scanWindow looks like a scan, so
// the rest of that directory is fetched in parallel. Two scanned siblings look like
// a recursive walk, so the following sibling directories are fetched as well.
const (
	prefetchWorkers  = 8
	scanWindow       = time.Minute
	prefetchMaxFile  = 32 << 20
	prefetchMaxBytes = 512 << 20
	prefetchMaxFiles = 512
)

type prefetcher struct {
	v     *vfs
	ctx   context.Context
	queue chan Entry

	mu       sync.Mutex
	cold     map[string]time.Time // directory -> last cold read
	expanded map[string]time.Time // directory -> when its files were queued
	pending  map[string]bool      // sha queued or in flight
	fetched  map[string]bool      // sha fetched ahead and not yet read
	inFlight int64

	stats struct{ fetched, bytes, used int64 }
}

func newPrefetcher(ctx context.Context, v *vfs) *prefetcher {
	p := &prefetcher{
		v: v, ctx: ctx, queue: make(chan Entry, prefetchMaxFiles),
		cold: map[string]time.Time{}, expanded: map[string]time.Time{},
		pending: map[string]bool{}, fetched: map[string]bool{},
	}
	for i := 0; i < prefetchWorkers; i++ {
		go p.work()
	}
	return p
}

func (p *prefetcher) work() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case entry := <-p.queue:
			_, errno := p.v.cached(p.ctx, entry, false)
			p.mu.Lock()
			delete(p.pending, entry.SHA)
			p.inFlight -= entry.Size
			if errno == 0 {
				p.fetched[entry.SHA] = true
				p.stats.fetched++
				p.stats.bytes += entry.Size
			}
			p.mu.Unlock()
		}
	}
}

// hit records a foreground read served from the cache, to measure the guesses.
func (p *prefetcher) hit(sha string) {
	p.mu.Lock()
	if p.fetched[sha] {
		delete(p.fetched, sha)
		p.stats.used++
	}
	p.mu.Unlock()
}

// miss records a foreground cold read and starts read-ahead when it looks like a scan.
func (p *prefetcher) miss(path string) {
	dir, now := filepath.Dir(path), time.Now()
	p.mu.Lock()
	last, seen := p.cold[dir]
	p.cold[dir] = now
	scan := seen && now.Sub(last) < scanWindow && now.Sub(p.expanded[dir]) > scanWindow
	if scan {
		p.expanded[dir] = now
	}
	walk := false
	if scan {
		parent := filepath.Dir(dir)
		for other, at := range p.expanded {
			if other != dir && filepath.Dir(other) == parent && now.Sub(at) < scanWindow {
				walk = true
				break
			}
		}
	}
	p.mu.Unlock()
	if !scan {
		return
	}
	dirs := []string{dir}
	if walk {
		dirs = append(dirs, p.followingSiblings(dir)...)
	}
	for _, d := range dirs {
		for _, entry := range p.remoteFiles(d, filepath.Base(path)) {
			if !p.enqueue(entry) {
				return
			}
		}
	}
}

// followingSiblings lists directories after dir under the same parent, in name
// order, each followed by its subdirectories: the order a recursive walk takes.
func (p *prefetcher) followingSiblings(dir string) []string {
	v := p.v
	v.mu.RLock()
	defer v.mu.RUnlock()
	parent := filepath.Dir(dir)
	var names []string
	for name := range v.store.idx.children[parent] {
		if filepath.Join(parent, name) > dir && len(v.store.idx.children[filepath.Join(parent, name)]) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var out []string
	var walk func(string)
	walk = func(d string) {
		if len(out) >= 64 {
			return
		}
		out = append(out, d)
		var subs []string
		for name := range v.store.idx.children[d] {
			if len(v.store.idx.children[filepath.Join(d, name)]) > 0 {
				subs = append(subs, name)
			}
		}
		sort.Strings(subs)
		for _, sub := range subs {
			walk(filepath.Join(d, sub))
		}
	}
	for _, name := range names {
		walk(filepath.Join(parent, name))
	}
	return out
}

// remoteFiles lists the files in dir that are only in the bucket and small enough
// to fetch ahead, starting after the name just read and wrapping around.
func (p *prefetcher) remoteFiles(dir, after string) []Entry {
	v := p.v
	v.mu.RLock()
	var names []string
	for name := range v.store.idx.children[dir] {
		names = append(names, name)
	}
	sort.Strings(names)
	start := sort.SearchStrings(names, after)
	var entries []Entry
	for i := range names {
		name := names[(start+i)%len(names)]
		entry, ok := v.store.idx.Entries[filepath.Join(dir, name)]
		if !ok || entry.SHA == "" || entry.Size > prefetchMaxFile {
			continue
		}
		if _, stored := v.store.idx.Objects[entry.SHA]; stored {
			entries = append(entries, entry)
		}
	}
	v.mu.RUnlock()
	var remote []Entry
	for _, entry := range entries {
		if !remoteOnly(v.store.real(entry.Path)) {
			continue
		}
		if _, err := os.Stat(filepath.Join(v.store.readCacheDir(), entry.SHA)); err == nil {
			continue
		}
		remote = append(remote, entry)
	}
	return remote
}

// enqueue reports false once the read-ahead budget is spent.
func (p *prefetcher) enqueue(entry Entry) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending[entry.SHA] {
		return true
	}
	if p.inFlight+entry.Size > prefetchMaxBytes || len(p.pending) >= prefetchMaxFiles {
		return false
	}
	select {
	case p.queue <- entry:
		p.pending[entry.SHA] = true
		p.inFlight += entry.Size
		return true
	default:
		return false
	}
}

// report returns and resets the counters since the last call.
func (p *prefetcher) report() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stats.fetched == 0 && p.stats.used == 0 {
		return ""
	}
	line := fmt.Sprintf("prefetch: fetched %d (%s), used %d", p.stats.fetched, human(p.stats.bytes), p.stats.used)
	p.stats.fetched, p.stats.bytes, p.stats.used = 0, 0, 0
	if len(p.fetched) > 4*prefetchMaxFiles {
		p.fetched = map[string]bool{} // guesses long since trimmed from the cache
	}
	for dir, at := range p.cold {
		if time.Since(at) > scanWindow {
			delete(p.cold, dir)
			delete(p.expanded, dir)
		}
	}
	return line
}
