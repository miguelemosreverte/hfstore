//go:build linux

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The dashboard is one embedded page and two JSON endpoints, served by `serve` on
// uiAddr. It only reads: the index, the use log, the metrics and the disk.

//go:embed ui/index.html
var dashboardPage []byte

type mountStat struct {
	Path        string `json:"path"`
	LocalBytes  int64  `json:"localBytes"`
	LocalFiles  int64  `json:"localFiles"`
	RemoteBytes int64  `json:"remoteBytes"` // in the bucket and not on disk
	RemoteFiles int64  `json:"remoteFiles"`
}

type dashboard struct {
	store *Store
	mu    *sync.RWMutex // the index lock shared with the mounts
	uses  *useLog
	stats *metrics

	scanMu  sync.Mutex
	mounts  []mountStat
	scanned time.Time
}

func (d *dashboard) run(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardPage)
	})
	mux.HandleFunc("GET /api/summary", func(w http.ResponseWriter, r *http.Request) { reply(w, d.summary()) })
	mux.HandleFunc("GET /api/series", func(w http.ResponseWriter, r *http.Request) {
		spans := map[string][2]int64{"1h": {3600, 60}, "6h": {6 * 3600, 300}, "24h": {86400, 900}, "7d": {7 * 86400, 3600}}
		span, ok := spans[r.URL.Query().Get("range")]
		if !ok {
			span = spans["24h"]
		}
		reply(w, d.stats.series(time.Now().Unix()-span[0], span[1]))
	})
	go d.scanEvery(ctx, 15*time.Minute)
	// The address may not exist yet at boot (a VPN address, say), so keep trying.
	for {
		server := &http.Server{Addr: d.store.cfg.UIAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		stop := context.AfterFunc(ctx, func() { server.Close() })
		fmt.Println("dashboard on http://" + d.store.cfg.UIAddr)
		err := server.ListenAndServe()
		stop()
		if ctx.Err() != nil {
			return
		}
		fmt.Fprintln(os.Stderr, "dashboard:", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

func reply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(value)
}

// scanEvery measures each mount: bytes on disk from a walk of the real tree, and
// bytes only in the bucket from the index entries whose real file is gone.
func (d *dashboard) scanEvery(ctx context.Context, every time.Duration) {
	for {
		var out []mountStat
		for _, mount := range d.store.cfg.Mounts {
			stat := mountStat{Path: mount}
			d.store.walk(mount, func(path string, info os.FileInfo) error {
				if info.Mode().IsRegular() {
					stat.LocalBytes += info.Size()
					stat.LocalFiles++
				}
				return nil
			})
			prefix := strings.TrimRight(mount, "/") + "/"
			d.mu.RLock()
			var entries []Entry
			for path, entry := range d.store.idx.Entries {
				if strings.HasPrefix(path, prefix) && entry.SHA != "" {
					entries = append(entries, entry)
				}
			}
			d.mu.RUnlock()
			for _, entry := range entries {
				if remoteOnly(d.store.real(entry.Path)) {
					stat.RemoteBytes += entry.Size
					stat.RemoteFiles++
				}
			}
			out = append(out, stat)
		}
		d.scanMu.Lock()
		d.mounts, d.scanned = out, time.Now()
		d.scanMu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

type hotFile struct {
	Path  string  `json:"path"`
	Score float64 `json:"score"`
	Last  int64   `json:"last"`
	Size  int64   `json:"size"`
	Local bool    `json:"local"`
}

type dayUpload struct {
	Day     string `json:"day"`
	Bytes   int64  `json:"bytes"`
	Objects int64  `json:"objects"`
}

func (d *dashboard) summary() map[string]any {
	now := time.Now()
	var disk syscall.Statfs_t
	syscall.Statfs(d.store.cfg.StateDir, &disk)

	d.mu.RLock()
	paths, objects := len(d.store.idx.Entries), len(d.store.idx.Objects)
	tiers := map[string]int64{tierPublic: d.store.idx.tierBytes(tierPublic), tierVault: d.store.idx.tierBytes(tierVault), tierPrivate: d.store.idx.tierBytes(tierPrivate)}
	days := map[string]*dayUpload{}
	var lastBackup string
	for _, object := range d.store.idx.Objects {
		if object.Verified > lastBackup {
			lastBackup = object.Verified
		}
		if len(object.Verified) < 10 {
			continue
		}
		day := object.Verified[:10]
		if days[day] == nil {
			days[day] = &dayUpload{Day: day}
		}
		days[day].Bytes += object.Bytes
		days[day].Objects++
	}
	d.mu.RUnlock()
	var uploads []dayUpload
	for _, day := range days {
		uploads = append(uploads, *day)
	}
	sort.Slice(uploads, func(a, b int) bool { return uploads[a].Day < uploads[b].Day })
	if len(uploads) > 30 {
		uploads = uploads[len(uploads)-30:]
	}

	d.uses.mu.Lock()
	var hot []hotFile
	for path, item := range d.uses.Files {
		hot = append(hot, hotFile{Path: path, Score: decayed(item.Score, item.Last, now.Unix()), Last: item.Last})
	}
	since, tracked := d.uses.Since, len(d.uses.Files)
	d.uses.mu.Unlock()
	sort.Slice(hot, func(a, b int) bool { return hot[a].Score > hot[b].Score })
	if len(hot) > 20 {
		hot = hot[:20]
	}
	d.mu.RLock()
	for i := range hot {
		hot[i].Size = d.store.idx.Entries[hot[i].Path].Size
	}
	d.mu.RUnlock()
	for i := range hot {
		info, err := os.Stat(d.store.real(hot[i].Path))
		hot[i].Local = err == nil
		if err == nil && hot[i].Size == 0 {
			hot[i].Size = info.Size()
		}
	}

	var cacheBytes int64
	if items, err := os.ReadDir(d.store.readCacheDir()); err == nil {
		for _, item := range items {
			if info, err := item.Info(); err == nil {
				cacheBytes += info.Size()
			}
		}
	}
	d.scanMu.Lock()
	mounts, scanned := d.mounts, d.scanned
	d.scanMu.Unlock()
	host, _ := os.Hostname()
	return map[string]any{
		"now":  now.Unix(),
		"host": host,
		"disk": map[string]int64{
			"free": int64(disk.Bavail) * disk.Bsize, "total": int64(disk.Blocks) * disk.Bsize,
			"keepFree": d.store.cfg.KeepFreeBytes,
		},
		"cache":      map[string]int64{"bytes": cacheBytes, "limit": d.store.cfg.ReadCacheBytes},
		"index":      map[string]any{"paths": paths, "objects": objects, "tiers": tiers, "lastBackup": lastBackup},
		"mounts":     mounts,
		"mountsAt":   scanned.Unix(),
		"uploads":    uploads,
		"hot":        hot,
		"week":       d.stats.totals(),
		"tracking":   map[string]any{"since": since, "files": tracked, "idleDays": d.store.cfg.IdleDays},
		"publicName": d.store.cfg.PublicBucket,
	}
}
