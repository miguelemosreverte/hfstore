package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Object is one encrypted blob proven by a fresh download.
type Object struct {
	SHA      string `json:"sha"`
	ID       string `json:"id"`
	Tier     string `json:"tier"`
	Batch    string `json:"batch"`
	Bytes    int64  `json:"bytes"`
	Verified string `json:"verified"`
}

// Entry records a path as of its last flush. Entries are kept after the local
// file disappears, which is what lets ls show remote-only files.
type Entry struct {
	Path    string `json:"path"`
	SHA     string `json:"sha,omitempty"`
	Link    string `json:"link,omitempty"`
	Size    int64  `json:"size"`
	MtimeNS int64  `json:"mtimeNs"`
	Mode    uint32 `json:"mode"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
}

type record struct {
	Object  *Object `json:"object,omitempty"`
	Entry   *Entry  `json:"entry,omitempty"`
	Removed string  `json:"removed,omitempty"`
}

// Index is state derived by replaying the log. The log is append-only JSONL, so a
// crash loses at most a partial last line and never a verified record, and its
// segments in the bucket can rebuild this state on any machine.
type Index struct {
	path     string
	offset   int64
	resolve  func(string) string
	Objects  map[string]Object
	Entries  map[string]Entry
	children map[string]map[string]bool // directory projection for the read side
}

func loadIndex(path string) (*Index, error) {
	idx := &Index{
		path: path, resolve: func(p string) string { return p },
		Objects: map[string]Object{}, Entries: map[string]Entry{}, children: map[string]map[string]bool{},
	}
	return idx, idx.tail()
}

// tail applies log records added since the last call, so a long-lived reader
// follows writers in other processes.
func (idx *Index) tail() error {
	file, err := os.Open(idx.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Seek(idx.offset, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	for {
		line, readErr := reader.ReadBytes('\n')
		if readErr == io.EOF {
			return nil // an unterminated final line is an interrupted append
		}
		if readErr != nil {
			return readErr
		}
		var rec record
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("corrupt index %s: %w", idx.path, err)
		}
		idx.apply(rec)
		idx.offset += int64(len(line))
	}
}

func (idx *Index) link(path string) {
	for path != "/" && path != "." {
		dir, name := filepath.Dir(path), filepath.Base(path)
		if idx.children[dir] == nil {
			idx.children[dir] = map[string]bool{}
		}
		if idx.children[dir][name] {
			return
		}
		idx.children[dir][name] = true
		path = dir
	}
}

func (idx *Index) unlink(path string) {
	for path != "/" && path != "." {
		dir, name := filepath.Dir(path), filepath.Base(path)
		delete(idx.children[dir], name)
		if len(idx.children[dir]) > 0 {
			return
		}
		delete(idx.children, dir)
		path = dir
	}
}

func (idx *Index) apply(rec record) {
	if rec.Object != nil {
		idx.Objects[rec.Object.SHA] = *rec.Object
	}
	if rec.Entry != nil {
		idx.Entries[rec.Entry.Path] = *rec.Entry
		idx.link(rec.Entry.Path)
	}
	if rec.Removed != "" {
		delete(idx.Entries, rec.Removed)
		idx.unlink(rec.Removed)
	}
}

func (idx *Index) append(recs []record) error {
	if len(recs) == 0 {
		return nil
	}
	file, err := os.OpenFile(idx.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	out := bufio.NewWriter(file)
	encoder := json.NewEncoder(out)
	for _, rec := range recs {
		if err := encoder.Encode(rec); err != nil {
			return err
		}
	}
	if err := out.Flush(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return idx.tail()
}

func entryFor(path string, info os.FileInfo) (Entry, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Entry{}, false
	}
	return Entry{
		Path: path, Size: info.Size(), MtimeNS: info.ModTime().UnixNano(),
		Mode: uint32(info.Mode()), UID: stat.Uid, GID: stat.Gid,
	}, true
}

// current reports whether the index still describes the file on disk.
func (idx *Index) current(entry Entry) bool {
	known, ok := idx.Entries[entry.Path]
	if !ok || known.Size != entry.Size || known.MtimeNS != entry.MtimeNS ||
		known.Mode != entry.Mode || known.UID != entry.UID || known.GID != entry.GID {
		return false
	}
	if known.SHA == "" {
		return known.Link != ""
	}
	_, verified := idx.Objects[known.SHA]
	return verified
}

func (idx *Index) tierBytes(tier string) int64 {
	var total int64
	for _, object := range idx.Objects {
		if object.Tier == tier {
			total += object.Bytes
		}
	}
	return total
}

type listing struct {
	Name  string
	State string
	Bytes int64
	Dir   bool
}

// list merges one directory level of the index with the local disk, offline.
func (idx *Index) list(dir string) ([]listing, error) {
	dir = filepath.Clean(dir)
	prefix := strings.TrimRight(dir, "/") + "/"
	rows := map[string]*listing{}
	for path, entry := range idx.Entries {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := path[len(prefix):]
		name, _, nested := strings.Cut(rest, "/")
		row := rows[name]
		if row == nil {
			row = &listing{Name: name, Dir: nested}
			rows[name] = row
		}
		row.Bytes += entry.Size
		if nested {
			continue
		}
		info, err := os.Lstat(idx.resolve(path))
		switch {
		case errors.Is(err, os.ErrNotExist):
			row.State = "remote"
		case err != nil:
			return nil, err
		default:
			row.State = "changed"
			if local, ok := entryFor(path, info); ok && idx.current(local) {
				row.State = "both"
			}
		}
	}
	entries, err := os.ReadDir(idx.resolve(dir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, item := range entries {
		row := rows[item.Name()]
		if row == nil {
			row = &listing{Name: item.Name(), Dir: item.IsDir(), State: "local"}
			if info, infoErr := item.Info(); infoErr == nil && !item.IsDir() {
				row.Bytes = info.Size()
			}
			rows[item.Name()] = row
		}
	}
	out := make([]listing, 0, len(rows))
	for _, row := range rows {
		out = append(out, *row)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

func stamp() string { return time.Now().UTC().Format(time.RFC3339) }
