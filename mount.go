//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// vfs is the read side. Its projection comes only from the log, so ls and stat
// never touch the network; a blob is fetched the first time a file is opened.
type vfs struct {
	store  *Store
	mount  string
	mu     *sync.RWMutex
	flight *hydrations
	pre    *prefetcher
}

type hydrations struct {
	mu    sync.Mutex
	paths map[string]*sync.Mutex
}

func (h *hydrations) lock(path string) func() {
	h.mu.Lock()
	lock := h.paths[path]
	if lock == nil {
		lock = &sync.Mutex{}
		h.paths[path] = lock
	}
	h.mu.Unlock()
	lock.Lock()
	return lock.Unlock
}

type node struct {
	fs.LoopbackNode
	v *vfs
}

func (n *node) logical(name string) string {
	return filepath.Join(n.v.mount, n.Path(n.Root()), name)
}

func (v *vfs) entry(path string) (Entry, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	entry, ok := v.store.idx.Entries[path]
	return entry, ok
}

func (v *vfs) isDir(path string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.store.idx.children[path]) > 0
}

func remoteOnly(real string) bool {
	_, err := os.Lstat(real)
	return errors.Is(err, os.ErrNotExist)
}

func stableIno(path string) uint64 {
	sum := fnv.New64a()
	sum.Write([]byte(path))
	return sum.Sum64() | 1<<63
}

func fillAttr(entry Entry, out *fuse.Attr) {
	mode := os.FileMode(entry.Mode)
	out.Mode = syscall.S_IFREG | uint32(mode.Perm())
	if mode&os.ModeSymlink != 0 {
		out.Mode = syscall.S_IFLNK | uint32(mode.Perm())
	}
	out.Size = uint64(entry.Size)
	out.Blocks = (uint64(entry.Size) + 511) / 512
	out.Uid, out.Gid = entry.UID, entry.GID
	out.Mtime = uint64(entry.MtimeNS / 1e9)
	out.Mtimensec = uint32(entry.MtimeNS % 1e9)
	out.Ctime, out.Ctimensec = out.Mtime, out.Mtimensec
	out.Atime, out.Atimensec = out.Mtime, out.Mtimensec
	out.Nlink = 1
}

// Lookup answers from the disk first and the projection second. A directory known
// only to the log is recreated, which is what makes a rebuilt disk browsable.
func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	inode, errno := n.LoopbackNode.Lookup(ctx, name, out)
	if errno != syscall.ENOENT {
		return inode, errno
	}
	path := n.logical(name)
	if entry, ok := n.v.entry(path); ok {
		fillAttr(entry, &out.Attr)
		child := n.RootData.NewNode(n.RootData, n.EmbeddedInode(), name, nil)
		return n.NewInode(ctx, child, fs.StableAttr{Mode: out.Attr.Mode & syscall.S_IFMT, Ino: stableIno(path)}), 0
	}
	if n.v.isDir(path) {
		if err := os.MkdirAll(n.v.store.real(path), 0o755); err != nil {
			return nil, fs.ToErrno(err)
		}
		return n.LoopbackNode.Lookup(ctx, name, out)
	}
	return nil, syscall.ENOENT
}

func (n *node) Getattr(ctx context.Context, handle fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if handle != nil && remoteOnly(n.v.store.real(n.logical(""))) {
		handle = nil // a read-cache copy: its owner and times are not the file's
	}
	errno := n.LoopbackNode.Getattr(ctx, handle, out)
	if errno == syscall.ENOENT {
		if entry, ok := n.v.entry(n.logical("")); ok {
			fillAttr(entry, &out.Attr)
			return 0
		}
	}
	return errno
}

// statxBasic is STATX_BASIC_STATS: everything fillStatx sets.
const statxBasic = 0x7ff

// Statx is how current kernels ask for attributes; Getattr alone leaves remote
// files unreadable to stat and ls -l.
func (n *node) Statx(ctx context.Context, handle fs.FileHandle, flags, mask uint32, out *fuse.StatxOut) syscall.Errno {
	if handle != nil && remoteOnly(n.v.store.real(n.logical(""))) {
		handle = nil
	}
	errno := n.LoopbackNode.Statx(ctx, handle, flags, mask, out)
	if errno != syscall.ENOENT {
		return errno
	}
	entry, ok := n.v.entry(n.logical(""))
	if !ok {
		return errno
	}
	var attr fuse.Attr
	fillAttr(entry, &attr)
	stamp := fuse.SxTime{Sec: attr.Mtime, Nsec: attr.Mtimensec}
	out.Statx = fuse.Statx{
		Mask: statxBasic, Blksize: 4096, Nlink: attr.Nlink, Uid: attr.Uid, Gid: attr.Gid,
		Mode: uint16(attr.Mode), Ino: stableIno(entry.Path), Size: attr.Size, Blocks: attr.Blocks,
		Atime: stamp, Ctime: stamp, Mtime: stamp,
	}
	return 0
}

func (n *node) entries() ([]fuse.DirEntry, syscall.Errno) {
	dir := n.logical("")
	local, err := os.ReadDir(n.v.store.real(dir))
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	seen := map[string]bool{}
	var list []fuse.DirEntry
	for _, item := range local {
		seen[item.Name()] = true
		if strings.Contains(item.Name(), ".pinpin-store-") {
			continue
		}
		list = append(list, fuse.DirEntry{Name: item.Name(), Mode: uint32(item.Type())})
	}
	n.v.mu.RLock()
	defer n.v.mu.RUnlock()
	for name := range n.v.store.idx.children[dir] {
		if seen[name] {
			continue
		}
		mode := uint32(syscall.S_IFDIR)
		if entry, ok := n.v.store.idx.Entries[filepath.Join(dir, name)]; ok {
			mode = syscall.S_IFREG
			if os.FileMode(entry.Mode)&os.ModeSymlink != 0 {
				mode = syscall.S_IFLNK
			}
		}
		list = append(list, fuse.DirEntry{Name: name, Mode: mode})
	}
	sort.Slice(list, func(a, b int) bool { return list[a].Name < list[b].Name })
	return list, 0
}

func (n *node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	list, errno := n.entries()
	if errno != 0 {
		return nil, errno
	}
	return fs.NewListDirStream(list), 0
}

func (n *node) OpendirHandle(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	stream, errno := n.Readdir(ctx)
	return stream, 0, errno
}

// hydrate fetches a remote-only file to its real path. A failed fetch is an I/O
// error to the caller: a sparse stub would hand back zeros instead.
func (n *node) hydrate(ctx context.Context, path string) syscall.Errno {
	unlock := n.v.flight.lock(path)
	defer unlock()
	real := n.v.store.real(path)
	if !remoteOnly(real) {
		return 0
	}
	entry, ok := n.v.entry(path)
	if !ok {
		return syscall.ENOENT
	}
	n.v.mu.RLock()
	object, stored := n.v.store.idx.Objects[entry.SHA]
	n.v.mu.RUnlock()
	if !stored {
		return syscall.EIO
	}
	if free, err := freeBytes(n.v.store.cfg.StateDir); err != nil || free-object.Bytes < n.v.store.cfg.MinFreeBytes {
		return syscall.ENOSPC
	}
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		return fs.ToErrno(err)
	}
	if err := n.v.store.Get(ctx, object, real); err != nil {
		fmt.Fprintln(os.Stderr, "hydrate", path, err)
		return syscall.EIO
	}
	restoreMeta(real, entry)
	return 0
}

// Open serves reads of a remote-only file from the read cache, so a grep across the
// tree costs downloads but never puts files back on disk. Writes hydrate in place.
func (n *node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	path := n.logical("")
	if remoteOnly(n.v.store.real(path)) {
		if flags&syscall.O_ACCMODE == syscall.O_RDONLY && flags&syscall.O_TRUNC == 0 {
			return n.openCached(ctx, path)
		}
		if errno := n.hydrate(ctx, path); errno != 0 {
			return nil, 0, errno
		}
	}
	return n.LoopbackNode.Open(ctx, flags)
}

func (n *node) openCached(ctx context.Context, path string) (fs.FileHandle, uint32, syscall.Errno) {
	entry, ok := n.v.entry(path)
	if !ok {
		return nil, 0, syscall.ENOENT
	}
	copy, errno := n.v.cached(ctx, entry, true)
	if errno != 0 {
		return nil, 0, errno
	}
	fd, err := syscall.Open(copy, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	return fs.NewLoopbackFile(fd), 0, 0
}

// cached returns a verified plaintext copy named by its hash, fetching it if needed.
// Foreground reads feed the prefetcher; its own fetches do not.
func (v *vfs) cached(ctx context.Context, entry Entry, foreground bool) (string, syscall.Errno) {
	unlock := v.flight.lock("cache:" + entry.SHA)
	defer unlock()
	copy := filepath.Join(v.store.readCacheDir(), entry.SHA)
	if _, err := os.Stat(copy); err == nil {
		now := time.Now()
		os.Chtimes(copy, now, now)
		if foreground {
			v.pre.hit(entry.SHA)
		}
		return copy, 0
	}
	if foreground {
		v.pre.miss(entry.Path)
	}
	v.mu.RLock()
	object, stored := v.store.idx.Objects[entry.SHA]
	v.mu.RUnlock()
	if !stored {
		return "", syscall.EIO
	}
	v.store.trimReadCache(object.Bytes)
	if free, err := freeBytes(v.store.cfg.StateDir); err != nil || free-object.Bytes < v.store.cfg.MinFreeBytes {
		return "", syscall.ENOSPC
	}
	if err := os.MkdirAll(v.store.readCacheDir(), 0o700); err != nil {
		return "", fs.ToErrno(err)
	}
	if err := v.store.Get(ctx, object, copy); err != nil {
		fmt.Fprintln(os.Stderr, "read", entry.Path, err)
		return "", syscall.EIO
	}
	return copy, 0
}

func (n *node) Setattr(ctx context.Context, handle fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	path := n.logical("")
	if handle == nil && remoteOnly(n.v.store.real(path)) {
		if errno := n.hydrate(ctx, path); errno != 0 {
			return errno
		}
	}
	return n.LoopbackNode.Setattr(ctx, handle, in, out)
}

// forget records the removal on the write side. The blob stays in the bucket; the
// path just leaves the projection, so rm behaves like rm.
func (v *vfs) forget(path string) syscall.Errno {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.store.idx.Entries[path]; !ok {
		return 0
	}
	return fs.ToErrno(v.store.idx.append([]record{{Removed: path}}))
}

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	path := n.logical(name)
	if !remoteOnly(n.v.store.real(path)) {
		if errno := n.LoopbackNode.Unlink(ctx, name); errno != 0 {
			return errno
		}
	}
	return n.v.forget(path)
}

func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	if n.v.isDir(n.logical(name)) {
		return syscall.ENOTEMPTY
	}
	return n.LoopbackNode.Rmdir(ctx, name)
}

// Rename hydrates a file first. A directory holding remote-only files returns
// EXDEV, which makes mv fall back to copy and delete through this filesystem.
func (n *node) Rename(ctx context.Context, name string, parent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	path := n.logical(name)
	if n.v.isDir(path) {
		return syscall.EXDEV
	}
	if remoteOnly(n.v.store.real(path)) {
		if errno := n.hydrate(ctx, path); errno != 0 {
			return errno
		}
	}
	if errno := n.LoopbackNode.Rename(ctx, name, parent, newName, flags); errno != 0 {
		return errno
	}
	return n.v.forget(path)
}

// Statfs reports the configured capacity, which is the point of the mount. Real
// writes still land on the local disk until a flush and eviction move them.
func (n *node) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	if errno := n.LoopbackNode.Statfs(ctx, out); errno != 0 {
		return errno
	}
	n.v.mu.RLock()
	remote := n.v.store.idx.tierBytes(tierPublic) + n.v.store.idx.tierBytes(tierVault) + n.v.store.idx.tierBytes(tierPrivate)
	n.v.mu.RUnlock()
	block := int64(out.Bsize)
	total := n.v.store.cfg.ViewBytes / block
	free := total - remote/block
	if free < 0 {
		free = 0
	}
	out.Blocks, out.Bfree, out.Bavail = uint64(total), uint64(free), uint64(free)
	return 0
}

// bindRaw exposes the real disk beneath every mount. Propagation must be private,
// or the FUSE mounts would appear here too and flush would read through itself.
func bindRaw(raw string) error {
	if _, err := os.Stat(filepath.Join(raw, "etc/hostname")); err == nil {
		return nil
	}
	if err := os.MkdirAll(raw, 0o700); err != nil {
		return err
	}
	if err := syscall.Mount("/", raw, "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	return syscall.Mount("", raw, "", syscall.MS_PRIVATE, "")
}

// Serve mounts the configured trees and keeps the projection caught up with the
// log. Space is reclaimed only once the key is confirmed to exist elsewhere.
func (s *Store) Serve(ctx context.Context) error {
	if s.cfg.RawRoot == "" || len(s.cfg.Mounts) == 0 {
		return errors.New("serve needs rawRoot and mounts")
	}
	if err := bindRaw(s.cfg.RawRoot); err != nil {
		return fmt.Errorf("raw view: %w", err)
	}
	lock := &sync.RWMutex{}
	flight := &hydrations{paths: map[string]*sync.Mutex{}}
	pre := newPrefetcher(ctx, &vfs{store: s, mu: lock, flight: flight})
	pre.v.pre = pre
	timeout := time.Second
	var servers []*fuse.Server
	for _, mount := range s.cfg.Mounts {
		syscall.Unmount(mount, syscall.MNT_DETACH) // a crashed daemon leaves a dead mount
		v := &vfs{store: s, mount: mount, mu: lock, flight: flight, pre: pre}
		real := s.real(mount)
		var stat syscall.Stat_t
		if err := syscall.Stat(real, &stat); err != nil {
			return err
		}
		root := &fs.LoopbackRoot{Path: real, Dev: stat.Dev}
		root.NewNode = func(data *fs.LoopbackRoot, _ *fs.Inode, _ string, _ *syscall.Stat_t) fs.InodeEmbedder {
			return &node{LoopbackNode: fs.LoopbackNode{RootData: data}, v: v}
		}
		root.RootNode = root.NewNode(root, nil, "", &stat)
		server, err := fs.Mount(mount, root.RootNode, &fs.Options{
			EntryTimeout: &timeout, AttrTimeout: &timeout,
			MountOptions: fuse.MountOptions{AllowOther: true, Name: "pinpin-store", FsName: "pinpin-store:" + mount, DirectMount: true},
		})
		if err != nil {
			return fmt.Errorf("mount %s: %w", mount, err)
		}
		defer server.Unmount()
		servers = append(servers, server)
		fmt.Println("mounted", mount)
	}
	tail, reclaim := time.NewTicker(15*time.Second), time.NewTicker(5*time.Minute)
	defer tail.Stop()
	defer reclaim.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tail.C:
			lock.Lock()
			err := s.idx.tail()
			lock.Unlock()
			if err != nil {
				fmt.Fprintln(os.Stderr, "tail:", err)
			}
		case <-reclaim.C:
			if line := pre.report(); line != "" {
				fmt.Println(line)
			}
			if s.cfg.KeyIsOffMachine {
				lock.RLock()
				freed, err := s.Reclaim()
				lock.RUnlock()
				if err != nil {
					fmt.Fprintln(os.Stderr, "reclaim:", err)
				} else if freed > 0 {
					fmt.Println("reclaimed", human(freed))
				}
			}
		}
	}
}

// Reclaim evicts proven files, least recently read first, until KeepFreeBytes is
// free. Open files are safe: their bytes live until the last descriptor closes.
func (s *Store) Reclaim() (int64, error) {
	free, err := freeBytes(s.cfg.StateDir)
	if err != nil || free >= s.cfg.KeepFreeBytes {
		return 0, err
	}
	type victim struct {
		path  string
		atime int64
		size  int64
	}
	var victims []victim
	for _, mount := range s.cfg.Mounts {
		err := s.walk(mount, func(path string, info os.FileInfo) error {
			entry, ok := entryFor(path, info)
			if !ok || !info.Mode().IsRegular() || !s.idx.current(entry) {
				return nil
			}
			atime := info.Sys().(*syscall.Stat_t).Atim
			victims = append(victims, victim{path, atime.Sec, info.Size()})
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	sort.Slice(victims, func(a, b int) bool { return victims[a].atime < victims[b].atime })
	var freed int64
	for _, item := range victims {
		if free+freed >= s.cfg.KeepFreeBytes {
			break
		}
		real := s.real(item.path)
		if sha, err := hashFile(real); err != nil || sha != s.idx.Entries[item.path].SHA {
			continue
		}
		if err := os.Remove(real); err != nil {
			return freed, err
		}
		freed += item.size
	}
	return freed, nil
}

func (s *Store) readCacheDir() string { return filepath.Join(s.cfg.StateDir, "readcache") }

// trimReadCache keeps the read cache under ReadCacheBytes with room for incoming,
// dropping the least recently used copies. Open copies live until their last close.
func (s *Store) trimReadCache(incoming int64) {
	items, _ := os.ReadDir(s.readCacheDir())
	type cached struct {
		path string
		size int64
		used time.Time
	}
	var copies []cached
	var total int64
	for _, item := range items {
		info, err := item.Info()
		if err != nil || strings.Contains(item.Name(), ".pinpin-store") {
			continue // gone, or a fetch in progress
		}
		copies = append(copies, cached{filepath.Join(s.readCacheDir(), item.Name()), info.Size(), info.ModTime()})
		total += info.Size()
	}
	sort.Slice(copies, func(a, b int) bool { return copies[a].used.Before(copies[b].used) })
	for _, item := range copies {
		if total+incoming <= s.cfg.ReadCacheBytes {
			break
		}
		if os.Remove(item.path) == nil {
			total -= item.size
		}
	}
}
