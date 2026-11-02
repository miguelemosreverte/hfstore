# hfstore

Backs up a whole machine to Hugging Face. Everything is public unless the owner says
otherwise or it is plainly a credential, such as an API key, which goes private. Every blob is encrypted on this machine first, so a
misclassified file exposes nothing. An append-only log is the source of truth; the
local index is its replay, and readers never need to know which bucket holds a blob.

```sh
hfstore init              # create the key and both buckets
hfstore flush             # report what would upload
hfstore flush --apply     # upload, verify from a fresh download, record
hfstore ls /root/work     # both | local | remote | changed, offline
hfstore check /root/work  # exit 1 if anything is not protected
hfstore get /path/file    # restore; never overwrites
hfstore evict DIR         # report what could be freed
hfstore get DIR           # restore every remote-only file under DIR
hfstore pull-index        # rebuild the index from the bucket log
```

The key is the only way to read the backup. Keep a copy off this machine.

Only `evict --apply --key-is-off-machine` deletes local files, and only inside the
configured `evictable` trees, after re-hashing each one against its proven blob.
Evicted paths still show in `hfstore ls` as `remote`; ordinary `ls` no longer
sees them. Everything else never deletes or changes local files. A blob counts only after a
fresh download decrypts to the expected hash; sensitive files never spill into the
public bucket when the private tier is full, they stay on disk, reported as
unprotected; sensitive files upload only to a bucket confirmed private. Files open
for writing can be captured mid-update.

## Ordinary commands: the mount

The log is the write side. `hfstore serve` is the read side: it projects the
log into a directory tree and mounts each tree in `mounts` over itself, so plain
`ls`, `find`, `stat`, `du` and `df` work on evicted files with no network, and
opening one downloads and verifies it first. Reads go to a cache of
`readCacheBytes` (2 GiB) under the state directory, so a grep across a tree never
refills the disk; opening for writing puts the file back in place.
Reads ahead like a disk does, using the index: a second cold read in a directory
within a minute fetches the rest of it, 8 at a time; two scanned sibling directories
fetch the following ones too, in walk order. Files over 32 MiB and anything past
512 MiB in flight are left to be read on demand. The daemon logs how many guesses
were used (`prefetch: fetched N, used M`). A grep over 251 moved files took 12.6 s
instead of 86 s; 98% of fetched-ahead files were read. `df` reports `viewBytes`. With
`keyIsOffMachine` set, it evicts proven files least-recently-read first to keep
`keepFreeBytes` free. A stopped daemon gives `Transport endpoint is not connected`,
never empty data. Writes land on the local disk until a flush proves them, so one
burst larger than the free space still fails with ENOSPC.

`rawRoot` is a private bind mount of `/` that exposes the real disk under the mounts.
**Never `rm -rf` it or a parent of it: that deletes the whole system, and
`--one-file-system` does not help because it is the same filesystem.** Unmount it.
It must also stay outside every temporary and state directory. Tools that walk `/`
will see it, so exclude it.

Uploads shell out to `hf` because bucket uploads use the Xet protocol, which has no
Go client. Tests use a fake `hf` executable: `go test ./...`.


### What stays on disk

The daemon records every open through a mount (`usage.json` in the state directory):
a score per file that grows by one per hour of use and halves every week. When space
is needed, files go lowest score first. Every hour it also moves files nobody opened
or modified for `idleDays` (14) off the disk, so free space grows past `keepFreeBytes`
on its own; history starts when tracking does, so a new install waits `idleDays`
before the first idle move. A remote file used in three separate hours comes back to
the disk from its cache copy, with no download, while there is room. Files the mount
holds open are never removed. The kernel's atime is not used: the flush reads every
file.
## Dashboard

`serve` also shows a dashboard at `uiAddr` (default `127.0.0.1:7650`; empty turns it
off): disk free against the minimum, what is protected and what has moved off the
disk, cache hit rate, read-ahead accuracy, download speed and wait, reads, space
freed, backup uploads per day, each mounted folder split into on disk and remote,
and the most used files. It samples once a minute into `metrics.jsonl` in the state
directory and keeps seven days. Every chart has a table view. It reads only; bind it
to localhost or a VPN address, not a public one.

## Setting up a machine

Needs Linux, Go 1.24+, FUSE (`/dev/fuse`), root, and the `hf` CLI logged in
(`pip install huggingface_hub` then `hf auth login`).

```sh
go build -o /usr/local/bin/hfstore .
mkdir -p /etc/pinpin-store
cp config.example.json /etc/pinpin-store/config.json   # set your bucket names and hf path
hfstore init                                           # creates the key and both buckets
cp systemd/* /etc/systemd/system/ && systemctl daemon-reload
systemctl enable --now hfstore.timer                    # daily flush
```

Copy `/etc/pinpin-store/key` off the machine before anything else. To turn on the
mount, add `rawRoot`, `mounts` and `keyIsOffMachine` to the config once the first
flush has finished, then `systemctl enable --now hfstore-serve.service`.

To check a new machine end to end, run `OWNER=your-hf-user scripts/selftest.sh` as
root. It clones and builds hfstore, backs up a test folder to two new
`hfstore-selftest-*` buckets, evicts it, reads it back through the mount, and restores
it on a simulated second machine from the key alone.

## Compatibility with pinpin-store

hfstore is pinpin-store under a new name, with the same behaviour and formats: it
reads and writes existing backups unchanged. These names stay as they were, because
stored data or running systems depend on them:

| Kept | Why |
|---|---|
| `PPS1` object header | identifies every stored blob |
| HKDF labels `pinpin-store/encrypt/v1`, `pinpin-store/name/v1` | derive the encryption key and object names; changing them makes old blobs unreadable |
| default config `/etc/pinpin-store/config.json` | existing machines keep working with no flags |
| FUSE type `fuse.pinpin-store` | tooling that checks mounts by type |
| temp suffixes `.pinpin-store-enc`, `.pinpin-store-tmp` | in-progress downloads are recognised by name |
