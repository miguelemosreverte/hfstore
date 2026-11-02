package main

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

// metrics counts what the mount does and samples it once a minute into a file under
// the state directory, kept for metricsKeep. The dashboard reads it; nothing else does.
const metricsKeep = 7 * 24 * time.Hour

type counters struct {
	Opens         int64 `json:"opens"`      // opens of files on disk
	CacheHits     int64 `json:"cacheHits"`  // remote files served from the read cache
	ColdReads     int64 `json:"coldReads"`  // remote files downloaded for a reader
	ColdBytes     int64 `json:"coldBytes"`  // bytes of those downloads
	PrefetchFiles int64 `json:"preFiles"`   // files fetched ahead
	PrefetchBytes int64 `json:"preBytes"`   // bytes fetched ahead
	PrefetchUsed  int64 `json:"preUsed"`    // fetched-ahead files later read
	Hydrations    int64 `json:"hydrations"` // remote files put back for writing
	Promotions    int64 `json:"promotions"` // remote files put back because they are hot
	EvictedBytes  int64 `json:"evicted"`    // freed to keep the minimum free
	IdleBytes     int64 `json:"idle"`       // freed because nobody used them
}

type sample struct {
	T int64 `json:"t"` // unix seconds, start of the minute
	counters
	FreeBytes  int64 `json:"free"`
	CacheBytes int64 `json:"cache"`
	ColdP50    int64 `json:"p50"` // ms to fetch a cold file, this minute
	ColdP95    int64 `json:"p95"`
}

type metrics struct {
	mu      sync.Mutex
	file    string
	cur     counters
	waits   []int64
	samples []sample
}

func loadMetrics(file string, now time.Time) *metrics {
	m := &metrics{file: file}
	if in, err := os.Open(file); err == nil {
		scanner := bufio.NewScanner(in)
		for scanner.Scan() {
			var s sample
			if json.Unmarshal(scanner.Bytes(), &s) == nil && now.Unix()-s.T < int64(metricsKeep.Seconds()) {
				m.samples = append(m.samples, s)
			}
		}
		in.Close()
	}
	return m
}

func (m *metrics) add(change func(*counters)) {
	m.mu.Lock()
	change(&m.cur)
	m.mu.Unlock()
}

func (m *metrics) cold(bytes int64, wait time.Duration, prefetch bool) {
	m.mu.Lock()
	if prefetch {
		m.cur.PrefetchFiles++
		m.cur.PrefetchBytes += bytes
	} else {
		m.cur.ColdReads++
		m.cur.ColdBytes += bytes
		m.waits = append(m.waits, wait.Milliseconds())
	}
	m.mu.Unlock()
}

// tick closes the current minute. The file is rewritten when it holds a day more than
// it keeps, so it never grows past eight days of samples.
func (m *metrics) tick(now time.Time, free, cache int64) error {
	m.mu.Lock()
	s := sample{T: now.Truncate(time.Minute).Unix(), counters: m.cur, FreeBytes: free, CacheBytes: cache}
	if len(m.waits) > 0 {
		sort.Slice(m.waits, func(a, b int) bool { return m.waits[a] < m.waits[b] })
		s.ColdP50 = m.waits[len(m.waits)/2]
		s.ColdP95 = m.waits[len(m.waits)*95/100]
	}
	m.cur, m.waits = counters{}, nil
	m.samples = append(m.samples, s)
	cut := 0
	for cut < len(m.samples) && now.Unix()-m.samples[cut].T >= int64(metricsKeep.Seconds()) {
		cut++
	}
	m.samples = m.samples[cut:]
	m.mu.Unlock()

	line, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if info, err := os.Stat(m.file); err == nil && info.Size() > int64(len(line))*int64((metricsKeep+24*time.Hour)/time.Minute) {
		return m.rewrite()
	}
	out, err := os.OpenFile(m.file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := out.Write(append(line, '\n')); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func (m *metrics) rewrite() error {
	m.mu.Lock()
	samples := append([]sample(nil), m.samples...)
	m.mu.Unlock()
	temp := m.file + ".tmp"
	out, err := os.OpenFile(temp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(out)
	encoder := json.NewEncoder(writer)
	for _, s := range samples {
		if err := encoder.Encode(s); err != nil {
			out.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(temp, m.file)
}

// series returns samples since a time, summed into buckets of step seconds. Counters
// add up; levels (free, cache) and wait percentiles take the bucket's last and worst.
func (m *metrics) series(since, step int64) []sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []sample
	for _, s := range m.samples {
		if s.T < since {
			continue
		}
		t := s.T - s.T%step
		if len(out) == 0 || out[len(out)-1].T != t {
			out = append(out, sample{T: t})
		}
		b := &out[len(out)-1]
		c := &b.counters
		c.Opens += s.Opens
		c.CacheHits += s.CacheHits
		c.ColdReads += s.ColdReads
		c.ColdBytes += s.ColdBytes
		c.PrefetchFiles += s.PrefetchFiles
		c.PrefetchBytes += s.PrefetchBytes
		c.PrefetchUsed += s.PrefetchUsed
		c.Hydrations += s.Hydrations
		c.Promotions += s.Promotions
		c.EvictedBytes += s.EvictedBytes
		c.IdleBytes += s.IdleBytes
		b.FreeBytes, b.CacheBytes = s.FreeBytes, s.CacheBytes
		b.ColdP50 = max(b.ColdP50, s.ColdP50)
		b.ColdP95 = max(b.ColdP95, s.ColdP95)
	}
	return out
}

// totals sums every counter over the kept window.
func (m *metrics) totals() counters {
	all := m.series(0, int64(metricsKeep.Seconds())*2)
	var c counters
	for _, s := range all {
		c.Opens += s.Opens
		c.CacheHits += s.CacheHits
		c.ColdReads += s.ColdReads
		c.ColdBytes += s.ColdBytes
		c.PrefetchFiles += s.PrefetchFiles
		c.PrefetchBytes += s.PrefetchBytes
		c.PrefetchUsed += s.PrefetchUsed
		c.Hydrations += s.Hydrations
		c.Promotions += s.Promotions
		c.EvictedBytes += s.EvictedBytes
		c.IdleBytes += s.IdleBytes
	}
	return c
}
