package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// HF shells out to the hf CLI: bucket uploads use the Xet protocol, which has no
// Go client, and the CLI already owns private credential handling.
type HF struct {
	bin    string
	bucket string
	web    string // set for public buckets: reads skip the slow Python CLI
}

type bucketInfo struct {
	ID         string `json:"id"`
	Private    bool   `json:"private"`
	Size       int64  `json:"size"`
	TotalFiles int64  `json:"total_files"`
}

func (h HF) url(path string) string {
	return strings.TrimRight("hf://buckets/"+h.bucket+"/"+path, "/")
}

func (h HF) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, h.bin, append([]string{"buckets"}, args...)...)
	cmd.Env = append(os.Environ(), "HF_HUB_DISABLE_PROGRESS_BARS=1", "NO_COLOR=1")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		tail := strings.TrimSpace(errOut.String())
		if len(tail) > 400 {
			tail = tail[len(tail)-400:]
		}
		return nil, fmt.Errorf("hf buckets %s: %w: %s", args[0], err, tail)
	}
	return out.Bytes(), nil
}

func (h HF) info(ctx context.Context) (bucketInfo, error) {
	raw, err := h.run(ctx, "info", h.bucket, "--format", "json")
	if err != nil {
		return bucketInfo{}, err
	}
	// The CLI may print hints around the JSON document.
	start, end := bytes.IndexByte(raw, '{'), bytes.LastIndexByte(raw, '}')
	if start < 0 || end < start {
		return bucketInfo{}, fmt.Errorf("unreadable bucket info for %s", h.bucket)
	}
	var info bucketInfo
	if err := json.Unmarshal(raw[start:end+1], &info); err != nil {
		return bucketInfo{}, err
	}
	return info, nil
}

// requirePrivate is the guard for every upload. It checks the live bucket, not a
// configured claim, and treats an unreadable answer as public.
func (h HF) requirePrivate(ctx context.Context) error {
	info, err := h.info(ctx)
	if err != nil {
		return fmt.Errorf("cannot confirm %s is private: %w", h.bucket, err)
	}
	if !info.Private {
		return fmt.Errorf("refusing to upload: bucket %s is public", h.bucket)
	}
	return nil
}

func (h HF) create(ctx context.Context, private bool) error {
	args := []string{"create", h.bucket, "--exist-ok"}
	if private {
		args = append(args, "--private")
	}
	_, err := h.run(ctx, args...)
	return err
}

func (h HF) syncUp(ctx context.Context, dir, prefix string) error {
	_, err := h.run(ctx, "sync", dir, h.url(prefix))
	return err
}

func (h HF) syncDown(ctx context.Context, prefix, dir string) error {
	_, err := h.run(ctx, "sync", h.url(prefix), dir)
	return err
}

func (h HF) put(ctx context.Context, local, remote string) error {
	_, err := h.run(ctx, "cp", local, h.url(remote))
	return err
}

func (h HF) fetch(ctx context.Context, remote, local string) error {
	if h.web != "" && h.fetchWeb(ctx, remote, local) == nil {
		return nil
	}
	_, err := h.run(ctx, "cp", h.url(remote), local)
	return err
}

// Downloads ask for the first rangeChunk bytes. A larger file comes back as 206 with
// its total size, and the rest is fetched in parallel ranges from the CDN URL the
// first request was redirected to: one stream from the CDN is several times slower.
const (
	rangeChunk   = 16 << 20
	rangeWorkers = 8
)

// webClient keeps connections open for the prefetch workers and range fetches;
// the default keeps two per host, so the rest would redo TLS every time.
var webClient = func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 64
	return &http.Client{Transport: transport}
}()

func (h HF) fetchWeb(ctx context.Context, remote, local string) error {
	file, err := os.Create(local)
	if err != nil {
		return err
	}
	defer file.Close()
	response, err := getRange(ctx, h.web+"/buckets/"+h.bucket+"/resolve/"+remote, 0, rangeChunk-1)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK: // no range support: the whole file in one stream
		if _, err := io.Copy(file, response.Body); err != nil {
			return err
		}
		return file.Close()
	case http.StatusPartialContent:
	default:
		return fmt.Errorf("fetch %s: %s", remote, response.Status)
	}
	var first, last, total int64
	if _, err := fmt.Sscanf(response.Header.Get("Content-Range"), "bytes %d-%d/%d", &first, &last, &total); err != nil || first != 0 {
		return fmt.Errorf("fetch %s: bad Content-Range %q", remote, response.Header.Get("Content-Range"))
	}
	if err := copyExactly(io.NewOffsetWriter(file, 0), response.Body, last+1); err != nil {
		return err
	}
	if err := fetchRanges(ctx, response.Request.URL.String(), file, last+1, total); err != nil {
		return fmt.Errorf("fetch %s: %w", remote, err)
	}
	return file.Close()
}

// fetchRanges fills [from, total) of file with parallel range requests.
func fetchRanges(ctx context.Context, url string, file *os.File, from, total int64) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wait sync.WaitGroup
	var once sync.Once
	var failure error
	slots := make(chan struct{}, rangeWorkers)
	for start := from; start < total; start += rangeChunk {
		end := min(start+rangeChunk, total) - 1
		slots <- struct{}{}
		if ctx.Err() != nil {
			break
		}
		wait.Add(1)
		go func() {
			defer func() { <-slots; wait.Done() }()
			err := func() error {
				response, err := getRange(ctx, url, start, end)
				if err != nil {
					return err
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusPartialContent {
					return fmt.Errorf("range %d-%d: %s", start, end, response.Status)
				}
				return copyExactly(io.NewOffsetWriter(file, start), response.Body, end-start+1)
			}()
			if err != nil {
				once.Do(func() { failure = err; cancel() })
			}
		}()
	}
	wait.Wait()
	return failure
}

func getRange(ctx context.Context, url string, start, end int64) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	return webClient.Do(request)
}

func copyExactly(out io.Writer, in io.Reader, size int64) error {
	n, err := io.Copy(out, io.LimitReader(in, size))
	if err == nil && n != size {
		err = fmt.Errorf("short read: %d of %d bytes", n, size)
	}
	return err
}
