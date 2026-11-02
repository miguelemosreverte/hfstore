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

func (h HF) fetchWeb(ctx context.Context, remote, local string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, h.web+"/buckets/"+h.bucket+"/resolve/"+remote, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: %s", remote, response.Status)
	}
	file, err := os.Create(local)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.Copy(file, response.Body); err != nil {
		return err
	}
	return file.Close()
}
