package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The bucket host redirects to a CDN, as Hugging Face does; the CDN may or may not
// honour ranges. Every size around the chunk boundaries must arrive intact.
func TestFetchWebRanges(t *testing.T) {
	for _, ranges := range []bool{true, false} {
		for _, size := range []int{0, 1, rangeChunk - 1, rangeChunk, rangeChunk + 1, 5*rangeChunk + 12345} {
			blob := make([]byte, size)
			rand.Read(blob)
			cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !ranges {
					r.Header.Del("Range")
				}
				http.ServeContent(w, r, "blob", time.Time{}, bytes.NewReader(blob))
			}))
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.Path, "/buckets/me/blobs/resolve/batches/") {
					http.NotFound(w, r)
					return
				}
				http.Redirect(w, r, cdn.URL+"/signed", http.StatusFound)
			}))
			out := filepath.Join(t.TempDir(), "blob")
			err := HF{bucket: "me/blobs", web: hub.URL}.fetchWeb(context.Background(), "batches/b/x", out)
			got, _ := os.ReadFile(out)
			if err != nil || !bytes.Equal(got, blob) {
				t.Fatalf("ranges=%v size=%d: err %v, got %d bytes", ranges, size, err, len(got))
			}
			hub.Close()
			cdn.Close()
		}
	}
}
