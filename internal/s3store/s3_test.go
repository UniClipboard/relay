// SPDX-License-Identifier: AGPL-3.0-only

package s3store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPresignVirtualHostAndPathStyleAddressing(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)

	// Tencent COS virtual-host style.
	cos, err := New(Config{
		Endpoint:        "https://cos.ap-guangzhou.myqcloud.com",
		Region:          "ap-guangzhou",
		Bucket:          "unic-relay-1250000000",
		AccessKeyID:     "AKIDTEST",
		SecretAccessKey: "SECRETTEST",
	})
	if err != nil {
		t.Fatalf("New COS client: %v", err)
	}
	key := cos.ObjectKey("f5jtnxzhp7egc7qi5s7b6xc6745vzblw", "0123456789abcdef0123456789abcdef", 0)
	putURL, err := cos.PresignPut(key, 5*time.Minute, now)
	if err != nil {
		t.Fatalf("PresignPut: %v", err)
	}
	u, err := url.Parse(putURL.URL)
	if err != nil {
		t.Fatalf("parse presigned URL: %v", err)
	}
	if u.Host != "unic-relay-1250000000.cos.ap-guangzhou.myqcloud.com" {
		t.Fatalf("unexpected COS host: %s", u.Host)
	}
	if u.Path != "/mailboxes/f5jtnxzhp7egc7qi5s7b6xc6745vzblw/transfers/0123456789abcdef0123456789abcdef/chunks/0" {
		t.Fatalf("unexpected COS path: %s", u.Path)
	}
	q := u.Query()
	if q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" ||
		q.Get("X-Amz-Credential") != "AKIDTEST/20261126/ap-guangzhou/s3/aws4_request" ||
		q.Get("X-Amz-Date") != "20261126T080000Z" ||
		q.Get("X-Amz-Expires") != "300" ||
		q.Get("X-Amz-SignedHeaders") != "host" ||
		len(q.Get("X-Amz-Signature")) != 64 {
		t.Fatalf("unexpected SigV4 query params: %v", q)
	}

	// Cloudflare R2 path-style + custom public endpoint.
	r2, err := New(Config{
		Endpoint:        "https://account123.r2.cloudflarestorage.com",
		PublicEndpoint:  "https://chunks.example.com",
		Region:          "auto",
		Bucket:          "uniclipboard-hyper-chunks",
		AccessKeyID:     "R2AK",
		SecretAccessKey: "R2SK",
		ForcePathStyle:  true,
	})
	if err != nil {
		t.Fatalf("New R2 client: %v", err)
	}
	getURL, err := r2.PresignGet(key, 2*time.Minute, now)
	if err != nil {
		t.Fatalf("PresignGet: %v", err)
	}
	gu, _ := url.Parse(getURL.URL)
	if gu.Host != "chunks.example.com" || !strings.HasPrefix(gu.Path, "/uniclipboard-hyper-chunks/mailboxes/") {
		t.Fatalf("unexpected R2 path-style URL: %s", getURL.URL)
	}
}

func TestHeadPutGetDeleteRoundTripAgainstMockS3(t *testing.T) {
	var mu sync.Mutex
	objects := map[string][]byte{}

	mockS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			if r.URL.Query().Get("X-Amz-Signature") == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			objects[r.URL.Path] = body
			mu.Unlock()
			w.Header().Set("ETag", `"mock-etag"`)
			w.WriteHeader(http.StatusOK)
		case http.MethodHead:
			if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			mu.Lock()
			b, ok := objects[r.URL.Path]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", string(rune('0')))
			w.Header().Set("Content-Length", "11")
			w.Header().Set("ETag", `"mock-etag"`)
			w.WriteHeader(http.StatusOK)
			_ = b
		case http.MethodGet:
			if r.URL.Query().Get("X-Amz-Signature") == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			mu.Lock()
			b, ok := objects[r.URL.Path]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
		case http.MethodDelete:
			if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			mu.Lock()
			delete(objects, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer mockS3.Close()

	client, err := New(Config{
		Endpoint:        mockS3.URL,
		Region:          "us-east-1",
		Bucket:          "test-bucket",
		AccessKeyID:     "test-ak",
		SecretAccessKey: "test-sk",
		ForcePathStyle:  true,
		HTTPClient:      mockS3.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := client.ObjectKey("f5jtnxzhp7egc7qi5s7b6xc6745vzblw", "0123456789abcdef0123456789abcdef", 0)
	now := time.Now()

	// Missing before upload.
	if _, err := client.HeadObject(context.Background(), key); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}

	// Direct PUT via presigned URL.
	putSigned, err := client.PresignPut(key, time.Minute, now)
	if err != nil {
		t.Fatalf("PresignPut: %v", err)
	}
	payload := []byte("hello-s3-ct")
	putReq, _ := http.NewRequest(putSigned.Method, putSigned.URL, bytes.NewReader(payload))
	putResp, err := mockS3.Client().Do(putReq)
	if err != nil || putResp.StatusCode != http.StatusOK {
		t.Fatalf("direct PUT failed: err=%v status=%v", err, putResp)
	}
	_ = putResp.Body.Close()

	// Server-side HeadObject confirms existence & size.
	meta, err := client.HeadObject(context.Background(), key)
	if err != nil || meta.Size != int64(len(payload)) || meta.ETag != "mock-etag" {
		t.Fatalf("HeadObject mismatch: meta=%+v err=%v", meta, err)
	}

	// Direct GET via presigned URL.
	getSigned, err := client.PresignGet(key, time.Minute, now)
	if err != nil {
		t.Fatalf("PresignGet: %v", err)
	}
	getResp, err := mockS3.Client().Get(getSigned.URL)
	if err != nil || getResp.StatusCode != http.StatusOK {
		t.Fatalf("direct GET failed: err=%v", err)
	}
	got, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("direct GET content mismatch: got %q", got)
	}

	// Server-side DeleteObject purges object.
	if err := client.DeleteObject(context.Background(), key); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if _, err := client.HeadObject(context.Background(), key); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound after delete, got %v", err)
	}
}
