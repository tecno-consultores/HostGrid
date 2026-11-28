package relay_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tecno-consultores/HostGrid/relay/internal/relay"
)

func TestRelayRejectsNonHTTPSRemoteUpstream(t *testing.T) {
	if _, err := relay.NewHandler(relay.Options{UpstreamURL: "http://controlplane.internal:8443"}); err == nil {
		t.Fatal("expected non-loopback HTTP upstream to be rejected")
	}
}

func TestRelayAllowListBlocksAdminSurfaceAndForwardsAgentTraffic(t *testing.T) {
	var snapshotHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/snapshots":
			if r.Header.Get("Authorization") != "Bearer hg_agent_abc" {
				http.Error(w, "missing auth", http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Idempotency-Key") != "550e8400-e29b-41d4-a716-446655440000" {
				http.Error(w, "missing idempotency key", http.StatusBadRequest)
				return
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"host":"demo"}` {
				http.Error(w, "payload mutated", http.StatusBadRequest)
				return
			}
			snapshotHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"snapshot_id":"s1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/agents/550e8400-e29b-41d4-a716-446655440001/patch-jobs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		default:
			http.Error(w, "unexpected upstream call: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	handler, err := relay.NewHandler(relay.Options{
		UpstreamURL: upstream.URL,
		CacheDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	relaySrv := httptest.NewServer(handler)
	defer relaySrv.Close()

	// Healthcheck responds locally
	healthResp, err := http.Get(relaySrv.URL + "/healthz")
	if err != nil || healthResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 /healthz, got %v err=%v", healthResp, err)
	}
	_ = healthResp.Body.Close()

	// Admin/user routes MUST be blocked with 403 on DMZ relay
	for _, blocked := range []string{"/api/v1/auth/login", "/api/v1/users", "/api/v1/cves/search", "/api/v1/patching/plans", "/api/v1/audit/logs"} {
		resp, reqErr := http.Get(relaySrv.URL + blocked)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for %s, got %d", blocked, resp.StatusCode)
		}
	}

	// Agent snapshot POST forwarded verbatim with headers preserved
	req, _ := http.NewRequest(http.MethodPost, relaySrv.URL+"/api/v1/snapshots", bytes.NewBufferString(`{"host":"demo"}`))
	req.Header.Set("Authorization", "Bearer hg_agent_abc")
	req.Header.Set("Idempotency-Key", "550e8400-e29b-41d4-a716-446655440000")
	req.Header.Set("Content-Type", "application/json")
	snapResp, err := http.DefaultClient.Do(req)
	if err != nil || snapResp.StatusCode != http.StatusCreated || snapResp.Header.Get("X-HostGrid-Relay") != "1" {
		t.Fatalf("expected 201 forwarded snapshot, got resp=%+v err=%v", snapResp, err)
	}
	_ = snapResp.Body.Close()
	if snapshotHits.Load() != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", snapshotHits.Load())
	}

	// Agent pull patch-jobs route is allowed
	jobReq, _ := http.NewRequest(http.MethodGet, relaySrv.URL+"/api/v1/agents/550e8400-e29b-41d4-a716-446655440001/patch-jobs", nil)
	jobResp, err := http.DefaultClient.Do(jobReq)
	if err != nil || jobResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 patch-jobs, got %v err=%v", jobResp, err)
	}
	_ = jobResp.Body.Close()
}

func TestRelayBundleCacheMissThenHitAndIntegrityRejection(t *testing.T) {
	tarBytes := []byte("signed-portable-lynis-tarball-bytes")
	sum := sha256.Sum256(tarBytes)
	tarSHA := hex.EncodeToString(sum[:])

	var upstreamDownloadHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer hg_agent_123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/bundles/lynis/3.1.4/download":
			upstreamDownloadHits.Add(1)
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("X-HostGrid-SHA256", tarSHA)
			_, _ = w.Write(tarBytes)
		case "/api/v1/bundles/lynis/9.9.9/download":
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("X-HostGrid-SHA256", "0000000000000000000000000000000000000000000000000000000000000000")
			_, _ = w.Write([]byte("corrupted-stream"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	cacheDir := t.TempDir()
	handler, err := relay.NewHandler(relay.Options{UpstreamURL: upstream.URL, CacheDir: cacheDir})
	if err != nil {
		t.Fatal(err)
	}
	relaySrv := httptest.NewServer(handler)
	defer relaySrv.Close()

	// Unauthenticated bundle request rejected with 401
	unauth, _ := http.Get(relaySrv.URL + "/api/v1/bundles/lynis/3.1.4/download")
	_ = unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without Bearer token, got %d", unauth.StatusCode)
	}

	// First authenticated fetch -> MISS and cached to disk
	doDownload := func(ver string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, relaySrv.URL+"/api/v1/bundles/lynis/"+ver+"/download", nil)
		req.Header.Set("Authorization", "Bearer hg_agent_123")
		resp, reqErr := http.DefaultClient.Do(req)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}

	r1, b1 := doDownload("3.1.4")
	if r1.StatusCode != http.StatusOK || r1.Header.Get("X-HostGrid-Relay-Cache") != "MISS" || !bytes.Equal(b1, tarBytes) {
		t.Fatalf("expected MISS with exact bytes, got status=%d cache=%q", r1.StatusCode, r1.Header.Get("X-HostGrid-Relay-Cache"))
	}

	// Second authenticated fetch -> HIT served locally without calling upstream again!
	r2, b2 := doDownload("3.1.4")
	if r2.StatusCode != http.StatusOK || r2.Header.Get("X-HostGrid-Relay-Cache") != "HIT" || !bytes.Equal(b2, tarBytes) {
		t.Fatalf("expected HIT with exact bytes, got status=%d cache=%q", r2.StatusCode, r2.Header.Get("X-HostGrid-Relay-Cache"))
	}
	if upstreamDownloadHits.Load() != 1 {
		t.Fatalf("expected upstream hit count 1 (served from cache on 2nd request), got %d", upstreamDownloadHits.Load())
	}

	// Tampered local cache file fails SHA-256 verification and falls back cleanly to upstream
	if err := os.WriteFile(filepath.Join(cacheDir, "lynis__3.1.4.download"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	r3, b3 := doDownload("3.1.4")
	if r3.StatusCode != http.StatusOK || r3.Header.Get("X-HostGrid-Relay-Cache") != "MISS" || !bytes.Equal(b3, tarBytes) {
		t.Fatalf("expected tampered cache fallback MISS, got status=%d cache=%q", r3.StatusCode, r3.Header.Get("X-HostGrid-Relay-Cache"))
	}

	// Corrupted upstream SHA-256 rejected with 502 Bad Gateway
	rBad, _ := doDownload("9.9.9")
	if rBad.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 on upstream SHA-256 mismatch, got %d", rBad.StatusCode)
	}

	// Empty Bearer token MUST be rejected with 401
	emptyAuthReq, _ := http.NewRequest(http.MethodGet, relaySrv.URL+"/api/v1/bundles/lynis/3.1.4/download", nil)
	emptyAuthReq.Header.Set("Authorization", "Bearer   ")
	emptyAuthResp, err := http.DefaultClient.Do(emptyAuthReq)
	if err != nil || emptyAuthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for empty Bearer token, got resp=%+v err=%v", emptyAuthResp, err)
	}
	_ = emptyAuthResp.Body.Close()

	// Forged/unverified Bearer token MUST NOT receive a cache HIT (forwarded to upstream -> 401)
	forgedReq, _ := http.NewRequest(http.MethodGet, relaySrv.URL+"/api/v1/bundles/lynis/3.1.4/download", nil)
	forgedReq.Header.Set("Authorization", "Bearer forged_attacker_token")
	forgedResp, err := http.DefaultClient.Do(forgedReq)
	if err != nil || forgedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for forged Bearer token on cached bundle, got resp=%+v err=%v", forgedResp, err)
	}
	_ = forgedResp.Body.Close()

	// Concurrent authenticated reads against cached bundle stay race-free and consistent
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, body := doDownload("3.1.4")
			if resp.StatusCode != http.StatusOK || !bytes.Equal(body, tarBytes) {
				t.Errorf("concurrent cache download failed: status=%d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
}

func TestRelayBundleCacheSeparatesByArchQuery(t *testing.T) {
	amd64Bytes := []byte("tool-amd64-tarball")
	arm64Bytes := []byte("tool-arm64-tarball")
	amdSum := sha256.Sum256(amd64Bytes)
	armSum := sha256.Sum256(arm64Bytes)
	amdSHA := hex.EncodeToString(amdSum[:])
	armSHA := hex.EncodeToString(armSum[:])

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer hg_agent_arch" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		upstreamHits.Add(1)
		switch r.URL.Query().Get("arch") {
		case "amd64":
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("X-HostGrid-SHA256", amdSHA)
			_, _ = w.Write(amd64Bytes)
		case "arm64":
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("X-HostGrid-SHA256", armSHA)
			_, _ = w.Write(arm64Bytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	handler, err := relay.NewHandler(relay.Options{UpstreamURL: upstream.URL, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	relaySrv := httptest.NewServer(handler)
	defer relaySrv.Close()

	fetchArch := func(arch string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, relaySrv.URL+"/api/v1/bundles/lynis/3.1.4/download?arch="+arch, nil)
		req.Header.Set("Authorization", "Bearer hg_agent_arch")
		resp, reqErr := http.DefaultClient.Do(req)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}

	rAmd1, bAmd1 := fetchArch("amd64")
	if rAmd1.StatusCode != http.StatusOK || rAmd1.Header.Get("X-HostGrid-Relay-Cache") != "MISS" || !bytes.Equal(bAmd1, amd64Bytes) {
		t.Fatalf("unexpected amd64 MISS: status=%d cache=%q", rAmd1.StatusCode, rAmd1.Header.Get("X-HostGrid-Relay-Cache"))
	}
	rArm1, bArm1 := fetchArch("arm64")
	if rArm1.StatusCode != http.StatusOK || rArm1.Header.Get("X-HostGrid-Relay-Cache") != "MISS" || !bytes.Equal(bArm1, arm64Bytes) {
		t.Fatalf("unexpected arm64 MISS: status=%d cache=%q", rArm1.StatusCode, rArm1.Header.Get("X-HostGrid-Relay-Cache"))
	}
	rArm2, bArm2 := fetchArch("arm64")
	if rArm2.StatusCode != http.StatusOK || rArm2.Header.Get("X-HostGrid-Relay-Cache") != "HIT" || !bytes.Equal(bArm2, arm64Bytes) {
		t.Fatalf("unexpected arm64 HIT: status=%d cache=%q", rArm2.StatusCode, rArm2.Header.Get("X-HostGrid-Relay-Cache"))
	}
	if upstreamHits.Load() != 2 {
		t.Fatalf("expected 2 upstream hits (1 amd64 + 1 arm64), got %d", upstreamHits.Load())
	}

	for _, badQuery := range []string{"?arch=bad$arch", "?arch=a..b", "?arch=mips", "?arch=amd64&arch=arm64"} {
		badReq, _ := http.NewRequest(http.MethodGet, relaySrv.URL+"/api/v1/bundles/lynis/3.1.4/download"+badQuery, nil)
		badReq.Header.Set("Authorization", "Bearer hg_agent_arch")
		badResp, err := http.DefaultClient.Do(badReq)
		if err != nil || badResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid arch query %q, got resp=%+v err=%v", badQuery, badResp, err)
		}
		_ = badResp.Body.Close()
	}
}
