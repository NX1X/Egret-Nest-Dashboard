package server

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

// countingBody records how many bytes a handler read from the request body.
type countingBody struct {
	r    io.Reader
	read int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func (c *countingBody) Close() error { return nil }

func newTestHandler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if cfg.SetupToken == "" {
		cfg.SetupToken = testSetupToken
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	return srv.Handler()
}

// emptyObjectBomb returns an envelope whose connections array holds n empty
// objects: 3 bytes each on the wire, a full struct each once decoded.
func emptyObjectBomb(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"schema_version":1,"run":{"repository":"a/b"},"session":{"connections":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("{}")
	}
	b.WriteString(`]}}`)
	return b.Bytes()
}

// Regression: the handler decoded the whole body before it checked the token,
// so one anonymous 8 MiB request could OOM-kill the dashboard (measured at about
// 770 MiB of heap against a 256 MiB limit). An unauthenticated caller must now
// be rejected without the body being read at all.
func TestIngestRejectsUnauthenticatedCallersBeforeReadingTheBody(t *testing.T) {
	h := newTestHandler(t, Config{}) // no open ingest, no shared token
	for name, header := range map[string]string{
		"no token":    "",
		"wrong token": "Bearer not-a-real-token",
	} {
		t.Run(name, func(t *testing.T) {
			body := &countingBody{r: bytes.NewReader(emptyObjectBomb(1000))}
			req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
			req.Body = body
			req.Header.Set("Content-Type", "application/json")
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			if body.read != 0 {
				t.Errorf("handler read %d body bytes before rejecting the caller", body.read)
			}
		})
	}
}

// An authorized caller must not be able to make the decode explode either.
func TestIngestRejectsAnElementBomb(t *testing.T) {
	h := newTestHandler(t, Config{OpenIngest: true})
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(emptyObjectBomb(maxIngestElements+1)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

// A body over the byte cap is a 413, not a misleading "invalid JSON" 400.
func TestIngestRejectsAnOversizedBodyWith413(t *testing.T) {
	h := newTestHandler(t, Config{OpenIngest: true})
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(bytes.Repeat([]byte(" "), maxIngestBytes+1)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestCheckIngestShape(t *testing.T) {
	deep := func(n int) []byte { return []byte(strings.Repeat("[", n) + strings.Repeat("]", n)) }
	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		{"real envelope", sampleBody(), nil},
		{"at the element cap", emptyObjectBomb(maxIngestElements), nil},
		{"over the element cap", emptyObjectBomb(maxIngestElements + 1), errIngestTooLarge},
		{"at the depth cap", deep(maxIngestDepth), nil},
		{"over the depth cap", deep(maxIngestDepth + 1), errIngestTooLarge},
		{"truncated", []byte(`{"schema_version":1,"session":{"connections":[{}`), errIngestMalformed},
		{"empty", nil, errIngestMalformed},
		{"trailing data is ignored, like json.Decoder.Decode", append(sampleBody(), []byte(" trailing")...), nil},
	} {
		if got := checkIngestShape(tc.in); !errors.Is(got, tc.want) {
			t.Errorf("%s: checkIngestShape = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The shape check itself must stay cheap on the exact payload that caused the
// OOM: about 2.8 million empty objects.
func TestCheckIngestShapeIsCheapOnTheOOMPayload(t *testing.T) {
	bomb := emptyObjectBomb(2_800_000)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := checkIngestShape(bomb)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, errIngestTooLarge) {
		t.Fatalf("checkIngestShape = %v, want errIngestTooLarge", err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
		t.Errorf("shape check allocated %d MiB, want under 64 MiB", alloc>>20)
	}
}

// When every argon2id slot is busy, a known and an unknown login must get the
// same answer (503 and the busy message), so the busy path cannot reveal which
// accounts exist. Neither may count as a failed attempt.
func TestLoginWhileHashingIsBusyDoesNotRevealAccounts(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	const pw = "a-long-enough-password"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := st.CreateUser(&model.User{Login: "alice", PasswordHash: hash}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	post := func(login, password string) (int, string) {
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar}
		if _, err := c.Get(ts.URL + "/login"); err != nil {
			t.Fatalf("get login: %v", err)
		}
		form := url.Values{"_csrf": {csrfFrom(t, jar, ts.URL)}, "login": {login}, "password": {password}}
		resp, err := c.PostForm(ts.URL+"/login", form)
		if err != nil {
			t.Fatalf("post login: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	release := auth.HoldHashSlotsForTest(20 * time.Millisecond)
	for _, login := range []string{"alice", "nobody"} {
		code, body := post(login, pw)
		if code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want 503", login, code)
		}
		if !strings.Contains(body, "busy") || strings.Contains(body, "invalid credentials") {
			t.Errorf("%s: body does not show the uniform busy message", login)
		}
	}
	release()

	// The busy attempts left no limiter strike: alice still logs in normally.
	if code, _ := post("alice", pw); code != http.StatusOK {
		t.Errorf("login after busy attempts = %d, want 200", code)
	}
}
