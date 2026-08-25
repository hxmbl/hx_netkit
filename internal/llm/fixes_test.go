package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hxmbl/hx_netkit/internal/belief"
	"github.com/hxmbl/hx_netkit/internal/store"
	"github.com/hxmbl/hx_netkit/internal/tools"
)

// Regression (audit C1): the seeded network-context brief must survive
// Session.Run and actually reach the model.
func TestSeedSurvivesRun(t *testing.T) {
	db, _ := store.OpenMemory()
	defer db.Close()
	env := &tools.Env{DB: db}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []Message `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		found := false
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "NETWORK-CONTEXT-CANARY") {
				found = true
			}
		}
		if !found {
			t.Error("SEED WIPED: model request contained no canary")
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		b, _ := json.Marshal(map[string]any{"message": map[string]any{"content": "ok"}})
		w.Write(b)
		w.Write([]byte("\n"))
		w.Write([]byte(`{"done":true}` + "\n"))
	}))
	defer srv.Close()

	s := &Session{
		Client:   New(srv.URL, "m", 2048),
		Env:      env,
		Beliefs:  belief.New(),
		Prompter: AlwaysAllow{},
		In:       strings.NewReader("hello\nquit\n"),
		Out:      &strings.Builder{},
	}
	s.Seed("Loaded context.\n\nNETWORK-CONTEXT-CANARY-12345", "ack")
	s.Run(context.Background())
}

// Regression (audit H4): Stop() must return promptly (bounded wait) even
// while a scan is in flight, instead of blocking until nmap finishes.
func TestBackgroundScannerStopIsBounded(t *testing.T) {
	b := belief.New()
	b.Ensure("10.0.0.1")

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	bs := &BackgroundScanner{
		Beliefs: b,
		Runner: runnerFunc(func(args []string) ([]byte, error) {
			once.Do(func() {
				close(entered)
				<-release // simulates nmap mid-scan (blocks only the first call)
			})
			return []byte("Host is up"), nil
		}),
		Events:  make(chan ScannerEvent, 16),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go func() { bs.scanOnce(); close(bs.stopped) }()

	<-entered // scan is now blocked inside Runner.Run

	done := make(chan struct{})
	go func() { bs.Stop(); close(done) }()

	select {
	case <-done:
		// good: returned within the 2s grace cap despite the blocked scan
	case <-time.After(4 * time.Second):
		t.Fatal("Stop exceeded its 2s cap while a scan was in flight")
	}

	close(release)
	select {
	case <-bs.stopped:
	default:
		t.Log("worker finishes after release; process exit reaps it otherwise")
	}
}

type runnerFunc func(args []string) ([]byte, error)

func (f runnerFunc) Run(args ...string) ([]byte, error) { return f(args) }

// Regression (audit M12): streamed tokens must reach the session output as
// they arrive, and must not be printed twice.
func TestStreamingPrintsOnce(t *testing.T) {
	db, _ := store.OpenMemory()
	defer db.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, part := range []string{"he", "llo", " there"} {
			b, _ := json.Marshal(map[string]any{"message": map[string]any{"content": part}})
			w.Write(b)
			w.Write([]byte("\n"))
		}
		w.Write([]byte(`{"done":true}` + "\n"))
	}))
	defer srv.Close()

	client := New(srv.URL, "m", 2048)
	out := &strings.Builder{}
	s := &Session{
		Client:   client,
		Env:      &tools.Env{DB: db},
		Prompter: AlwaysAllow{},
		In:       strings.NewReader("hi\nquit\n"),
		Out:      out,
	}
	s.Run(context.Background())

	got := out.String()
	if strings.Count(got, "hello there") != 1 {
		t.Errorf("streamed content printed wrong number of times (%d):\n%q",
			strings.Count(got, "hello there"), got)
	}
}

// Regression (audit L13): unknown slash commands get guidance instead of
// silently running a search.
func TestUnknownSlashCommandGetsGuidance(t *testing.T) {
	db, _ := store.OpenMemory()
	defer db.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	out := &strings.Builder{}
	s := &Session{
		Client:   New(srv.URL, "m", 2048),
		Env:      &tools.Env{DB: db},
		Prompter: AlwaysAllow{},
		In:       strings.NewReader("/frobnicate\nquit\n"),
		Out:      out,
	}
	s.Run(context.Background())
	if !strings.Contains(out.String(), "Unknown command") {
		t.Errorf("expected guidance for unknown slash command:\n%s", out.String())
	}
}
