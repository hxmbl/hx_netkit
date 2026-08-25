package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hxmbl/hx_netkit/internal/belief"
	"github.com/hxmbl/hx_netkit/internal/store"
	"github.com/hxmbl/hx_netkit/internal/tools"
)

// scriptedServer returns responses per turn: first with a tool call, then text.
func scriptedServer(t *testing.T, calls ...map[string]any) *httptest.Server {
	t.Helper()
	turn := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []json.RawMessage `json:"messages"`
			Tools    []map[string]any  `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/x-ndjson")

		var chunk map[string]any
		if turn < len(calls) {
			chunk = calls[turn]
		} else {
			chunk = map[string]any{"message": map[string]any{"content": "final answer"}, "done": true}
		}
		turn++
		b, _ := json.Marshal(chunk)
		w.Write(b)
		w.Write([]byte("\n"))
		w.Write([]byte(`{"done":true}` + "\n"))
	}))
}

func newTestEnv(t *testing.T) (*tools.Env, *store.DB) {
	t.Helper()
	db, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for i := 0; i < 3; i++ {
		_ = db.InsertPacket(1000+float64(i), "10.0.0.1", "10.0.0.2", 40000, 443, 0, 0, "", "", 100)
	}
	return &tools.Env{DB: db}, db
}

func TestSessionExecutesToolAndFollowsUp(t *testing.T) {
	env, _ := newTestEnv(t)

	srv := scriptedServer(t,
		map[string]any{"message": map[string]any{
			"content": "",
			"tool_calls": []map[string]any{{
				"function": map[string]any{
					"name":      "sql",
					"arguments": map[string]any{"query": "SELECT COUNT(*) AS n FROM packets"},
				},
			}},
		},
		})
	defer srv.Close()

	out := &strings.Builder{}
	session := &Session{
		Client:    New(srv.URL, "test-model", 2048),
		Env:       env,
		Beliefs:   belief.New(),
		Prompter:  AlwaysAllow{},
		SystemPmt: "test",
		In:        strings.NewReader("how many packets?\nquit\n"),
		Out:       out,
	}
	session.Seed("context", "ok")
	n := session.Run(context.Background())

	log := out.String()
	if !strings.Contains(log, "[Tool: sql]") {
		t.Errorf("tool execution not reported:\n%s", log)
	}
	if !strings.Contains(log, "final answer") {
		t.Errorf("follow-up answer missing:\n%s", log)
	}
	if n < 4 {
		t.Errorf("message count = %d, expected seeded+user+assistant+tools >= 4", n)
	}
}

func TestSessionDeniedToolFeedsDenialBack(t *testing.T) {
	env, _ := newTestEnv(t)
	srv := scriptedServer(t,
		map[string]any{"message": map[string]any{
			"tool_calls": []map[string]any{{
				"function": map[string]any{"name": "nmap", "arguments": map[string]any{"target": "10.0.0.9"}},
			}},
		},
		})
	defer srv.Close()

	out := &strings.Builder{}
	session := &Session{
		Client:   New(srv.URL, "m", 2048),
		Env:      env,
		Prompter: DenyAll{},
		In:       strings.NewReader("scan it\nquit\n"),
		Out:      out,
	}
	session.Run(context.Background())
	if !strings.Contains(out.String(), "[Tool denied]") {
		t.Errorf("denial not surfaced:\n%s", out.String())
	}
}

func TestSessionWebToggleGatesWebTools(t *testing.T) {
	env, _ := newTestEnv(t)

	var sawTools bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Tools []map[string]any `json:"tools"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		for _, tl := range req.Tools {
			if fn, ok := tl["function"].(map[string]any); ok {
				if n := fn["name"].(string); n == "websearch" || n == "webfetch" {
					sawTools = true
					t.Errorf("web tool %q advertised while disabled", n)
				}
			}
		}
		resp := map[string]any{"message": map[string]any{"content": "ok"}}
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Write(b)
		w.Write([]byte("\n"))
	}))
	defer srv.Close()

	env.Web = nil // no web client at all
	out := &strings.Builder{}
	session := &Session{
		Client: New(srv.URL, "m", 2048), Env: env, Prompter: AlwaysAllow{},
		In: strings.NewReader("/web on\nhello\nquit\n"), Out: out,
	}
	session.Run(context.Background())
	if !strings.Contains(out.String(), "--allow-web") {
		t.Errorf("toggling web without client should explain opt-in:\n%s", out.String())
	}
	if sawTools {
		t.Error("web tools leaked into request")
	}
}

func TestSlashCommandsRouteToSearch(t *testing.T) {
	env, _ := newTestEnv(t)
	beliefs := belief.New()
	beliefs.Ensure("10.0.0.1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	out := &strings.Builder{}
	session := &Session{
		Client: New(srv.URL, "m", 2048), Env: env, Beliefs: beliefs, Prompter: AlwaysAllow{},
		In: strings.NewReader("/stats\n/beliefs\nquit\n"), Out: out,
	}
	session.Run(context.Background())
	log := out.String()
	if !strings.Contains(log, "3 packets") {
		t.Errorf("/stats failed:\n%s", log)
	}
	if !strings.Contains(log, "═══ Beliefs ═══") || !strings.Contains(log, "10.0.0.1") {
		t.Errorf("/beliefs failed:\n%s", log)
	}
}
