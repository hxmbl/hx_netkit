package llm

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hxmbl/hx_netkit/internal/belief"
	"github.com/hxmbl/hx_netkit/internal/config"
	"github.com/hxmbl/hx_netkit/internal/store"
	"github.com/hxmbl/hx_netkit/internal/tools"
	"github.com/hxmbl/hx_netkit/internal/websearch"
)

func newWebSession(t *testing.T, web *websearch.Client) *Session {
	t.Helper()
	db, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Session{
		Client:    &Client{},
		Env:       &tools.Env{DB: db, Cfg: config.Config{}, Beliefs: belief.New(), Web: web, WebOn: web != nil},
		Beliefs:   belief.New(),
		Prompter:  AlwaysAllow{},
		Out:       &bytes.Buffer{},
		SystemPmt: "test",
	}
}

// "/web off" must actually revoke the internet tools. It used to only print a
// confirmation: the tools stayed in the advertised schema and kept running
// outbound requests, because webEnabled() looked at Env.Web alone.
func TestWebOffRevokesWebTools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"title":"LEAKED","url":"https://x.test","content":"fetched"}]}`))
	}))
	defer srv.Close()

	web := websearch.New(websearch.Config{Enabled: true, Provider: "searxng", SearXNGURL: srv.URL})
	if web == nil {
		t.Fatal("web client should exist when enabled")
	}
	s := newWebSession(t, web)
	s.WebOn = true
	s.Env.WebOn = true

	if !s.webEnabled() {
		t.Fatal("web should be on before the toggle")
	}
	s.handleSlash("web off")

	if s.webEnabled() {
		t.Error("webEnabled() still true after /web off")
	}
	for _, d := range tools.Definitions(s.webEnabled()) {
		fm, _ := d["function"].(map[string]any)
		if n, _ := fm["name"].(string); isWebTool(n) {
			t.Errorf("web tool %q still advertised after /web off", n)
		}
	}
	res := s.Env.Execute(context.Background(), "websearch", map[string]any{"query": "x"})
	if strings.Contains(res.Output, "LEAKED") {
		t.Errorf("websearch reached the network after /web off: %s", res.Summary)
	}
	if !strings.Contains(strings.ToLower(res.Output), "disabled") {
		t.Errorf("websearch should report disabled, got: %+v", res)
	}
}

// The schema filter and the execution gate must agree. If a web tool is
// hidden from the model but still runnable at execution (or vice versa),
// "/web off" stops being a real control.
func TestWebToolGateMatchesSchemaFilter(t *testing.T) {
	web := websearch.New(websearch.Config{Enabled: true, Provider: "duckduckgo"})
	s := newWebSession(t, web)
	s.WebOn = true
	s.Env.WebOn = true
	s.handleSlash("web off") // revoked

	if s.webEnabled() {
		t.Fatal("web still enabled after /web off")
	}
	gated := map[string]bool{}
	for _, d := range tools.Definitions(true) {
		fm, _ := d["function"].(map[string]any)
		name, _ := fm["name"].(string)
		if isWebTool(name) {
			gated[name] = true
		}
	}
	if len(gated) != 2 || !gated["websearch"] || !gated["webfetch"] {
		t.Fatalf("expected both web tools to be web-gated, got %v", gated)
	}
	// Both are hidden from the schema when revoked...
	visible := map[string]bool{}
	for _, d := range tools.Definitions(s.webEnabled()) {
		fm, _ := d["function"].(map[string]any)
		name, _ := fm["name"].(string)
		if isWebTool(name) {
			visible[name] = true
		}
	}
	if len(visible) != 0 {
		t.Errorf("web tools still advertised after /web off: %v", visible)
	}
	// ...and both refuse at the execution boundary.
	for _, name := range []string{"websearch", "webfetch"} {
		args := map[string]any{"query": "x", "url": "https://example.com"}
		res := s.Env.Execute(context.Background(), name, args)
		if !strings.Contains(strings.ToLower(res.Output), "disabled") {
			t.Errorf("%s did not refuse after /web off: %+v", name, res)
		}
	}
	// Non-web tools must remain unaffected.
	if res := s.Env.Execute(context.Background(), "stats", map[string]any{}); res.Output == "" {
		t.Error("stats should still work while web is off")
	}
}

// The toggle must also work back the other way, but only when the user opted
// in at startup.
func TestWebOnRequiresStartupConsent(t *testing.T) {
	s := newWebSession(t, nil)
	s.handleSlash("web on")
	if s.webEnabled() {
		t.Error("/web on must not enable web when Env.Web is nil")
	}
	out := s.Out.(*bytes.Buffer)
	if !strings.Contains(out.String(), "disabled in config") {
		t.Errorf("expected a refusal message, got: %q", out.String())
	}
}
