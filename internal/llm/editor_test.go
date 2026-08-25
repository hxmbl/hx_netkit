package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hxmbl/hx_netkit/internal/store"
	"github.com/hxmbl/hx_netkit/internal/tools"
)

// Regression (Phase 3): /help must show the SESSION help, not leak the
// search-engine help.
func TestHelpShowsSessionHelp(t *testing.T) {
	db, _ := store.OpenMemory()
	defer db.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	out := &strings.Builder{}
	s := &Session{
		Client:   New(srv.URL, "m", 2048),
		Env:      &tools.Env{DB: db},
		Prompter: AlwaysAllow{},
		In:       strings.NewReader("/help\nquit\n"),
		Out:      out,
	}
	s.Run(context.Background())

	got := out.String()
	if !strings.Contains(got, "Slash commands") || !strings.Contains(got, "/beliefs") {
		t.Errorf("/help did not render session help:\n%s", got)
	}
	if strings.Contains(got, "NETWORK SEARCH ENGINE") {
		t.Error("/help leaked the search REPL banner")
	}
}

// Phase 3: a LineEditor drives input; Ctrl-C (ErrLineCancelled) re-prompts
// instead of ending the session.
const cancelToken = "\x00CANCEL"

type fakeEditor struct {
	lines []string // cancelToken = Ctrl-C; end of list = EOF
	i     int
}

func (f *fakeEditor) ReadLine(prompt string) (string, error) {
	if f.i >= len(f.lines) {
		return "", io.EOF
	}
	l := f.lines[f.i]
	f.i++
	if l == cancelToken {
		return "", ErrLineCancelled
	}
	return l, nil
}

func (f *fakeEditor) Close() error { return nil }

func TestEditorDrivesSessionAndCtrlCCancelsLine(t *testing.T) {
	db, _ := store.OpenMemory()
	defer db.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		b, _ := json.Marshal(map[string]any{"message": map[string]any{"content": "ok"}})
		w.Write(b)
		w.Write([]byte("\n"))
		w.Write([]byte(`{"done":true}` + "\n"))
	}))
	defer srv.Close()

	out := &strings.Builder{}
	s := &Session{
		Client:   New(srv.URL, "m", 2048),
		Env:      &tools.Env{DB: db},
		Prompter: AlwaysAllow{},
		Editor: &fakeEditor{lines: []string{
			"first question",
			cancelToken,
			"quit",
		}},
		Out: out,
	}
	s.Run(context.Background())

	if !strings.Contains(out.String(), "(cancelled") {
		t.Errorf("cancelled line feedback missing:\n%s", out.String())
	}
	if s.messages[0].Role != "system" {
		t.Errorf("system preamble missing")
	}
}
