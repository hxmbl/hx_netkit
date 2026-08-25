package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// streamServer emulates Ollama's NDJSON /api/chat streaming.
func streamServer(t *testing.T, chunks []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad request: %v", err)
			w.WriteHeader(400)
			return
		}
		if req.Stream != true {
			t.Error("client must request streaming")
		}
		if req.Options.NumCtx == 0 {
			t.Error("num_ctx must be forwarded")
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, c := range chunks {
			b, _ := json.Marshal(c)
			w.Write(b)
			w.Write([]byte("\n"))
		}
	}))
}

func TestChatStreamsContentAndToolCalls(t *testing.T) {
	srv := streamServer(t, []map[string]any{
		{"message": map[string]any{"content": "Hello"}},
		{"message": map[string]any{"content": " world"}},
		{"message": map[string]any{
			"content": "",
			"tool_calls": []map[string]any{{
				"function": map[string]any{
					"name":      "sql",
					"arguments": map[string]any{"query": "SELECT 1"},
				},
			}},
		}},
		{"done": true},
	})
	defer srv.Close()

	client := New(srv.URL, "test-model", 4096)
	var tokens []string
	client.OnToken = func(tok string) { tokens = append(tokens, tok) }

	resp, err := client.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content != "Hello world" {
		t.Errorf("content = %q", resp.Content)
	}
	if strings.Join(tokens, "") != "Hello world" {
		t.Errorf("token stream = %v", tokens)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Function.Name != "sql" {
		t.Fatalf("tool calls wrong: %+v", resp.ToolCalls)
	}
	if resp.ToolCalls[0].Function.Arguments["query"] != "SELECT 1" {
		t.Errorf("args = %+v", resp.ToolCalls[0].Function.Arguments)
	}
}

func TestChatParsesStringifiedArguments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		line := `{"message":{"content":"","tool_calls":[{"function":{"name":"packets","arguments":"{\"ip\":\"1.2.3.4\",\"limit\":5}"}}]},"done":false}`
		w.Write([]byte(line + "\n"))
		w.Write([]byte(`{"done":true}` + "\n"))
	}))
	defer srv.Close()

	resp, err := New(srv.URL, "m", 2048).Chat(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	args := resp.ToolCalls[0].Function.Arguments
	if args["ip"] != "1.2.3.4" {
		t.Errorf("string args not decoded: %+v", args)
	}
}

func TestChatSurfacesOllamaErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": "model not found"})
	}))
	defer srv.Close()

	_, err := New(srv.URL, "missing-model", 2048).Chat(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "model not found") {
		t.Errorf("error should carry Ollama detail, got %v", err)
	}
}

func TestChatInlineErrorChunk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Write([]byte(`{"error":"oom"}` + "\n"))
	}))
	defer srv.Close()

	_, err := New(srv.URL, "m", 2048).Chat(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "oom") {
		t.Errorf("inline error chunk not surfaced: %v", err)
	}
}

func TestGenerateRejectsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Write([]byte(`{"message":{"content":""},"done":true}` + "\n"))
	}))
	defer srv.Close()

	_, err := New(srv.URL, "m", 2048).Generate(context.Background(), "hello")
	if err == nil || !strings.Contains(err.Error(), "empty response") {
		t.Errorf("expected empty response error, got %v", err)
	}
}

func TestAvailableProbes(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/tags") {
			t.Errorf("probe hit %s", r.URL.Path)
		}
		w.WriteHeader(200)
	}))
	defer ok.Close()
	if !(New(ok.URL, "m", 2048).Available(context.Background())) {
		t.Error("server up but Available=false")
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer down.Close()
	if New(down.URL, "m", 2048).Available(context.Background()) {
		t.Error("server 503 but Available=true")
	}
}
