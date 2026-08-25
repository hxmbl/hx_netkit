// Package llm talks to a local Ollama server: streaming chat with tool
// calling, availability probing, and auto-start of a local daemon.
package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Message is one chat message. Role: system | user | assistant | tool.
type Message struct {
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	ToolName  string     `json:"tool_name,omitempty"`
}

// ToolCall mirrors Ollama's tool_calls entries.
type ToolCall struct {
	Function struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"function"`
}

// Response aggregates one streamed assistant turn.
type Response struct {
	Content   string
	ToolCalls []ToolCall
}

// Options tunes generation.
type Options struct {
	Temperature float32 `json:"temperature"`
	NumPredict  int     `json:"num_predict"`
	NumCtx      int     `json:"num_ctx"`
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Tools    any       `json:"tools,omitempty"`
	Stream   bool      `json:"stream"`
	Options  Options   `json:"options"`
}

// Client is an Ollama HTTP client.
type Client struct {
	BaseURL string
	Model   string
	NumCtx  int
	HTTP    *http.Client
	probe   *http.Client // short-timeout client for availability checks

	// OnToken fires for each streamed content token (nil-safe).
	OnToken func(string)
}

// New creates a client pointed at baseURL (default http://localhost:11434).
func New(baseURL, model string, numCtx int) *Client {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Model:   model,
		NumCtx:  numCtx,
		HTTP:    &http.Client{Timeout: 300 * time.Second},
		probe:   &http.Client{Timeout: 3 * time.Second},
	}
}

// Available probes the /api/tags endpoint with a short timeout so an
// unreachable host cannot stall startup for minutes.
func (c *Client) Available(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/tags", nil)
	if err != nil {
		return false
	}
	resp, err := c.probe.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// TryStart launches `ollama serve` in the background when the URL is local
// and nothing answers yet. Returns true when the server becomes reachable.
func (c *Client) TryStart(ctx context.Context) bool {
	if c.Available(ctx) {
		return true
	}
	host := c.BaseURL
	if !strings.Contains(host, "localhost") && !strings.Contains(host, "127.0.0.1") {
		return false
	}
	cmd := execCommand("ollama", "serve")
	if cmd == nil {
		return false
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		if c.Available(ctx) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
	}
	return false
}

// Chat streams one assistant turn. Tools may be nil/empty to disable them.
// The returned Response carries concatenated content and any tool calls.
func (c *Client) Chat(ctx context.Context, messages []Message, tools []map[string]any) (*Response, error) {
	body := chatRequest{
		Model:    c.Model,
		Messages: messages,
		Stream:   true,
		Options:  Options{Temperature: 0.3, NumPredict: 2048, NumCtx: c.NumCtx},
	}
	if len(tools) > 0 {
		body.Tools = tools
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/chat", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		var errBody struct {
			Error string `json:"error"`
		}
		detail := strings.TrimSpace(string(raw))
		if json.Unmarshal(raw, &errBody) == nil && errBody.Error != "" {
			detail = errBody.Error
		}
		return nil, fmt.Errorf("Ollama at %s rejected model '%s': %s (%d)",
			c.BaseURL, c.Model, detail, resp.StatusCode)
	}

	out := &Response{}
	reader := bufio.NewReaderSize(resp.Body, 64*1024)
	for {
		line, rerr := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			var chunk struct {
				Message struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Function struct {
							Name      string          `json:"name"`
							Arguments json.RawMessage `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
				Error string `json:"error"`
				Done  bool   `json:"done"`
			}
			if jerr := json.Unmarshal([]byte(trimmed), &chunk); jerr == nil {
				if chunk.Error != "" {
					return nil, fmt.Errorf("Ollama error: %s", chunk.Error)
				}
				if chunk.Message.Content != "" {
					out.Content += chunk.Message.Content
					if c.OnToken != nil {
						c.OnToken(chunk.Message.Content)
					}
				}
				for _, tc := range chunk.Message.ToolCalls {
					call := ToolCall{Function: struct {
						Name      string         `json:"name"`
						Arguments map[string]any `json:"arguments"`
					}{Name: tc.Function.Name}}
					call.Function.Arguments = parseArgs(tc.Function.Arguments)
					out.ToolCalls = append(out.ToolCalls, call)
				}
				if chunk.Done {
					return out, nil
				}
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return out, rerr
		}
	}
	return out, nil
}

// Generate performs a single non-interactive completion without tools.
func (c *Client) Generate(ctx context.Context, prompt string) (string, error) {
	msgs := []Message{{Role: "user", Content: prompt}}
	resp, err := c.Chat(ctx, msgs, nil)
	if err != nil {
		return "", err
	}
	content := strings.TrimSpace(resp.Content)
	if content == "" {
		return "", fmt.Errorf("empty response from Ollama")
	}
	return content, nil
}

func parseArgs(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err == nil {
		return m
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		var inner map[string]any
		if json.Unmarshal([]byte(s), &inner) == nil {
			return inner
		}
	}
	return map[string]any{}
}
