package cli

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/ergochat/readline"

	"github.com/hxmbl/hx_netkit/internal/config"
	"github.com/hxmbl/hx_netkit/internal/llm"
	"github.com/hxmbl/hx_netkit/internal/store"
)

// editline adapts ergochat/readline to the llm.LineEditor interface,
// adding persistent history and tab completion over slash commands and
// known device IPs.
type editline struct {
	rl *readline.Instance
}

var _ llm.LineEditor = (*editline)(nil)

// slashCommands offered by tab completion (chat session surface).
var slashCommands = []string{
	"/help", "/beliefs", "/scan ", "/web ",
	"/ip ", "/port ", "/dns ", "/find ", "/devices", "/stats",
	"/talkers ", "/recent ", "/connections ", "/services ",
}

var searchVerbs = []string{
	"ip ", "host ", "port ", "dns ", "find ", "devices", "stats",
	"talkers ", "recent ", "connections ", "services ", "help",
}

// wordCompleter completes the token under the cursor against a dynamic
// word list (slash commands for the chat REPL, device IPs everywhere).
type wordCompleter struct {
	words func() []string
}

func (c wordCompleter) Do(line []rune, pos int) ([][]rune, int) {
	upTo := line[:pos]
	start := len(upTo)
	for start > 0 && upTo[start-1] != ' ' {
		start--
	}
	token := string(upTo[start:])
	prefix := token

	var out [][]rune
	for _, w := range c.words() {
		if strings.HasPrefix(w, prefix) && w != prefix {
			out = append(out, []rune(w))
		}
	}
	return out, start
}

func deviceIPWords(db *store.DB) func() []string {
	var cached []string
	if db != nil {
		if devs, err := db.Devices(); err == nil {
			for _, d := range devs {
				cached = append(cached, d.IP+" ")
			}
		}
	}
	return func() []string { return cached }
}

func newChatEditor(db *store.DB) (*editline, error) {
	words := func() []string {
		return append(append([]string{}, slashCommands...), deviceIPWords(db)()...)
	}
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "you> ",
		HistoryFile:     filepath.Join(config.Dir(), "history_chat"),
		HistoryLimit:    2000,
		AutoComplete:    wordCompleter{words: words},
		InterruptPrompt: "^C",
		EOFPrompt:       "quit",
	})
	if err != nil {
		return nil, err
	}
	return &editline{rl: rl}, nil
}

func newSearchEditor(db *store.DB) (*editline, error) {
	words := func() []string {
		return append(append([]string{}, searchVerbs...), deviceIPWords(db)()...)
	}
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "search> ",
		HistoryFile:     filepath.Join(config.Dir(), "history_search"),
		HistoryLimit:    2000,
		AutoComplete:    wordCompleter{words: words},
		InterruptPrompt: "^C",
		EOFPrompt:       "quit",
	})
	if err != nil {
		return nil, err
	}
	return &editline{rl: rl}, nil
}

// ReadLine implements llm.LineEditor.
func (e *editline) ReadLine(prompt string) (string, error) {
	e.rl.SetPrompt(prompt)
	line, err := e.rl.Readline()
	if errors.Is(err, readline.ErrInterrupt) {
		return "", llm.ErrLineCancelled
	}
	return line, err
}

// Close implements llm.LineEditor.
func (e *editline) Close() error {
	return e.rl.Close()
}
