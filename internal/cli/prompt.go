package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// isTerminal reports whether f refers to an interactive character device.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// requireTerminal guards interactive commands against piped stdin.
func requireTerminal(command string) error {
	if isTerminal(os.Stdin) {
		return nil
	}
	return &terminalNeededError{command: command}
}

type terminalNeededError struct{ command string }

func (e *terminalNeededError) Error() string {
	return e.command + " needs an interactive terminal; pipe-friendly alternatives: doctor, list, stats, analyze, captures"
}

// askString prints label and reads a line, returning def on empty input.
// ok=false signals EOF (abort the wizard).
func askString(r *bufio.Reader, w io.Writer, label, def string) (string, bool) {
	suffix := ""
	if def != "" {
		suffix = " [" + def + "]"
	}
	fmt.Fprintf(w, "%s%s > ", label, suffix)
	line, err := r.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		fmt.Fprintln(w)
		return "", false
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, true
	}
	return line, true
}

// askYesNo reads y/n; Enter picks def. ok=false on EOF.
func askYesNo(r *bufio.Reader, w io.Writer, label string, def bool) (bool, bool) {
	options := "[y/N]"
	if def {
		options = "[Y/n]"
	}
	for {
		fmt.Fprintf(w, "%s %s > ", label, options)
		line, err := r.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			fmt.Fprintln(w)
			return def, false
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def, true
		case "y", "yes":
			return true, true
		case "n", "no":
			return false, true
		default:
			fmt.Fprintln(w, "  please answer y or n")
		}
	}
}

// askChoice renders a numbered menu and returns the chosen index.
func askChoice(r *bufio.Reader, w io.Writer, label string, options []string, defIdx int) (int, bool) {
	for i, o := range options {
		marker := "  "
		if i == defIdx {
			marker = "→ "
		}
		fmt.Fprintf(w, "  %s%d) %s\n", marker, i+1, o)
	}
	for {
		s, ok := askString(r, w, label, strconv.Itoa(defIdx+1))
		if !ok {
			return defIdx, false
		}
		n := parseChoice(s, len(options))
		if n >= 0 {
			return n, true
		}
		fmt.Fprintf(w, "  pick 1-%d\n", len(options))
	}
}

func parseChoice(s string, max int) int {
	var n int
	if s == "" || len(s) > 3 {
		return -1
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > max {
		return -1
	}
	return n - 1
}
