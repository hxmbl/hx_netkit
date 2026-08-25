package tools

import (
	"os/exec"
	"strings"
	"time"
)

func timeDuration(secs int64) time.Duration { return time.Duration(secs) * time.Second }
func timeSleep(d time.Duration)             { time.Sleep(d) }

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// sudoCommand builds a command invoking prog via sudo unless already root.
// Stderr is left assignable so callers can capture diagnostics.
func sudoCommand(prog string, args ...string) *exec.Cmd {
	isRoot := false
	if out, err := exec.Command("id", "-u").Output(); err == nil {
		isRoot = strings.TrimSpace(string(out)) == "0"
	}
	if isRoot {
		return exec.Command(prog, args...)
	}
	full := append([]string{prog}, args...)
	return exec.Command("sudo", full...)
}

// stopProcess interrupts a running capture process.
func stopProcess(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}

// waitProcess reaps the child to avoid zombies.
func waitProcess(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_, _ = cmd.Process.Wait()
}
