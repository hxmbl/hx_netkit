package llm

import "os/exec"

func execCommand(prog string, args ...string) *exec.Cmd {
	cmd := exec.Command(prog, args...)
	// Detached daemon must not pollute the correlator's terminal.
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	return cmd
}
