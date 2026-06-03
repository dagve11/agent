package pty

import (
	"os/exec"
	"path/filepath"
)

func loginShellCommand(shellPath string) *exec.Cmd {
	cmd := exec.Command(shellPath) // #nosec
	cmd.Args[0] = "-" + filepath.Base(shellPath)
	return cmd
}
