package pty

import (
	"path/filepath"
	"testing"
)

func TestLoginShellCommandUsesDashPrefixedArgv0(t *testing.T) {
	cmd := loginShellCommand("/bin/bash")

	if cmd.Path != "/bin/bash" {
		t.Fatalf("cmd path = %q, want /bin/bash", cmd.Path)
	}
	if len(cmd.Args) == 0 {
		t.Fatal("cmd args must not be empty")
	}
	if cmd.Args[0] != "-bash" {
		t.Fatalf("argv[0] = %q, want -bash", cmd.Args[0])
	}
}

func TestLoginShellCommandUsesShellBaseName(t *testing.T) {
	shellPath := filepath.Join("/usr/local/bin", "zsh")
	cmd := loginShellCommand(shellPath)

	if cmd.Args[0] != "-zsh" {
		t.Fatalf("argv[0] = %q, want -zsh", cmd.Args[0])
	}
}
