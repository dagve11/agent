//go:build windows

package pty

import (
	"reflect"
	"strings"
	"testing"
)

func TestMergeWindowsTerminalEnvPrefersActiveUserEnvAndFillsEssentials(t *testing.T) {
	processEnv := []string{
		`USERPROFILE=C:\WINDOWS\system32\config\systemprofile`,
		`Path=C:\Windows\System32`,
		`SystemRoot=C:\Windows`,
		`ComSpec=C:\Windows\System32\cmd.exe`,
		`PATHEXT=.COM;.EXE;.BAT;.CMD`,
		`NZ_CLIENT_SECRET=secret`,
		`ANTHROPIC_BASE_URL=https://official.example`,
	}
	userEnv := []string{
		`USERPROFILE=C:\Users\alice`,
		`APPDATA=C:\Users\alice\AppData\Roaming`,
		`LOCALAPPDATA=C:\Users\alice\AppData\Local`,
		`Path=C:\Users\alice\AppData\Roaming\npm;C:\Windows\System32`,
		`ANTHROPIC_BASE_URL=https://relay.example`,
	}

	got := mergeWindowsTerminalEnv(processEnv, userEnv)
	env := envByUppercaseName(got)

	if env["USERPROFILE"] != `C:\Users\alice` {
		t.Fatalf("USERPROFILE = %q, want active user profile", env["USERPROFILE"])
	}
	if env["PATH"] != `C:\Users\alice\AppData\Roaming\npm;C:\Windows\System32` {
		t.Fatalf("PATH = %q, want active user PATH", env["PATH"])
	}
	if env["ANTHROPIC_BASE_URL"] != "https://relay.example" {
		t.Fatalf("ANTHROPIC_BASE_URL = %q, want active user relay URL", env["ANTHROPIC_BASE_URL"])
	}
	if env["SYSTEMROOT"] != `C:\Windows` {
		t.Fatalf("SystemRoot = %q, want process fallback value", env["SYSTEMROOT"])
	}
	if env["COMSPEC"] != `C:\Windows\System32\cmd.exe` {
		t.Fatalf("ComSpec = %q, want process fallback value", env["COMSPEC"])
	}
	if _, ok := env["NZ_CLIENT_SECRET"]; ok {
		t.Fatal("NZ_CLIENT_SECRET must not be injected into terminal environment")
	}
}

func TestMergeWindowsTerminalEnvFallsBackToProcessEnvWhenUserEnvMissing(t *testing.T) {
	processEnv := []string{
		`USERPROFILE=C:\WINDOWS\system32\config\systemprofile`,
		`Path=C:\Windows\System32`,
		`NZ_CLIENT_SECRET=secret`,
	}

	got := mergeWindowsTerminalEnv(processEnv, nil)
	if !reflect.DeepEqual(got, processEnv) {
		t.Fatalf("mergeWindowsTerminalEnv() = %#v, want process env fallback", got)
	}
}

func envByUppercaseName(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		out[strings.ToUpper(name)] = value
	}
	return out
}
