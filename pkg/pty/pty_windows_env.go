//go:build windows

package pty

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var windowsTerminalProcessFallbackKeys = []string{
	"ALLUSERSPROFILE",
	"ComSpec",
	"OS",
	"PATHEXT",
	"Path",
	"PROCESSOR_ARCHITECTURE",
	"ProgramFiles",
	"ProgramFiles(x86)",
	"ProgramW6432",
	"PSModulePath",
	"PUBLIC",
	"SystemDrive",
	"SystemRoot",
	"TEMP",
	"TMP",
	"windir",
}

func windowsTerminalEnv() []string {
	processEnv := os.Environ()
	userEnv, err := activeWindowsUserEnv()
	if err != nil || len(userEnv) == 0 {
		return processEnv
	}
	return mergeWindowsTerminalEnv(processEnv, userEnv)
}

func activeWindowsUserEnv() ([]string, error) {
	sessionIDs, err := activeWindowsSessionIDs()
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, sessionID := range sessionIDs {
		var token windows.Token
		if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
			lastErr = err
			continue
		}
		env, err := token.Environ(false)
		_ = token.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if len(env) > 0 {
			return env, nil
		}
	}
	return nil, lastErr
}

func activeWindowsSessionIDs() ([]uint32, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		consoleID := windows.WTSGetActiveConsoleSessionId()
		if consoleID == 0xffffffff {
			return nil, err
		}
		return []uint32{consoleID}, nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))

	out := make([]uint32, 0, count)
	for _, session := range unsafe.Slice(sessions, count) {
		if session.State == windows.WTSActive {
			out = append(out, session.SessionID)
		}
	}
	if len(out) == 0 {
		consoleID := windows.WTSGetActiveConsoleSessionId()
		if consoleID != 0xffffffff {
			out = append(out, consoleID)
		}
	}
	return out, nil
}

func mergeWindowsTerminalEnv(processEnv, userEnv []string) []string {
	if len(userEnv) == 0 {
		return processEnv
	}

	result := make([]string, 0, len(userEnv)+len(windowsTerminalProcessFallbackKeys))
	seen := make(map[string]struct{}, len(userEnv)+len(windowsTerminalProcessFallbackKeys))
	for _, kv := range userEnv {
		result = append(result, kv)
		if name := envName(kv); name != "" {
			seen[strings.ToUpper(name)] = struct{}{}
		}
	}

	processByName := make(map[string]string, len(processEnv))
	for _, kv := range processEnv {
		if name := envName(kv); name != "" {
			upper := strings.ToUpper(name)
			if _, ok := processByName[upper]; !ok {
				processByName[upper] = kv
			}
		}
	}

	for _, name := range windowsTerminalProcessFallbackKeys {
		upper := strings.ToUpper(name)
		if _, ok := seen[upper]; ok {
			continue
		}
		if kv, ok := processByName[upper]; ok {
			result = append(result, kv)
			seen[upper] = struct{}{}
		}
	}
	return result
}

func envName(kv string) string {
	name, _, ok := strings.Cut(kv, "=")
	if !ok {
		return ""
	}
	return name
}
