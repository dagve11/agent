//go:build !windows

package pty

import (
	"reflect"
	"testing"
)

func TestParseEnvironmentLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
		ok   bool
	}{
		{name: "plain", line: "HTTP_PROXY=http://127.0.0.1:8080", want: "HTTP_PROXY=http://127.0.0.1:8080", ok: true},
		{name: "quoted", line: `NO_PROXY="localhost,127.0.0.1"`, want: "NO_PROXY=localhost,127.0.0.1", ok: true},
		{name: "export", line: "export HTTPS_PROXY=https://proxy.example", want: "HTTPS_PROXY=https://proxy.example", ok: true},
		{name: "comment", line: "# HTTP_PROXY=http://127.0.0.1:8080", ok: false},
		{name: "invalid", line: "BAD NAME=value", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseEnvironmentLine(tt.line)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("parseEnvironmentLine(%q) = %q, %t; want %q, %t", tt.line, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestMergeMissingEnvDoesNotOverrideProcessEnv(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"HTTP_PROXY=http://process-proxy",
	}
	extra := []string{
		"HTTP_PROXY=http://system-proxy",
		"NO_PROXY=localhost,127.0.0.1",
	}

	got := mergeMissingEnv(base, extra)
	want := []string{
		"PATH=/usr/bin",
		"HTTP_PROXY=http://process-proxy",
		"NO_PROXY=localhost,127.0.0.1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeMissingEnv() = %#v, want %#v", got, want)
	}
}
