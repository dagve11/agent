//go:build !windows

package pty

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	opty "github.com/creack/pty"
)

var _ IPty = (*Pty)(nil)

var defaultShells = []string{"zsh", "fish", "bash", "sh"}

type Pty struct {
	tty *os.File
	cmd *exec.Cmd
}

func DownloadDependency() error {
	return nil
}

func Start() (IPty, error) {
	var shellPath string
	for _, sh := range defaultShells {
		shellPath, _ = exec.LookPath(sh)
		if shellPath != "" {
			break
		}
	}
	if shellPath == "" {
		return nil, errors.New("没有可用终端")
	}
	cmd := loginShellCommand(shellPath)
	cmd.Env = terminalEnv(shellPath)
	tty, err := opty.Start(cmd)
	return &Pty{tty: tty, cmd: cmd}, err
}

func terminalEnv(shellPath string) []string {
	env := os.Environ()
	env = mergeMissingEnv(env, readEnvironmentFile("/etc/environment"))
	env = ensureUserEnv(env, shellPath)
	env = setEnvValue(env, "TERM", "xterm-256color")
	env = setEnvValue(env, "LANG", "en_US.UTF-8")
	env = setEnvValue(env, "LC_ALL", "en_US.UTF-8")
	return env
}

func ensureUserEnv(env []string, shellPath string) []string {
	current, _ := user.Current()
	if current != nil {
		env = setEnvDefault(env, "HOME", current.HomeDir)
		env = setEnvDefault(env, "USER", current.Username)
		env = setEnvDefault(env, "LOGNAME", current.Username)
	}
	return setEnvDefault(env, "SHELL", shellPath)
}

func readEnvironmentFile(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var env []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if kv, ok := parseEnvironmentLine(scanner.Text()); ok {
			env = append(env, kv)
		}
	}
	return env
}

func parseEnvironmentLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	line = strings.TrimPrefix(line, "export ")
	name, value, ok := strings.Cut(line, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" || strings.ContainsAny(name, " \t") {
		return "", false
	}
	value = strings.TrimSpace(value)
	if unquoted, err := strconv.Unquote(value); err == nil {
		value = unquoted
	}
	return name + "=" + value, true
}

func mergeMissingEnv(base []string, extra []string) []string {
	seen := make(map[string]struct{}, len(base))
	for _, kv := range base {
		if name := envName(kv); name != "" {
			seen[name] = struct{}{}
		}
	}
	for _, kv := range extra {
		name := envName(kv)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		base = append(base, kv)
		seen[name] = struct{}{}
	}
	return base
}

func setEnvDefault(env []string, name string, value string) []string {
	if value == "" || hasEnvName(env, name) {
		return env
	}
	return append(env, name+"="+value)
}

func setEnvValue(env []string, name string, value string) []string {
	for i, kv := range env {
		if envName(kv) == name {
			env[i] = name + "=" + value
			return env
		}
	}
	return append(env, name+"="+value)
}

func hasEnvName(env []string, name string) bool {
	for _, kv := range env {
		if envName(kv) == name {
			return true
		}
	}
	return false
}

func envName(kv string) string {
	name, _, ok := strings.Cut(kv, "=")
	if !ok {
		return ""
	}
	return name
}

func (pty *Pty) Write(p []byte) (n int, err error) {
	return pty.tty.Write(p)
}

func (pty *Pty) Read(p []byte) (n int, err error) {
	return pty.tty.Read(p)
}

func (pty *Pty) Getsize() (uint16, uint16, error) {
	ws, err := opty.GetsizeFull(pty.tty)
	if err != nil {
		return 0, 0, err
	}
	return ws.Cols, ws.Rows, nil
}

func (pty *Pty) Setsize(cols, rows uint32) error {
	return opty.Setsize(pty.tty, &opty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	})
}

func (pty *Pty) killChildProcess(c *exec.Cmd) error {
	pgid, err := syscall.Getpgid(c.Process.Pid)
	if err != nil {
		// Fall-back on error. Kill the main process only.
		c.Process.Kill()
	}
	// Kill the whole process group.
	syscall.Kill(-pgid, syscall.SIGKILL) // SIGKILL 直接杀掉 SIGTERM 发送信号，等待进程自己退出
	return c.Wait()
}

func (pty *Pty) Close() error {
	if err := pty.tty.Close(); err != nil {
		return err
	}
	return pty.killChildProcess(pty.cmd)
}
