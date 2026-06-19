package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/processgroup"
)

type vpnSidecarStartSpec struct {
	SessionID  string
	Role       string
	WorkDir    string
	ConfigPath string
	LogPath    string
	CorePath   string
}

type vpnSidecarProcess interface {
	Stop() error
	Wait() error
}

type vpnSidecarRunner func(context.Context, vpnSidecarStartSpec) (vpnSidecarProcess, error)

type AgentVPNSidecar struct {
	spec    vpnSidecarStartSpec
	process vpnSidecarProcess
}

func defaultVPNWorkDir() string {
	base := "."
	if executablePath != "" {
		base = filepath.Dir(executablePath)
	}
	return filepath.Join(base, "vpn")
}

func defaultVPNCorePath() string {
	name := "sing-box"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(defaultVPNWorkDir(), "core", name)
}

func startAgentVPNSidecar(ctx context.Context, req model.VPNControlRequest, workDir string, corePath string, runner vpnSidecarRunner) (*AgentVPNSidecar, error) {
	if runner == nil {
		runner = defaultVPNSidecarRunner
	}
	if strings.TrimSpace(workDir) == "" {
		workDir = defaultVPNWorkDir()
	}
	if strings.TrimSpace(corePath) == "" {
		corePath = defaultVPNCorePath()
	}

	sessionDir := filepath.Join(workDir, "sessions", safeVPNPathName(req.SessionID))
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		return nil, err
	}

	config, err := buildVPNSingBoxConfig(req)
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(sessionDir, "config.json")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		return nil, err
	}

	spec := vpnSidecarStartSpec{
		SessionID:  req.SessionID,
		Role:       req.Role,
		WorkDir:    sessionDir,
		ConfigPath: configPath,
		LogPath:    filepath.Join(sessionDir, "sing-box.log"),
		CorePath:   corePath,
	}
	process, err := runner(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &AgentVPNSidecar{spec: spec, process: process}, nil
}

func (s *AgentVPNSidecar) Stop() error {
	if s == nil || s.process == nil {
		return nil
	}
	return s.process.Stop()
}

func (s *AgentVPNSidecar) Wait() error {
	if s == nil || s.process == nil {
		return nil
	}
	return s.process.Wait()
}

type execVPNSidecarProcess struct {
	cmd     *exec.Cmd
	group   processExitGroup
	waitErr chan error
	once    sync.Once
}

type processExitGroup interface {
	AddProcess(*exec.Cmd) error
	Dispose() error
	Close()
}

func defaultVPNSidecarRunner(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
	if strings.TrimSpace(spec.CorePath) == "" {
		return nil, errors.New("VPN core path is required")
	}
	cmd := processgroup.NewExecCommandContext(ctx, spec.CorePath, "run", "-c", spec.ConfigPath)
	cmd.Dir = spec.WorkDir
	logFile, err := os.OpenFile(spec.LogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	group, err := processgroup.NewProcessExitGroup()
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		group.Close()
		_ = logFile.Close()
		return nil, err
	}
	if err := group.AddProcess(cmd); err != nil {
		_ = cmd.Process.Kill()
		group.Close()
		_ = logFile.Close()
		return nil, err
	}

	process := &execVPNSidecarProcess{
		cmd:     cmd,
		group:   normalizeProcessExitGroup(group),
		waitErr: make(chan error, 1),
	}
	go func() {
		process.waitErr <- cmd.Wait()
		_ = logFile.Close()
	}()
	return process, nil
}

func (p *execVPNSidecarProcess) Stop() error {
	if p == nil {
		return nil
	}
	var err error
	p.once.Do(func() {
		if p.group != nil {
			err = p.group.Dispose()
			return
		}
		if p.cmd != nil && p.cmd.Process != nil {
			err = p.cmd.Process.Kill()
		}
	})
	return err
}

func (p *execVPNSidecarProcess) Wait() error {
	if p == nil || p.waitErr == nil {
		return nil
	}
	return <-p.waitErr
}

func normalizeProcessExitGroup(group any) processExitGroup {
	switch g := group.(type) {
	case processExitGroup:
		return g
	case processgroup.ProcessExitGroup:
		return &g
	default:
		return nil
	}
}

var vpnPathUnsafePattern = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

func safeVPNPathName(value string) string {
	value = strings.TrimSpace(value)
	value = vpnPathUnsafePattern.ReplaceAllString(value, "_")
	value = strings.Trim(value, "._")
	if value == "" {
		return "session"
	}
	return value
}

func vpnSidecarMetadata(sidecar *AgentVPNSidecar) (string, string) {
	if sidecar == nil {
		return "", ""
	}
	return sidecar.spec.ConfigPath, sidecar.spec.LogPath
}

func vpnSidecarPID(sidecar *AgentVPNSidecar) int {
	if sidecar == nil || sidecar.process == nil {
		return 0
	}
	process, ok := sidecar.process.(*execVPNSidecarProcess)
	if !ok || process.cmd == nil || process.cmd.Process == nil {
		return 0
	}
	return process.cmd.Process.Pid
}

func killStaleVPNSidecarProcess(pid int) error {
	if pid <= 0 {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}

func vpnSidecarStartError(req model.VPNControlRequest, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("start VPN sidecar for session %s role %s: %w", req.SessionID, req.Role, err)
}
