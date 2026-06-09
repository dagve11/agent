package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nezhahq/agent/model"
)

type vpnTunManager interface {
	Preflight(model.VPNControlRequest) error
	Snapshot(model.VPNControlRequest, string) (string, error)
	Restore(model.VPNControlRequest, string) error
}

type platformVPNTunManager struct{}

func defaultVPNTunManager() vpnTunManager {
	return platformVPNTunManager{}
}

func (platformVPNTunManager) Preflight(req model.VPNControlRequest) error {
	if !isVPNTunMode(req.Mode) {
		return nil
	}
	if strings.TrimSpace(req.TunName) == "" {
		req.TunName = "nezha-vpn"
	}

	switch runtime.GOOS {
	case "windows":
		if !isElevatedRuntime() {
			return errors.New("administrator privileges are required for TUN mode")
		}
		if !wintunAvailable() {
			return errors.New("Wintun is not available")
		}
	case "linux":
		if os.Geteuid() != 0 {
			return errors.New("root or CAP_NET_ADMIN is required for TUN mode")
		}
		if _, err := os.Stat("/dev/net/tun"); err != nil {
			return fmt.Errorf("/dev/net/tun is not available: %w", err)
		}
	case "darwin":
		if os.Geteuid() != 0 {
			return errors.New("root privileges are required for TUN mode")
		}
	default:
		return fmt.Errorf("TUN mode is not supported on %s", runtime.GOOS)
	}
	return nil
}

type vpnTunSystemSnapshot struct {
	Version       int              `json:"version"`
	GOOS          string           `json:"goos"`
	SessionID     string           `json:"session_id"`
	Role          string           `json:"role"`
	Mode          string           `json:"mode"`
	TunName       string           `json:"tun_name,omitempty"`
	TunInterface  string           `json:"tun_interface,omitempty"`
	DNSServer     string           `json:"dns_server,omitempty"`
	RoutePrint    string           `json:"route_print,omitempty"`
	DNS           []vpnTunDNSState `json:"dns,omitempty"`
	RestoreIssued bool             `json:"restore_issued,omitempty"`
}

type vpnTunDNSState struct {
	Family    string   `json:"family,omitempty"`
	Interface string   `json:"interface,omitempty"`
	Source    string   `json:"source,omitempty"`
	Servers   []string `json:"servers,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	Raw       string   `json:"raw,omitempty"`
	Path      string   `json:"path,omitempty"`
}

func (platformVPNTunManager) Snapshot(req model.VPNControlRequest, sessionDir string) (string, error) {
	if req.Role != model.VPNRoleEntry || !isVPNTunMode(req.Mode) {
		return "", nil
	}
	if strings.TrimSpace(sessionDir) == "" {
		return "", errors.New("TUN snapshot session directory is required")
	}
	snapshot := vpnTunSystemSnapshot{
		Version:   1,
		GOOS:      runtime.GOOS,
		SessionID: req.SessionID,
		Role:      req.Role,
		Mode:      req.Mode,
		TunName:   firstNonEmpty(req.TunName, "nezha-vpn"),
		DNSServer: req.DNSServer,
	}
	if runtime.GOOS == "windows" {
		if err := fillWindowsVPNTunSnapshot(&snapshot); err != nil {
			return "", err
		}
	}
	if runtime.GOOS == "linux" {
		if err := fillLinuxVPNTunSnapshot(&snapshot); err != nil {
			return "", err
		}
	}
	if runtime.GOOS == "darwin" {
		if err := fillDarwinVPNTunSnapshot(&snapshot); err != nil {
			return "", err
		}
	}
	path := filepath.Join(sessionDir, "tun-snapshot.json")
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return "", err
	}
	return path, nil
}

func (platformVPNTunManager) Restore(req model.VPNControlRequest, snapshotPath string) error {
	if req.Role != model.VPNRoleEntry || !isVPNTunMode(req.Mode) || strings.TrimSpace(snapshotPath) == "" {
		return nil
	}
	if _, err := os.Stat(snapshotPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if runtime.GOOS == "windows" {
		if err := restoreWindowsVPNTunSnapshot(req, snapshotPath); err != nil {
			return err
		}
	}
	if runtime.GOOS == "linux" {
		if err := restoreLinuxVPNTunSnapshot(req, snapshotPath); err != nil {
			return err
		}
	}
	if runtime.GOOS == "darwin" {
		if err := restoreDarwinVPNTunSnapshot(req, snapshotPath); err != nil {
			return err
		}
	}
	return os.Remove(snapshotPath)
}

func wintunAvailable() bool {
	for _, candidate := range vpnWintunCandidatePaths(defaultVPNWorkDir()) {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return true
		}
	}
	return false
}

func ensureVPNWintunAvailable(ctx context.Context, req model.VPNControlRequest, workDir string, httpClient vpnHTTPClient) error {
	if !isWindowsRuntime() || req.Role != model.VPNRoleEntry || !isVPNTunMode(req.Mode) {
		return nil
	}
	for _, candidate := range vpnWintunCandidatePaths(workDir) {
		if _, err := os.Stat(candidate); err == nil {
			return nil
		}
	}
	_, err := installVPNWintun(ctx, req, workDir, httpClient)
	return err
}

func installVPNWintun(ctx context.Context, req model.VPNControlRequest, workDir string, httpClient vpnHTTPClient) (string, error) {
	if err := validateVPNWintunSpec(req); err != nil {
		return "", err
	}
	targetPath := vpnWintunTargetPath(workDir)
	if sourcePath := strings.TrimSpace(req.Extra["wintun_path"]); sourcePath != "" {
		if err := copyVPNFile(sourcePath, targetPath); err != nil {
			return "", fmt.Errorf("copy Wintun from %s: %w", sourcePath, err)
		}
		if err := verifyVPNCoreSHA256(targetPath, req.Extra["wintun_sha256"]); err != nil {
			_ = os.Remove(targetPath)
			return "", err
		}
		return targetPath, nil
	}

	if downloadURL := strings.TrimSpace(req.Extra["wintun_url"]); downloadURL != "" {
		if httpClient == nil {
			httpClient = httpClientDefault()
		}
		if err := downloadVPNCore(ctx, downloadURL, targetPath, httpClient); err != nil {
			return "", fmt.Errorf("download Wintun: %w", err)
		}
		if err := verifyVPNCoreSHA256(targetPath, req.Extra["wintun_sha256"]); err != nil {
			_ = os.Remove(targetPath)
			return "", err
		}
		return targetPath, nil
	}

	return "", errors.New("Wintun is not available")
}

func vpnWintunTargetPath(workDir string) string {
	if strings.TrimSpace(agentConfig.VPNCoreDir) != "" {
		return filepath.Join(strings.TrimSpace(agentConfig.VPNCoreDir), "wintun.dll")
	}
	if strings.TrimSpace(workDir) == "" {
		workDir = defaultVPNWorkDir()
	}
	return filepath.Join(workDir, "core", "wintun.dll")
}

func vpnWintunCandidatePaths(workDir string) []string {
	candidates := make([]string, 0, 4)
	if executablePath != "" {
		candidates = append(candidates, filepath.Join(filepath.Dir(executablePath), "wintun.dll"))
	}
	if strings.TrimSpace(agentConfig.VPNCoreDir) != "" {
		candidates = append(candidates, filepath.Join(strings.TrimSpace(agentConfig.VPNCoreDir), "wintun.dll"))
	}
	if strings.TrimSpace(agentConfig.VPNStateDir) != "" {
		candidates = append(candidates, filepath.Join(strings.TrimSpace(agentConfig.VPNStateDir), "core", "wintun.dll"))
	}
	if strings.TrimSpace(workDir) != "" {
		candidates = append(candidates, filepath.Join(workDir, "core", "wintun.dll"))
	}
	candidates = append(candidates, filepath.Join(defaultVPNWorkDir(), "core", "wintun.dll"))
	return candidates
}

func copyVPNFile(sourcePath string, targetPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()

	if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
		return err
	}
	tmpPath := targetPath + ".tmp"
	target, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(target, source)
	closeErr := target.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}
	return os.Rename(tmpPath, targetPath)
}

func httpClientDefault() vpnHTTPClient {
	return httpClient
}
