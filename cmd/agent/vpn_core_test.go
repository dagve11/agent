package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nezhahq/agent/model"
)

func TestPrepareVPNCoreUsesExistingFileWhenSHA256Matches(t *testing.T) {
	workDir := t.TempDir()
	corePath := filepath.Join(workDir, "core", "sing-box")
	content := []byte("core-binary")
	if err := os.MkdirAll(filepath.Dir(corePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corePath, content, 0600); err != nil {
		t.Fatal(err)
	}

	resolved, err := prepareVPNCore(context.Background(), model.VPNCoreSpec{
		Name:   "sing-box",
		SHA256: sha256HexForTest(content),
	}, corePath, nil)
	if err != nil {
		t.Fatalf("prepare core: %v", err)
	}
	if resolved != corePath {
		t.Fatalf("existing matching core should be reused: want %q got %q", corePath, resolved)
	}
}

func TestPrepareVPNCoreRejectsExistingFileWhenSHA256Mismatches(t *testing.T) {
	workDir := t.TempDir()
	corePath := filepath.Join(workDir, "core", "sing-box")
	if err := os.MkdirAll(filepath.Dir(corePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corePath, []byte("tampered-core"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := prepareVPNCore(context.Background(), model.VPNCoreSpec{
		Name:   "sing-box",
		SHA256: sha256HexForTest([]byte("expected-core")),
	}, corePath, nil)
	if err == nil {
		t.Fatal("SHA256 mismatch must reject existing core")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("error must explain hash mismatch, got %v", err)
	}
}

func TestPrepareVPNCoreDownloadsMissingCoreAndVerifiesSHA256(t *testing.T) {
	content := []byte("downloaded-core")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)

	workDir := t.TempDir()
	corePath := filepath.Join(workDir, "core", "sing-box")
	resolved, err := prepareVPNCore(context.Background(), model.VPNCoreSpec{
		Name:        "sing-box",
		SHA256:      sha256HexForTest(content),
		DownloadURL: server.URL + "/sing-box",
	}, corePath, server.Client())
	if err != nil {
		t.Fatalf("prepare downloaded core: %v", err)
	}
	if resolved != corePath {
		t.Fatalf("downloaded core path mismatch: want %q got %q", corePath, resolved)
	}
	got, err := os.ReadFile(corePath)
	if err != nil {
		t.Fatalf("downloaded core must be written: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("downloaded core content mismatch: %q", got)
	}
}

func TestPrepareVPNCoreRejectsInvalidSpecBeforeDownload(t *testing.T) {
	workDir := t.TempDir()
	corePath := filepath.Join(workDir, "core", "sing-box")
	cases := []struct {
		name    string
		spec    model.VPNCoreSpec
		wantErr string
	}{
		{
			name: "non HTTP download URL",
			spec: model.VPNCoreSpec{
				Name:        "sing-box",
				DownloadURL: "file:///tmp/sing-box",
			},
			wantErr: "core download url must use http or https",
		},
		{
			name: "short sha256",
			spec: model.VPNCoreSpec{
				Name:        "sing-box",
				DownloadURL: "https://download.example.com/sing-box",
				SHA256:      "sha256:abcdef",
			},
			wantErr: "core sha256 must be a 64-character hex digest without prefix",
		},
		{
			name: "prefixed sha256",
			spec: model.VPNCoreSpec{
				Name:        "sing-box",
				DownloadURL: "https://download.example.com/sing-box",
				SHA256:      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: "core sha256 must be a 64-character hex digest without prefix",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prepareVPNCore(context.Background(), tc.spec, corePath, nil)
			if err == nil {
				t.Fatal("invalid core spec must be rejected before download")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateVPNControlRequestRejectsInvalidCoreSpec(t *testing.T) {
	base := model.VPNControlRequest{
		SessionID:     "vpn-session-core-validation",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-core-validation",
		Token:         "session-token",
	}
	cases := []struct {
		name    string
		mutate  func(*model.VPNControlRequest)
		wantErr string
	}{
		{
			name: "non HTTP download URL",
			mutate: func(req *model.VPNControlRequest) {
				req.Core.DownloadURL = "file:///tmp/sing-box"
			},
			wantErr: "core download url must use http or https",
		},
		{
			name: "short sha256",
			mutate: func(req *model.VPNControlRequest) {
				req.Core.SHA256 = "sha256:abcdef"
			},
			wantErr: "core sha256 must be a 64-character hex digest without prefix",
		},
		{
			name: "prefixed sha256",
			mutate: func(req *model.VPNControlRequest) {
				req.Core.SHA256 = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			},
			wantErr: "core sha256 must be a 64-character hex digest without prefix",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			err := validateVPNControlRequest(req)
			if err == nil {
				t.Fatal("invalid core spec must be rejected")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateVPNControlRequestAllowsRecoveryActionsWithoutRelayTokenOrCore(t *testing.T) {
	for _, action := range []string{
		model.VPNActionStatus,
		model.VPNActionLogs,
		model.VPNActionStop,
		model.VPNActionCleanup,
	} {
		t.Run(action, func(t *testing.T) {
			err := validateVPNControlRequest(model.VPNControlRequest{
				SessionID: "vpn-session-recovery-action",
				Action:    action,
				Role:      model.VPNRoleEntry,
				Mode:      model.VPNModeSystemProxy,
				RelayMode: model.VPNRelayModeDashboard,
			})
			if err != nil {
				t.Fatalf("%s must not require relay stream, token, or core spec for dashboard recovery/cleanup: %v", action, err)
			}
		})
	}
}

func TestValidateVPNControlRequestRejectsRecoveryActionsWithoutRelayMode(t *testing.T) {
	for _, action := range []string{
		model.VPNActionStatus,
		model.VPNActionLogs,
		model.VPNActionStop,
		model.VPNActionCleanup,
	} {
		t.Run(action, func(t *testing.T) {
			err := validateVPNControlRequest(model.VPNControlRequest{
				SessionID: "vpn-session-recovery-action",
				Action:    action,
				Role:      model.VPNRoleEntry,
				Mode:      model.VPNModeSystemProxy,
			})
			if err == nil {
				t.Fatalf("%s without relay_mode must be rejected", action)
			}
			if !strings.Contains(err.Error(), "relay_mode is required") {
				t.Fatalf("error = %q, want relay_mode is required", err.Error())
			}
		})
	}
}

func TestValidateVPNControlRequestRejectsUnknownActionBeforeRuntimeValidation(t *testing.T) {
	err := validateVPNControlRequest(model.VPNControlRequest{
		SessionID: "vpn-session-unknown-action",
		Action:    "start-now",
		Role:      model.VPNRoleEntry,
		Mode:      model.VPNModeSystemProxy,
		RelayMode: model.VPNRelayModeDashboard,
	})
	if err == nil {
		t.Fatal("unknown VPN action must be rejected")
	}
	if !strings.Contains(err.Error(), `unsupported VPN action "start-now"`) {
		t.Fatalf("error = %q, want unsupported VPN action", err.Error())
	}
}

func TestValidateVPNControlRequestRejectsInvalidWintunSpec(t *testing.T) {
	base := model.VPNControlRequest{
		SessionID:     "vpn-session-wintun-validation",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-wintun-validation",
		Token:         "session-token",
		Extra:         map[string]string{},
	}
	cases := []struct {
		name    string
		mutate  func(*model.VPNControlRequest)
		wantErr string
	}{
		{
			name: "non HTTP Wintun download URL",
			mutate: func(req *model.VPNControlRequest) {
				req.Extra["wintun_url"] = "file:///tmp/wintun.dll"
			},
			wantErr: "wintun_url must use http or https",
		},
		{
			name: "short Wintun sha256",
			mutate: func(req *model.VPNControlRequest) {
				req.Extra["wintun_sha256"] = "sha256:abcdef"
			},
			wantErr: "wintun_sha256 must be a 64-character hex digest",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			req.Extra = map[string]string{}
			tc.mutate(&req)
			err := validateVPNControlRequest(req)
			if err == nil {
				t.Fatal("invalid Wintun spec must be rejected")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestInstallVPNWintunRejectsInvalidSpecBeforeInstall(t *testing.T) {
	originalConfig := agentConfig
	agentConfig = model.AgentConfig{}
	t.Cleanup(func() { agentConfig = originalConfig })

	base := model.VPNControlRequest{
		SessionID: "vpn-session-wintun-install-validation",
		Role:      model.VPNRoleEntry,
		Mode:      model.VPNModeTunSplit,
		Extra:     map[string]string{},
	}
	cases := []struct {
		name    string
		mutate  func(*model.VPNControlRequest)
		wantErr string
	}{
		{
			name: "non HTTP Wintun download URL",
			mutate: func(req *model.VPNControlRequest) {
				req.Extra["wintun_url"] = "file:///tmp/wintun.dll"
			},
			wantErr: "wintun_url must use http or https",
		},
		{
			name: "short Wintun sha256",
			mutate: func(req *model.VPNControlRequest) {
				req.Extra["wintun_url"] = "https://download.example.com/wintun.dll"
				req.Extra["wintun_sha256"] = "sha256:abcdef"
			},
			wantErr: "wintun_sha256 must be a 64-character hex digest",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			req.Extra = map[string]string{}
			tc.mutate(&req)
			_, err := installVPNWintun(context.Background(), req, t.TempDir(), nil)
			if err == nil {
				t.Fatal("invalid Wintun spec must be rejected before install")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestInstallVPNWintunDownloadsMissingDLLAndVerifiesSHA256(t *testing.T) {
	originalConfig := agentConfig
	agentConfig = model.AgentConfig{}
	t.Cleanup(func() { agentConfig = originalConfig })

	content := []byte("downloaded-wintun")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)

	workDir := t.TempDir()
	req := model.VPNControlRequest{
		SessionID: "vpn-session-wintun-download",
		Role:      model.VPNRoleEntry,
		Mode:      model.VPNModeTunSplit,
		Extra: map[string]string{
			"wintun_url":    server.URL + "/wintun.dll",
			"wintun_sha256": sha256HexForTest(content),
		},
	}

	path, err := installVPNWintun(context.Background(), req, workDir, server.Client())
	if err != nil {
		t.Fatalf("install Wintun from URL: %v", err)
	}
	wantPath := filepath.Join(workDir, "core", "wintun.dll")
	if path != wantPath {
		t.Fatalf("Wintun target path mismatch: want %q got %q", wantPath, path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read installed Wintun: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("installed Wintun content mismatch: %q", got)
	}
}

func TestInstallVPNWintunCopiesConfiguredDLLAndVerifiesSHA256(t *testing.T) {
	originalConfig := agentConfig
	agentConfig = model.AgentConfig{}
	t.Cleanup(func() { agentConfig = originalConfig })

	workDir := t.TempDir()
	sourcePath := filepath.Join(workDir, "source", "wintun.dll")
	content := []byte("local-wintun")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, content, 0600); err != nil {
		t.Fatal(err)
	}

	targetWorkDir := filepath.Join(workDir, "state")
	req := model.VPNControlRequest{
		SessionID: "vpn-session-wintun-copy",
		Role:      model.VPNRoleEntry,
		Mode:      model.VPNModeTunGlobal,
		Extra: map[string]string{
			"wintun_path":   sourcePath,
			"wintun_sha256": sha256HexForTest(content),
		},
	}

	path, err := installVPNWintun(context.Background(), req, targetWorkDir, nil)
	if err != nil {
		t.Fatalf("install Wintun from local path: %v", err)
	}
	wantPath := filepath.Join(targetWorkDir, "core", "wintun.dll")
	if path != wantPath {
		t.Fatalf("Wintun target path mismatch: want %q got %q", wantPath, path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read copied Wintun: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("copied Wintun content mismatch: %q", got)
	}
}

func TestAgentVPNStartInstallsWintunBeforeTunPreflight(t *testing.T) {
	resetVPNManagerForTest(t)
	if !isWindowsRuntime() {
		t.Skip("Wintun installation is only required on Windows")
	}
	if err := os.Remove(vpnWintunTargetPath(vpnManager.effectiveWorkDir())); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	tun := &recordingVPNTunManager{}
	vpnManager.tunManager = tun

	content := []byte("configured-wintun")
	sourcePath := filepath.Join(t.TempDir(), "wintun.dll")
	if err := os.WriteFile(sourcePath, content, 0600); err != nil {
		t.Fatal(err)
	}
	req := model.VPNControlRequest{
		SessionID:     "vpn-session-wintun-start",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-wintun",
		Token:         "session-token",
		TunName:       "nezha-vpn",
		Extra: map[string]string{
			"wintun_path":   sourcePath,
			"wintun_sha256": sha256HexForTest(content),
		},
	}
	targetPath := filepath.Join(vpnManager.effectiveWorkDir(), "core", "wintun.dll")
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		if tun.preflightCalls != 1 {
			t.Fatalf("TUN preflight must run before relay attach, got %d calls", tun.preflightCalls)
		}
		got, readErr := os.ReadFile(targetPath)
		if readErr != nil {
			t.Fatalf("Wintun must be installed before relay attach: %v", readErr)
		}
		if string(got) != string(content) {
			t.Fatalf("installed Wintun content mismatch before relay attach: %q", got)
		}
		return nil, errors.New("intentional relay attach stop")
	}

	_, err := vpnManager.Start(req)
	if err == nil {
		t.Fatal("relay attach failure should still fail start after Wintun install and preflight")
	}
	if !strings.Contains(err.Error(), "intentional relay attach stop") {
		t.Fatalf("start should reach relay attach after Wintun install and preflight, got %v", err)
	}
	if tun.preflightCalls != 1 {
		t.Fatalf("TUN preflight must run after Wintun install, got %d calls", tun.preflightCalls)
	}
	got, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatalf("Wintun must be installed before relay attach: %v", readErr)
	}
	if string(got) != string(content) {
		t.Fatalf("installed Wintun content mismatch: %q", got)
	}
}

func TestAgentVPNStartRejectsDisabledVPNBeforeRelayAttach(t *testing.T) {
	resetVPNManagerForTest(t)
	originalConfig := agentConfig
	agentConfig = model.AgentConfig{DisableVPN: true}
	t.Cleanup(func() { agentConfig = originalConfig })

	stream := &recordingVPNIOStream{}
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		t.Fatal("disabled VPN must be rejected before attaching relay")
		return stream, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-1",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
	}
	_, err := vpnManager.Start(req)
	if err == nil {
		t.Fatal("DisableVPN must reject VPN start")
	}
	if !strings.Contains(err.Error(), "DisableVPN") {
		t.Fatalf("error must mention DisableVPN, got %v", err)
	}
}

func TestAgentVPNStartRejectsDisabledSystemProxyModeBeforeRelayAttach(t *testing.T) {
	resetVPNManagerForTest(t)
	originalConfig := agentConfig
	agentConfig = model.AgentConfig{VPNAllowTun: true}
	t.Cleanup(func() { agentConfig = originalConfig })

	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		t.Fatal("disabled system proxy mode must be rejected before attaching relay")
		return nil, errors.New("unexpected relay attach")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-1",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
	}
	_, err := vpnManager.Start(req)
	if err == nil {
		t.Fatal("disabled system proxy mode must reject VPN start")
	}
	if !strings.Contains(err.Error(), "system_proxy") {
		t.Fatalf("error must mention system_proxy, got %v", err)
	}
}

func TestAgentVPNStartRejectsDisabledTunModeBeforeRelayAttach(t *testing.T) {
	resetVPNManagerForTest(t)
	originalConfig := agentConfig
	agentConfig = model.AgentConfig{VPNAllowSystemProxy: true}
	t.Cleanup(func() { agentConfig = originalConfig })

	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		t.Fatal("disabled TUN mode must be rejected before attaching relay")
		return nil, errors.New("unexpected relay attach")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-1",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	_, err := vpnManager.Start(req)
	if err == nil {
		t.Fatal("disabled TUN mode must reject VPN start")
	}
	if !strings.Contains(err.Error(), "tun") {
		t.Fatalf("error must mention tun, got %v", err)
	}
}

func TestAgentVPNStartRejectsUnknownModeBeforeRelayAttach(t *testing.T) {
	resetVPNManagerForTest(t)
	originalConfig := agentConfig
	agentConfig = model.AgentConfig{
		VPNAllowSystemProxy: true,
		VPNAllowTun:         true,
	}
	t.Cleanup(func() { agentConfig = originalConfig })

	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		t.Fatal("unknown VPN mode must be rejected before attaching relay")
		return nil, errors.New("unexpected relay attach")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-unknown-mode",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          "wireguard",
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-unknown-mode",
		Token:         "session-token",
	}
	_, err := vpnManager.Start(req)
	if err == nil {
		t.Fatal("unknown VPN mode must reject VPN start")
	}
	if !strings.Contains(err.Error(), `unsupported VPN mode "wireguard"`) {
		t.Fatalf("error = %q, want unsupported VPN mode", err.Error())
	}
}

func TestAgentVPNStartRejectsTunPreflightFailureBeforeRelayAttach(t *testing.T) {
	resetVPNManagerForTest(t)
	vpnManager.tunManager = &recordingVPNTunManager{
		preflightErr: errors.New("TUN preflight failed"),
	}
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		t.Fatal("TUN preflight failure must be rejected before attaching relay")
		return nil, errors.New("unexpected relay attach")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-1",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	_, err := vpnManager.Start(req)
	if err == nil {
		t.Fatal("TUN preflight failure must reject VPN start")
	}
	if !strings.Contains(err.Error(), "TUN preflight failed") {
		t.Fatalf("error must include preflight failure, got %v", err)
	}
}

func TestAgentVPNStartRunsTunPreflightOnlyForEntryTunMode(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{}
	vpnManager.tunManager = tun

	entry := model.VPNControlRequest{
		SessionID:     "vpn-session-entry-tun",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunGlobal,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	entry = withTestVPNBridgeAddress(t, entry)
	if _, err := vpnManager.Start(entry); err != nil {
		t.Fatalf("entry TUN start should pass with successful preflight: %v", err)
	}
	if tun.preflightCalls != 1 || tun.lastRequest.SessionID != entry.SessionID {
		t.Fatalf("entry TUN start must run preflight once, got %#v", tun)
	}

	exit := model.VPNControlRequest{
		SessionID:     "vpn-session-exit-tun",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleExit,
		Mode:          model.VPNModeTunGlobal,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-exit-stream-tun",
		Token:         "session-token",
	}
	exit = withTestVPNBridgeAddress(t, exit)
	if _, err := vpnManager.Start(exit); err != nil {
		t.Fatalf("exit start should not run entry TUN preflight: %v", err)
	}
	if tun.preflightCalls != 1 {
		t.Fatalf("exit role must not run entry TUN preflight, got %d calls", tun.preflightCalls)
	}
}

func TestAgentVPNStartRejectsCoreHashMismatchBeforeRelayAttach(t *testing.T) {
	resetVPNManagerForTest(t)
	workDir := t.TempDir()
	corePath := filepath.Join(workDir, "core", "sing-box")
	if err := os.MkdirAll(filepath.Dir(corePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corePath, []byte("tampered-core"), 0600); err != nil {
		t.Fatal(err)
	}
	vpnManager.corePath = corePath

	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		t.Fatal("invalid core must be rejected before attaching relay")
		return nil, errors.New("unexpected relay attach")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-1",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Core: model.VPNCoreSpec{
			Name:   "sing-box",
			SHA256: sha256HexForTest([]byte("expected-core")),
		},
	}
	_, err := vpnManager.Start(req)
	if err == nil {
		t.Fatal("core hash mismatch must reject VPN start")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("error must mention sha256 mismatch, got %v", err)
	}
}

func sha256HexForTest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
