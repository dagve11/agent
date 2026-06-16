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
	"runtime"
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

func TestAgentVPNDownloadsCoreToTemporarySessionDirAndRemovesOnCleanup(t *testing.T) {
	originalConfig := agentConfig
	t.Cleanup(func() { agentConfig = originalConfig })
	agentConfig = model.AgentConfig{VPNAllowSystemProxy: true, VPNAllowTun: true}

	content := []byte("downloaded-temp-core")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)

	manager := NewAgentVPNManager()
	manager.workDir = t.TempDir()
	manager.corePath = ""
	manager.httpClient = server.Client()
	manager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		return &recordingVPNIOStream{}, nil
	}
	process := newBlockingRecordingVPNSidecarProcess()
	var started vpnSidecarStartSpec
	manager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		started = spec
		return process, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-temp-core-download",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleExit,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-exit-stream-temp-core-download",
		Token:         "session-token",
		Core: model.VPNCoreSpec{
			Name:        "sing-box",
			SHA256:      sha256HexForTest(content),
			DownloadURL: server.URL + "/sing-box",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	coreDir := defaultVPNSessionCoreCleanupDir(defaultVPNPolicyCoreID)
	t.Cleanup(func() { _ = os.RemoveAll(coreDir) })
	_ = os.RemoveAll(coreDir)

	payload, err := manager.Start(req)
	if err != nil {
		t.Fatalf("start VPN with downloaded temp core: %v", err)
	}
	if payload.State != model.VPNStateRunning {
		t.Fatalf("unexpected start payload: %#v", payload)
	}
	session, ok := manager.Get(req.SessionID)
	if !ok {
		t.Fatal("running session must be tracked")
	}
	if !session.coreTemporary || session.CoreCleanupDir == "" {
		t.Fatalf("default core must be marked temporary: %#v", session)
	}
	if started.CorePath != session.CorePath {
		t.Fatalf("sidecar core path must match session core path: started=%q session=%q", started.CorePath, session.CorePath)
	}
	if _, err := os.Stat(started.CorePath); err != nil {
		t.Fatalf("downloaded temporary core must exist before stop: %v", err)
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	if _, err := manager.Stop(stopReq); err != nil {
		t.Fatalf("stop VPN: %v", err)
	}
	if _, err := os.Stat(session.CoreCleanupDir); err != nil {
		t.Fatalf("temporary core directory must remain after stop: %v", err)
	}

	cleanupReq := req
	cleanupReq.Action = model.VPNActionCleanup
	if _, err := manager.Cleanup(cleanupReq); err != nil {
		t.Fatalf("cleanup VPN core: %v", err)
	}
	if _, err := os.Stat(session.CoreCleanupDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary core directory must be removed on cleanup, stat err=%v", err)
	}
}

func TestAgentVPNExitSharesOneCoreRuntimeAcrossSessions(t *testing.T) {
	originalConfig := agentConfig
	t.Cleanup(func() { agentConfig = originalConfig })
	agentConfig = model.AgentConfig{VPNAllowSystemProxy: true, VPNAllowTun: true}

	manager := NewAgentVPNManager()
	manager.workDir = t.TempDir()
	manager.corePath = filepath.Join(t.TempDir(), "core", "sing-box")
	if err := os.MkdirAll(filepath.Dir(manager.corePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.corePath, []byte("shared-core"), 0600); err != nil {
		t.Fatal(err)
	}
	manager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		return &recordingVPNIOStream{}, nil
	}
	processes := []*recordingVPNSidecarProcess{}
	manager.sidecarRunner = func(context.Context, vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		process := newBlockingRecordingVPNSidecarProcess()
		processes = append(processes, process)
		return process, nil
	}

	first := model.VPNControlRequest{
		SessionID:     "vpn-session-shared-exit-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleExit,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-exit-stream-shared-1",
		Token:         "session-token",
	}
	first = withTestVPNBridgeAddress(t, first)
	second := first
	second.SessionID = "vpn-session-shared-exit-2"
	second.RelayStreamID = "vpn-exit-stream-shared-2"
	second.Extra = map[string]string{
		"bridge_listen": freeLocalTCPAddrForTest(t),
	}
	firstBridgeListen := first.Extra["bridge_listen"]

	if _, err := manager.Start(first); err != nil {
		t.Fatalf("start first shared exit session: %v", err)
	}
	if _, err := manager.Start(second); err != nil {
		t.Fatalf("start second shared exit session: %v", err)
	}
	if len(processes) != 1 {
		t.Fatalf("exit sessions must share one sidecar, started=%d", len(processes))
	}
	secondSession, ok := manager.Get(second.SessionID)
	if !ok {
		t.Fatal("second shared exit session must be tracked")
	}
	if secondSession.Request.Extra["bridge_listen"] != firstBridgeListen {
		t.Fatalf("second shared exit session must reuse first bridge listen address: got=%q want=%q", secondSession.Request.Extra["bridge_listen"], firstBridgeListen)
	}

	stopFirst := first
	stopFirst.Action = model.VPNActionStop
	if _, err := manager.Stop(stopFirst); err != nil {
		t.Fatalf("stop first shared exit session: %v", err)
	}
	if processes[0].stopCalls != 0 {
		t.Fatalf("shared exit sidecar must keep running while referenced, stopCalls=%d", processes[0].stopCalls)
	}

	stopSecond := second
	stopSecond.Action = model.VPNActionStop
	if _, err := manager.Stop(stopSecond); err != nil {
		t.Fatalf("stop second shared exit session: %v", err)
	}
	if processes[0].stopCalls != 1 {
		t.Fatalf("shared exit sidecar must stop after last reference, stopCalls=%d", processes[0].stopCalls)
	}
}

func TestAgentVPNPrepareDownloadsCoreWithoutStartingSidecar(t *testing.T) {
	originalConfig := agentConfig
	t.Cleanup(func() { agentConfig = originalConfig })
	agentConfig = model.AgentConfig{VPNAllowSystemProxy: true, VPNAllowTun: true}

	content := []byte("prepared-temp-core")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)

	manager := NewAgentVPNManager()
	manager.corePath = ""
	manager.httpClient = server.Client()
	sidecarStarted := false
	manager.sidecarRunner = func(context.Context, vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		sidecarStarted = true
		return newBlockingRecordingVPNSidecarProcess(), nil
	}

	req := model.VPNControlRequest{
		SessionID: "vpn-session-prepare-core",
		Action:    model.VPNActionPrepare,
		Role:      model.VPNRoleExit,
		Mode:      model.VPNModeSystemProxy,
		RelayMode: model.VPNRelayModeDashboard,
		Core: model.VPNCoreSpec{
			Name:        "sing-box",
			SHA256:      sha256HexForTest(content),
			DownloadURL: server.URL + "/sing-box",
		},
	}
	coreDir := defaultVPNSessionCoreCleanupDir(defaultVPNPolicyCoreID)
	t.Cleanup(func() { _ = os.RemoveAll(coreDir) })
	_ = os.RemoveAll(coreDir)

	payload, err := manager.Prepare(req)
	if err != nil {
		t.Fatalf("prepare VPN core: %v", err)
	}
	if payload.State != model.VPNStatePrepared {
		t.Fatalf("prepare must report prepared state, got %#v", payload)
	}
	if sidecarStarted {
		t.Fatal("prepare must not start the VPN sidecar")
	}
	if _, ok := manager.Get(req.SessionID); ok {
		t.Fatal("prepare must not create a running local session")
	}
	corePath := filepath.Join(coreDir, "core", vpnCoreFileName(req.Core))
	if _, err := os.Stat(corePath); err != nil {
		t.Fatalf("prepared temporary core must exist: %v", err)
	}
	if !strings.Contains(strings.Join(payload.Logs, "\n"), "[core] prepare=downloaded") {
		t.Fatalf("prepare logs must report core download status, got %#v", payload.Logs)
	}
}

func TestAgentVPNCleanupRemovesPreparedTemporaryCore(t *testing.T) {
	originalConfig := agentConfig
	t.Cleanup(func() { agentConfig = originalConfig })
	agentConfig = model.AgentConfig{VPNAllowSystemProxy: true, VPNAllowTun: true}

	content := []byte("prepared-core-for-stop")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)

	manager := NewAgentVPNManager()
	manager.corePath = ""
	manager.httpClient = server.Client()
	req := model.VPNControlRequest{
		SessionID: "vpn-session-prepared-stop",
		Action:    model.VPNActionPrepare,
		Role:      model.VPNRoleExit,
		Mode:      model.VPNModeSystemProxy,
		RelayMode: model.VPNRelayModeDashboard,
		Core: model.VPNCoreSpec{
			Name:        "sing-box",
			SHA256:      sha256HexForTest(content),
			DownloadURL: server.URL + "/sing-box",
		},
	}
	coreDir := defaultVPNSessionCoreCleanupDir(defaultVPNPolicyCoreID)
	t.Cleanup(func() { _ = os.RemoveAll(coreDir) })
	_ = os.RemoveAll(coreDir)

	if _, err := manager.Prepare(req); err != nil {
		t.Fatalf("prepare VPN core: %v", err)
	}
	if _, err := os.Stat(filepath.Join(coreDir, "core", vpnCoreFileName(req.Core))); err != nil {
		t.Fatalf("prepared temporary core must exist before stop: %v", err)
	}

	cleanupReq := req
	cleanupReq.Action = model.VPNActionCleanup
	payload, err := manager.Cleanup(cleanupReq)
	if err != nil {
		t.Fatalf("cleanup prepared VPN core: %v", err)
	}
	if payload.State != model.VPNStateStopped {
		t.Fatalf("cleanup must report stopped state, got %#v", payload)
	}
	if _, err := os.Stat(coreDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepared temporary core directory must be removed on cleanup, stat err=%v", err)
	}
	if !strings.Contains(strings.Join(payload.Logs, "\n"), "[cleanup] core_remove=ok") {
		t.Fatalf("cleanup logs must report core cleanup, got %#v", payload.Logs)
	}
}

func TestAgentVPNKeepsExplicitCorePathOnStop(t *testing.T) {
	originalConfig := agentConfig
	t.Cleanup(func() { agentConfig = originalConfig })
	agentConfig = model.AgentConfig{VPNAllowSystemProxy: true, VPNAllowTun: true}

	manager := NewAgentVPNManager()
	manager.workDir = t.TempDir()
	manager.corePath = filepath.Join(t.TempDir(), "core", "sing-box")
	if err := os.MkdirAll(filepath.Dir(manager.corePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.corePath, []byte("persistent-core"), 0600); err != nil {
		t.Fatal(err)
	}
	manager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		return &recordingVPNIOStream{}, nil
	}
	process := newBlockingRecordingVPNSidecarProcess()
	manager.sidecarRunner = func(context.Context, vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-persistent-core",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleExit,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-exit-stream-persistent-core",
		Token:         "session-token",
	}
	req = withTestVPNBridgeAddress(t, req)

	if _, err := manager.Start(req); err != nil {
		t.Fatalf("start VPN with explicit core: %v", err)
	}
	session, ok := manager.Get(req.SessionID)
	if !ok {
		t.Fatal("running session must be tracked")
	}
	if session.coreTemporary {
		t.Fatalf("explicit core path must not be marked temporary: %#v", session)
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	if _, err := manager.Stop(stopReq); err != nil {
		t.Fatalf("stop VPN: %v", err)
	}
	if _, err := os.Stat(manager.corePath); err != nil {
		t.Fatalf("explicit core path must remain after stop: %v", err)
	}
}

func TestPrepareVPNCoreDownloadsPlatformCoreFromBaseURLManifestAndRedirect(t *testing.T) {
	content := []byte("downloaded-platform-core")
	assetName := vpnCoreAssetName(runtime.GOOS, runtime.GOARCH)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			_, _ = w.Write([]byte(`{"assets":[{"asset":"` + assetName + `","sha256":"` + sha256HexForTest(content) + `"}]}`))
		case "/" + assetName:
			http.Redirect(w, r, "/download/"+assetName, http.StatusFound)
		case "/download/" + assetName:
			_, _ = w.Write(content)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	workDir := t.TempDir()
	corePath := filepath.Join(workDir, "core", "sing-box")
	resolved, err := prepareVPNCore(context.Background(), model.VPNCoreSpec{
		Name:            "sing-box",
		DownloadBaseURL: server.URL,
	}, corePath, client)
	if err != nil {
		t.Fatalf("prepare downloaded platform core: %v", err)
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

func TestVPNCoreDownloadCandidatesPreferCNSource(t *testing.T) {
	t.Setenv("NZ_VPN_CORE_CN", "1")

	assetName := vpnCoreAssetName(runtime.GOOS, runtime.GOARCH)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			_, _ = w.Write([]byte(`{"assets":[{"asset":"` + assetName + `","sha256":"` + strings.Repeat("a", 64) + `","url":"` + server.URL + `/global","cn_url":"` + server.URL + `/cn"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	candidates, err := vpnCoreDownloadCandidates(context.Background(), model.VPNCoreSpec{
		Name:              "sing-box",
		DownloadBaseURL:   server.URL + "/global-base",
		CNDownloadBaseURL: server.URL + "/cn-base",
		ManifestURL:       server.URL + "/manifest.json",
		CNManifestURL:     server.URL + "/manifest.json",
	}, server.Client())
	if err != nil {
		t.Fatalf("build core download candidates: %v", err)
	}

	want := []string{
		server.URL + "/cn",
		server.URL + "/global",
		server.URL + "/cn-base/" + assetName,
		server.URL + "/global-base/" + assetName,
	}
	if len(candidates) != len(want) {
		t.Fatalf("candidate count = %d, want %d: %#v", len(candidates), len(want), candidates)
	}
	for i, candidate := range candidates {
		if candidate.URL != want[i] {
			t.Fatalf("candidate %d URL = %q, want %q", i, candidate.URL, want[i])
		}
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
		{
			name: "non HTTP base URL",
			spec: model.VPNCoreSpec{
				Name:            "sing-box",
				DownloadBaseURL: "file:///tmp/sing-box",
			},
			wantErr: "core download base url must use http or https",
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
