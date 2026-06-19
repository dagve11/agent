package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/monitor"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

func TestAgentVPNStartWritesConfigAndStartsSidecar(t *testing.T) {
	resetVPNManagerForTest(t)
	workDir := t.TempDir()
	corePath := filepath.Join(workDir, "core", "sing-box")
	vpnManager.workDir = workDir
	vpnManager.corePath = corePath
	if err := os.MkdirAll(filepath.Dir(corePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corePath, []byte("test-core"), 0600); err != nil {
		t.Fatal(err)
	}

	var started vpnSidecarStartSpec
	process := &recordingVPNSidecarProcess{}
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		started = spec
		return process, nil
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
	req = withTestVPNBridgeAddress(t, req)

	payload, err := vpnManager.Start(req)
	if err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	if payload.State != model.VPNStateRunning {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	if started.CorePath != corePath {
		t.Fatalf("sidecar runner must receive core path %q, got %q", corePath, started.CorePath)
	}
	if started.SessionID != req.SessionID || started.Role != req.Role {
		t.Fatalf("sidecar runner session mismatch: %#v", started)
	}
	if started.ConfigPath == "" || started.LogPath == "" || started.WorkDir == "" {
		t.Fatalf("sidecar runner must receive config/log/work paths: %#v", started)
	}
	if _, err := os.Stat(started.ConfigPath); err != nil {
		t.Fatalf("config file must be written before sidecar start: %v", err)
	}
	raw, err := os.ReadFile(started.ConfigPath)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	cfg := decodeSingBoxConfigForTest(t, raw)
	if len(cfg.array("inbounds")) == 0 {
		t.Fatalf("written config must contain sing-box inbounds: %s", string(raw))
	}

	session, ok := vpnManager.Get(req.SessionID)
	if !ok {
		t.Fatal("running session must be tracked")
	}
	if session.ConfigPath != started.ConfigPath || session.LogPath != started.LogPath || session.sidecar == nil {
		t.Fatalf("tracked session must include sidecar metadata: %#v", session)
	}
}

func TestAgentVPNStatusReturnsRunningSidecarLogTail(t *testing.T) {
	resetVPNManagerForTest(t)
	workDir := t.TempDir()
	vpnManager.workDir = workDir
	process := newBlockingRecordingVPNSidecarProcess()
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		if err := os.WriteFile(spec.LogPath, []byte("sidecar ready\nproxy accepted connection\n"), 0600); err != nil {
			return nil, err
		}
		return process, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-status-log-tail",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-status-log-tail",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	statusReq := req
	statusReq.Action = model.VPNActionStatus
	status, err := vpnManager.Status(statusReq)
	if err != nil {
		t.Fatalf("status VPN: %v", err)
	}
	logs := strings.Join(status.Logs, "\n")
	if !strings.Contains(logs, "sidecar ready") || !strings.Contains(logs, "proxy accepted connection") {
		t.Fatalf("running status must include sidecar log tail, got %#v", status.Logs)
	}
}

func TestAgentVPNStopStopsSidecarAndRelay(t *testing.T) {
	resetVPNManagerForTest(t)
	process := &recordingVPNSidecarProcess{}
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	stream := &recordingVPNIOStream{recvFrames: make(chan []byte, 4)}
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
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
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start before stop: %v", err)
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	if _, err := vpnManager.Stop(stopReq); err != nil {
		t.Fatalf("stop VPN: %v", err)
	}
	if process.stopCalls != 1 {
		t.Fatalf("stop must stop sidecar exactly once, got %d", process.stopCalls)
	}
	stream.mu.Lock()
	closed := stream.closed
	stream.mu.Unlock()
	if !closed {
		t.Fatal("stop must close Dashboard relay stream")
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("stopped session must be removed from tracking")
	}
}

func TestAgentVPNStopAllRestoresActiveSessionsOnWorkerExit(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{}
	tun := &recordingVPNTunManager{}
	vpnManager.systemProxyManager = proxy
	vpnManager.tunManager = tun
	processes := make(map[string]*recordingVPNSidecarProcess)
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		process := &recordingVPNSidecarProcess{}
		processes[spec.SessionID] = process
		return process, nil
	}

	proxyReq := model.VPNControlRequest{
		SessionID:     "vpn-session-proxy",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-proxy",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	proxyReq = withTestVPNBridgeAddress(t, proxyReq)
	if _, err := vpnManager.Start(proxyReq); err != nil {
		t.Fatalf("start proxy VPN: %v", err)
	}
	tunReq := model.VPNControlRequest{
		SessionID:     "vpn-session-tun",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	tunReq = withTestVPNBridgeAddress(t, tunReq)
	if _, err := vpnManager.Start(tunReq); err != nil {
		t.Fatalf("start TUN VPN: %v", err)
	}

	vpnManager.StopAll("worker exit")

	if proxy.restoreCalls != 1 {
		t.Fatalf("StopAll must restore active system proxy sessions, got %d", proxy.restoreCalls)
	}
	if tun.restoreCalls != 1 {
		t.Fatalf("StopAll must restore active TUN sessions, got %d", tun.restoreCalls)
	}
	if processes[proxyReq.SessionID].stopCalls != 1 || processes[tunReq.SessionID].stopCalls != 1 {
		t.Fatalf("StopAll must stop every sidecar once, got %#v", processes)
	}
	if _, ok := vpnManager.Get(proxyReq.SessionID); ok {
		t.Fatal("StopAll must remove proxy session from tracking")
	}
	if _, ok := vpnManager.Get(tunReq.SessionID); ok {
		t.Fatal("StopAll must remove TUN session from tracking")
	}
}

func TestAgentVPNSystemProxyApplyAndRestoreOnStop(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{}
	vpnManager.systemProxyManager = proxy

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-1",
		Token:         "session-token",
		ListenHTTP:    "127.0.0.1:8088",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	if proxy.applyCalls != 1 || proxy.lastHTTP != req.ListenHTTP || proxy.lastSOCKS != req.ListenSOCKS {
		t.Fatalf("system proxy must be applied once with local proxy addresses, got %#v", proxy)
	}
	if proxy.inspectCalls != 1 || proxy.clearCalls != 1 {
		t.Fatalf("start must inspect and clear foreign system proxy before apply, got %#v", proxy)
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	if _, err := vpnManager.Stop(stopReq); err != nil {
		t.Fatalf("stop VPN: %v", err)
	}
	if proxy.restoreCalls != 1 {
		t.Fatalf("system proxy must be restored once on stop, got %d", proxy.restoreCalls)
	}
}

func TestAgentVPNSystemProxyStartSkipsClearWhenAlreadyApplied(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{inspection: vpnSystemProxyInspection{Applied: true, Status: "applied"}}
	vpnManager.systemProxyManager = proxy

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-proxy-owned",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-proxy-owned",
		Token:         "session-token",
		ListenHTTP:    "127.0.0.1:8088",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	if proxy.inspectCalls != 1 {
		t.Fatalf("start must inspect system proxy ownership once, got %d", proxy.inspectCalls)
	}
	if proxy.clearCalls != 0 {
		t.Fatalf("start must not clear system proxy already owned by this project, got %d", proxy.clearCalls)
	}
	if proxy.applyCalls != 1 {
		t.Fatalf("start must still apply system proxy once, got %d", proxy.applyCalls)
	}
	if got, want := strings.Join(proxy.operations, ","), "inspect,apply"; got != want {
		t.Fatalf("system proxy operations mismatch: want %s got %s", want, got)
	}
}

func TestAgentVPNSystemProxyRestoredWhenSidecarCrashes(t *testing.T) {
	resetVPNManagerForTest(t)
	process := newBlockingRecordingVPNSidecarProcess()
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	proxy := &recordingVPNSystemProxyManager{}
	vpnManager.systemProxyManager = proxy

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-1",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	process.exit(errors.New("sidecar crashed"))
	waitForVPNSessionState(t, req.SessionID, model.VPNStateFailed)
	if proxy.restoreCalls != 1 {
		t.Fatalf("system proxy must be restored when sidecar crashes, got %d", proxy.restoreCalls)
	}
}

func TestAgentVPNStopAfterSidecarCrashDoesNotRestoreSystemProxyTwice(t *testing.T) {
	resetVPNManagerForTest(t)
	process := newBlockingRecordingVPNSidecarProcess()
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	proxy := &recordingVPNSystemProxyManager{}
	vpnManager.systemProxyManager = proxy

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-crash-stop-proxy",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-crash-stop-proxy",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	process.exit(errors.New("sidecar crashed"))
	waitForVPNSessionState(t, req.SessionID, model.VPNStateFailed)
	if proxy.restoreCalls != 1 {
		t.Fatalf("sidecar crash must restore system proxy once, got %d", proxy.restoreCalls)
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	if _, err := vpnManager.Stop(stopReq); err != nil {
		t.Fatalf("stop failed session: %v", err)
	}
	if proxy.restoreCalls != 1 {
		t.Fatalf("stop after sidecar crash must not restore system proxy twice, got %d", proxy.restoreCalls)
	}
}

func TestAgentVPNTunSnapshotAndRestoreOnStop(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{}
	vpnManager.tunManager = tun

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-tun-stop",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun-stop",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	if tun.snapshotCalls != 1 || tun.lastSnapshot.SessionID != req.SessionID {
		t.Fatalf("TUN start must snapshot system network state once, got %#v", tun)
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	if _, err := vpnManager.Stop(stopReq); err != nil {
		t.Fatalf("stop VPN: %v", err)
	}
	if tun.restoreCalls != 1 || tun.lastRestore.SessionID != req.SessionID {
		t.Fatalf("TUN stop must restore system network state once, got %#v", tun)
	}
}

func TestAgentVPNTunRestoreFailureKeepsStateForRetry(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{restoreErr: errors.New("restore failed")}
	vpnManager.tunManager = tun

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-tun-restore-fail",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun-restore-fail",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	session, ok := vpnManager.Get(req.SessionID)
	if !ok {
		t.Fatal("running session must be tracked")
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	if _, err := vpnManager.Stop(stopReq); err != nil {
		t.Fatalf("stop VPN should still return stopped result when restore fails: %v", err)
	}
	if _, err := os.Stat(session.StatePath); err != nil {
		t.Fatalf("state must be kept when TUN restore fails so startup cleanup can retry: %v", err)
	}
}

func TestAgentVPNStopResultReportsTunCleanupStatus(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{restoreErr: errors.New("tun restore failed")}
	vpnManager.tunManager = tun

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-stop-cleanup-status",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-stop-cleanup-status",
		Token:         "session-token",
		TunName:       "nezha-vpn",
		ListenSOCKS:   "127.0.0.1:1080",
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	result, err := vpnManager.Stop(stopReq)
	if err != nil {
		t.Fatalf("stop VPN should still return stopped result when cleanup has recoverable errors: %v", err)
	}
	if result.State != model.VPNStateStopped {
		t.Fatalf("unexpected stop result: %#v", result)
	}
	logs := strings.Join(result.Logs, "\n")
	if !strings.Contains(logs, "tun_restore=failed: tun restore failed") {
		t.Fatalf("stop result must report TUN restore failure, logs=%#v", result.Logs)
	}
	if !strings.Contains(logs, "state=kept-for-restore-retry") {
		t.Fatalf("stop result must report retained state for retry, logs=%#v", result.Logs)
	}
}

func TestAgentVPNStopResultReportsSystemProxyCleanupStatus(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{restoreErr: errors.New("proxy restore failed")}
	vpnManager.systemProxyManager = proxy

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-stop-proxy-cleanup-status",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-stop-proxy-cleanup-status",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	result, err := vpnManager.Stop(stopReq)
	if err != nil {
		t.Fatalf("stop VPN should still return stopped result when system proxy restore fails: %v", err)
	}
	logs := strings.Join(result.Logs, "\n")
	if !strings.Contains(logs, "system_proxy_restore=failed: proxy restore failed") {
		t.Fatalf("stop result must report system proxy restore failure, logs=%#v", result.Logs)
	}
}

func TestAgentVPNSystemProxyRestoreFailureKeepsStateForRetry(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{restoreErr: errors.New("proxy restore failed")}
	vpnManager.systemProxyManager = proxy

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-proxy-restore-fail",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-proxy-restore-fail",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	session, ok := vpnManager.Get(req.SessionID)
	if !ok {
		t.Fatal("running session must be tracked")
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	result, err := vpnManager.Stop(stopReq)
	if err != nil {
		t.Fatalf("stop VPN should return stopped result when proxy restore fails: %v", err)
	}
	if result.State != model.VPNStateStopped {
		t.Fatalf("unexpected stop result: %#v", result)
	}
	raw, err := os.ReadFile(session.StatePath)
	if err != nil {
		t.Fatalf("state must be kept when system proxy restore fails: %v", err)
	}
	var persisted agentVPNSessionState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode retained state: %v", err)
	}
	if !persisted.SystemProxyApplied {
		t.Fatal("retained state must keep system_proxy_applied=true for retry")
	}
}

func TestAgentVPNTunHealthFailureRestoresTunAndStopsSidecar(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{}
	vpnManager.tunManager = tun
	process := &recordingVPNSidecarProcess{}
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	stream := &recordingVPNIOStream{recvFrames: make(chan []byte, 4)}
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		return stream, nil
	}
	vpnManager.tunHealthProbe = func(context.Context, model.VPNControlRequest) error {
		return errors.New("public probe failed")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-tun-health",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun-health",
		Token:         "session-token",
		TunName:       "nezha-vpn",
		Rules: model.VPNRules{
			Mode:    "domain",
			Domains: []string{"example.com"},
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	result, err := vpnManager.Start(req)
	if err == nil {
		t.Fatal("TUN health failure must reject VPN start")
	}
	if !strings.Contains(err.Error(), "public probe failed") {
		t.Fatalf("start error must include health probe failure, got %v", err)
	}
	if result.State != model.VPNStateFailed {
		t.Fatalf("failed start result mismatch: %#v", result)
	}
	if result.LastError == "" || !strings.Contains(result.LastError, "public probe failed") {
		t.Fatalf("failed start result must include health failure reason, got %#v", result)
	}
	if joined := strings.Join(result.Logs, "\n"); !strings.Contains(joined, "TUN health probe failed") || !strings.Contains(joined, "tun_restore=ok") || !strings.Contains(joined, "rollback=sidecar-stopped,relay-closed") {
		t.Fatalf("failed TUN health result must include rollback log, got %#v", result.Logs)
	}
	if process.stopCalls != 1 {
		t.Fatalf("TUN health failure must stop sidecar, got %d", process.stopCalls)
	}
	if tun.restoreCalls != 1 {
		t.Fatalf("TUN health failure must restore snapshot, got %d", tun.restoreCalls)
	}
	stream.mu.Lock()
	closed := stream.closed
	stream.mu.Unlock()
	if !closed {
		t.Fatal("TUN health failure must close Dashboard relay stream")
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed TUN health session must not be tracked as running")
	}
}

func TestAgentVPNTunHealthFailureKeepsRecoveryStateWhenTunRestoreFails(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{restoreErr: errors.New("tun restore failed")}
	vpnManager.tunManager = tun
	process := &recordingVPNSidecarProcess{}
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	vpnManager.tunHealthProbe = func(context.Context, model.VPNControlRequest) error {
		return errors.New("public probe failed")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-tun-health-restore-fail",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun-health-restore-fail",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	req = withTestVPNBridgeAddress(t, req)
	result, err := vpnManager.Start(req)
	if err == nil {
		t.Fatalf("TUN health failure must reject VPN start, result=%#v", result)
	}
	logs := strings.Join(result.Logs, "\n")
	if !strings.Contains(logs, "tun_restore=failed: tun restore failed") {
		t.Fatalf("failed TUN health result must report TUN restore failure, logs=%#v", result.Logs)
	}
	if !strings.Contains(logs, "state=kept-for-restore-retry") {
		t.Fatalf("failed TUN health result must report retained recovery state, logs=%#v", result.Logs)
	}
	if strings.Contains(logs, "rollback=tun-restored") {
		t.Fatalf("failed TUN health result must not report successful TUN restore when restore failed, logs=%#v", result.Logs)
	}
	if tun.restoreCalls != 1 {
		t.Fatalf("TUN health failure must try to restore TUN state once, got %d", tun.restoreCalls)
	}
	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), req.SessionID)
	raw, readErr := os.ReadFile(statePath)
	if readErr != nil {
		t.Fatalf("TUN health restore failure must keep recovery state for startup cleanup retry: %v", readErr)
	}
	var persisted agentVPNSessionState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode recovery state: %v", err)
	}
	if persisted.TunSnapshotPath == "" || persisted.SessionID != req.SessionID {
		t.Fatalf("unexpected recovery state: %#v", persisted)
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed TUN health session must not be tracked as running")
	}
}

func TestAgentVPNTunSidecarStartFailureKeepsRecoveryStateWhenTunRestoreFails(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{restoreErr: errors.New("tun restore failed")}
	vpnManager.tunManager = tun
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return nil, errors.New("sidecar boot failed")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-tun-sidecar-start-restore-fail",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun-sidecar-start-restore-fail",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	req = withTestVPNBridgeAddress(t, req)
	result, err := vpnManager.Start(req)
	if err == nil {
		t.Fatalf("sidecar start failure must reject VPN start, result=%#v", result)
	}
	if !strings.Contains(err.Error(), "sidecar boot failed") {
		t.Fatalf("start error must include sidecar failure, got %v", err)
	}
	logs := strings.Join(result.Logs, "\n")
	if !strings.Contains(logs, "tun_restore=failed: tun restore failed") {
		t.Fatalf("sidecar start failure result must report TUN restore failure, logs=%#v", result.Logs)
	}
	if !strings.Contains(logs, "state=kept-for-restore-retry") {
		t.Fatalf("sidecar start failure result must report retained recovery state, logs=%#v", result.Logs)
	}
	if tun.snapshotCalls != 1 {
		t.Fatalf("sidecar start failure must snapshot TUN state before launch, got %d", tun.snapshotCalls)
	}
	if tun.restoreCalls != 1 {
		t.Fatalf("sidecar start failure must try to restore TUN state once, got %d", tun.restoreCalls)
	}
	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), req.SessionID)
	raw, readErr := os.ReadFile(statePath)
	if readErr != nil {
		t.Fatalf("sidecar start restore failure must keep recovery state for startup cleanup retry: %v", readErr)
	}
	var persisted agentVPNSessionState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode recovery state: %v", err)
	}
	if persisted.TunSnapshotPath == "" || persisted.SessionID != req.SessionID {
		t.Fatalf("unexpected recovery state: %#v", persisted)
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed sidecar start session must not be tracked as running")
	}
}

func TestAgentVPNTunBridgeStartFailureReportsCleanupLogsWhenTunRestoreFails(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{restoreErr: errors.New("tun restore failed")}
	vpnManager.tunManager = tun
	process := &recordingVPNSidecarProcess{}
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-tun-bridge-start-restore-fail",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun-bridge-start-restore-fail",
		Token:         "session-token",
		TunName:       "nezha-vpn",
		Extra: map[string]string{
			"bridge_addr": ln.Addr().String(),
		},
	}
	result, err := vpnManager.Start(req)
	if err == nil {
		t.Fatalf("bridge start failure must reject VPN start, result=%#v", result)
	}
	if !strings.Contains(err.Error(), "start VPN bridge") {
		t.Fatalf("start error must include bridge failure, got %v", err)
	}
	logs := strings.Join(result.Logs, "\n")
	if !strings.Contains(logs, "tun_restore=failed: tun restore failed") {
		t.Fatalf("bridge start failure result must report TUN restore failure, logs=%#v", result.Logs)
	}
	if !strings.Contains(logs, "state=kept-for-restore-retry") {
		t.Fatalf("bridge start failure result must report retained recovery state, logs=%#v", result.Logs)
	}
	if process.stopCalls != 1 {
		t.Fatalf("bridge start failure must stop the sidecar once, got %d", process.stopCalls)
	}
	if tun.restoreCalls != 1 {
		t.Fatalf("bridge start failure must try to restore TUN state once, got %d", tun.restoreCalls)
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed bridge start session must not be tracked as running")
	}
}

func TestAgentVPNSystemProxyApplyFailureReportsStartupCleanupLogs(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{applyErr: errors.New("proxy apply failed")}
	vpnManager.systemProxyManager = proxy
	process := &recordingVPNSidecarProcess{}
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-system-proxy-apply-fail",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-system-proxy-apply-fail",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	result, err := vpnManager.Start(req)
	if err == nil {
		t.Fatalf("system proxy apply failure must reject VPN start, result=%#v", result)
	}
	if !strings.Contains(err.Error(), "proxy apply failed") {
		t.Fatalf("start error must include system proxy apply failure, got %v", err)
	}
	logs := strings.Join(result.Logs, "\n")
	if !strings.Contains(logs, "rollback=bridge-closed,sidecar-stopped,relay-closed") {
		t.Fatalf("system proxy apply failure result must report startup cleanup, logs=%#v", result.Logs)
	}
	if proxy.applyCalls != 1 {
		t.Fatalf("system proxy must be applied exactly once, got %d", proxy.applyCalls)
	}
	if process.stopCalls != 1 {
		t.Fatalf("system proxy apply failure must stop the sidecar once, got %d", process.stopCalls)
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed system proxy apply session must not be tracked as running")
	}
}

func TestAgentVPNEgressProbeLogsObservedExitAfterStart(t *testing.T) {
	resetVPNManagerForTest(t)
	called := false
	vpnManager.egressProbe = func(ctx context.Context, req model.VPNControlRequest) ([]string, error) {
		called = true
		if req.Extra["egress_probe_url"] != "https://ifconfig.example/ip" {
			t.Fatalf("egress probe URL mismatch: %#v", req.Extra)
		}
		return []string{"[egress] observed_ip=198.51.100.20"}, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-egress-probe",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-egress-probe",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"egress_probe_url": "https://ifconfig.example/ip",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	result, err := vpnManager.Start(req)
	if err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	if !called {
		t.Fatal("entry VPN start must run configured egress probe")
	}
	if len(result.Logs) != 1 || !strings.Contains(result.Logs[0], "198.51.100.20") {
		t.Fatalf("start result must include egress probe log, got %#v", result.Logs)
	}
}

func TestAgentVPNEgressProbeFailureFailsStartWithExitReason(t *testing.T) {
	resetVPNManagerForTest(t)
	vpnManager.egressProbe = func(ctx context.Context, req model.VPNControlRequest) ([]string, error) {
		return []string{"[egress] probe failed via http://127.0.0.1:8088"}, errors.New("exit probe mismatch")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-egress-probe-failed",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-egress-probe-failed",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"egress_probe_url": "https://ifconfig.example/ip",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	result, err := vpnManager.Start(req)
	if err == nil {
		t.Fatal("start must fail when egress probe fails")
	}
	if result.State != model.VPNStateFailed || result.FailureReason != model.VPNFailureReasonExitEgressFailed {
		t.Fatalf("egress probe failure must report exit failure, got %#v", result)
	}
	if !strings.Contains(strings.Join(result.Logs, "\n"), "[egress] probe failed") {
		t.Fatalf("egress probe failure logs must be preserved, got %#v", result.Logs)
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed egress probe session must not be tracked as running")
	}
}

func TestDefaultVPNEgressProbeRetriesUntilLocalProxyReady(t *testing.T) {
	probeURL := "http://ifconfig.example/ip"
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}

	proxyReady := make(chan struct{})
	go func() {
		time.Sleep(80 * time.Millisecond)
		listener, err := net.Listen("tcp", proxyAddr)
		if err != nil {
			close(proxyReady)
			return
		}
		close(proxyReady)
		server := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.String() != probeURL {
					t.Errorf("probe request URL mismatch: %s", r.URL.String())
				}
				_, _ = w.Write([]byte("198.51.100.77\n"))
			}),
		}
		defer server.Close()
		_ = server.Serve(listener)
	}()
	defer func() {
		<-proxyReady
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logs, err := defaultVPNEgressProbe(ctx, model.VPNControlRequest{
		Role:       model.VPNRoleEntry,
		Mode:       model.VPNModeSystemProxy,
		ListenHTTP: proxyAddr,
		Extra: map[string]string{
			"egress_probe_url":             probeURL,
			"egress_probe_timeout_seconds": "1",
		},
	})
	if err != nil {
		t.Fatalf("egress probe should eventually succeed: %v logs=%#v", err, logs)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "198.51.100.77") {
		t.Fatalf("egress probe should retry until local proxy is ready, got %#v", logs)
	}
}

func TestDefaultVPNEgressProbeLogsExpectedIPMatch(t *testing.T) {
	probeURL := "http://ifconfig.example/ip"
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != probeURL {
			t.Errorf("probe request URL mismatch: %s", r.URL.String())
		}
		_, _ = w.Write([]byte("198.51.100.20\n"))
	}))
	defer proxyServer.Close()
	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")

	logs, err := defaultVPNEgressProbe(context.Background(), model.VPNControlRequest{
		Role:       model.VPNRoleEntry,
		Mode:       model.VPNModeSystemProxy,
		ListenHTTP: proxyAddr,
		Extra: map[string]string{
			"egress_probe_url":    probeURL,
			"egress_expected_ips": "198.51.100.20,2001:db8::20",
		},
	})
	if err != nil {
		t.Fatalf("egress probe should match expected IP: %v logs=%#v", err, logs)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "expected=198.51.100.20,2001:db8::20") || !strings.Contains(logs[0], "match=true") {
		t.Fatalf("egress probe log must include expected IPs and match result, got %#v", logs)
	}
}

func TestDefaultVPNEgressProbeFailsExpectedIPMismatch(t *testing.T) {
	probeURL := "http://ifconfig.example/ip"
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != probeURL {
			t.Errorf("probe request URL mismatch: %s", r.URL.String())
		}
		_, _ = w.Write([]byte("203.0.113.10\n"))
	}))
	defer proxyServer.Close()
	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	logs, err := defaultVPNEgressProbe(ctx, model.VPNControlRequest{
		Role:       model.VPNRoleEntry,
		Mode:       model.VPNModeSystemProxy,
		ListenHTTP: proxyAddr,
		Extra: map[string]string{
			"egress_probe_url":             probeURL,
			"egress_expected_ips":          "198.51.100.20",
			"egress_probe_timeout_seconds": "1",
		},
	})
	if err == nil {
		t.Fatalf("egress probe should fail on expected IP mismatch, logs=%#v", logs)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "match=false") {
		t.Fatalf("egress probe mismatch log must include match=false, got %#v", logs)
	}
}

func TestAgentVPNTunSnapshotRestoredWhenSidecarCrashes(t *testing.T) {
	resetVPNManagerForTest(t)
	process := newBlockingRecordingVPNSidecarProcess()
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	tun := &recordingVPNTunManager{}
	vpnManager.tunManager = tun

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-tun-crash",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunGlobal,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun-crash",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	process.exit(errors.New("sidecar crashed"))
	waitForVPNSessionState(t, req.SessionID, model.VPNStateFailed)
	if tun.restoreCalls != 1 || tun.lastRestore.SessionID != req.SessionID {
		t.Fatalf("TUN sidecar crash must restore system network state once, got %#v", tun)
	}
}

func TestAgentVPNSidecarCrashReportsFailedOnlyAfterTunRestoreCompletes(t *testing.T) {
	resetVPNManagerForTest(t)
	process := newBlockingRecordingVPNSidecarProcess()
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	tun := &blockingVPNTunManager{
		restoreStarted: make(chan struct{}, 1),
		releaseRestore: make(chan struct{}),
	}
	vpnManager.tunManager = tun

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-tun-crash-order",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunGlobal,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun-crash-order",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	process.exit(errors.New("sidecar crashed"))
	select {
	case <-tun.restoreStarted:
	case <-time.After(time.Second):
		t.Fatal("sidecar crash must start TUN restore")
	}

	statusReq := req
	statusReq.Action = model.VPNActionStatus
	status, err := vpnManager.Status(statusReq)
	if err != nil {
		close(tun.releaseRestore)
		t.Fatalf("status during TUN restore: %v", err)
	}
	if status.State == model.VPNStateFailed {
		close(tun.releaseRestore)
		waitForVPNSessionState(t, req.SessionID, model.VPNStateFailed)
		t.Fatalf("session must not report failed before TUN restore completes: %#v", status)
	}

	close(tun.releaseRestore)
	waitForVPNSessionState(t, req.SessionID, model.VPNStateFailed)
	if tun.restoreCalls != 1 {
		t.Fatalf("TUN sidecar crash must restore once, got %d", tun.restoreCalls)
	}
}

func TestAgentVPNSidecarCrashRemovesPersistedSessionState(t *testing.T) {
	resetVPNManagerForTest(t)
	process := newBlockingRecordingVPNSidecarProcess()
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-crash-state",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-crash-state",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	session, ok := vpnManager.Get(req.SessionID)
	if !ok {
		t.Fatal("running session must be tracked")
	}
	if _, err := os.Stat(session.StatePath); err != nil {
		t.Fatalf("session state must exist before sidecar crash: %v", err)
	}

	process.exit(errors.New("sidecar crashed"))
	waitForVPNSessionState(t, req.SessionID, model.VPNStateFailed)
	if _, err := os.Stat(session.StatePath); !os.IsNotExist(err) {
		t.Fatalf("session state must be removed after sidecar crash, stat err=%v", err)
	}
}

func TestAgentVPNStartPersistsSessionStateAndStopRemovesIt(t *testing.T) {
	resetVPNManagerForTest(t)

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-state",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-state",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	session, ok := vpnManager.Get(req.SessionID)
	if !ok {
		t.Fatal("running session must be tracked")
	}
	if session.StatePath == "" {
		t.Fatal("running session must record its persistent state path")
	}
	raw, err := os.ReadFile(session.StatePath)
	if err != nil {
		t.Fatalf("read session state: %v", err)
	}
	var persisted agentVPNSessionState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode session state: %v", err)
	}
	if persisted.SessionID != req.SessionID || persisted.Role != req.Role || persisted.State != model.VPNStateRunning {
		t.Fatalf("unexpected persisted session state: %#v", persisted)
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	if _, err := vpnManager.Stop(stopReq); err != nil {
		t.Fatalf("stop VPN: %v", err)
	}
	if _, err := os.Stat(session.StatePath); !os.IsNotExist(err) {
		t.Fatalf("session state must be removed on stop, stat err=%v", err)
	}
}

func TestAgentVPNStartPersistsRecoveryStateWhenPersistFailsAfterSystemProxyApply(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{restoreErr: errors.New("proxy restore failed")}
	vpnManager.systemProxyManager = proxy
	writeCalls := 0
	var recoveryState agentVPNSessionState
	vpnManager.sessionStateWriter = func(path string, state agentVPNSessionState) error {
		writeCalls++
		if writeCalls == 1 {
			return errors.New("disk full")
		}
		recoveryState = state
		return writeAgentVPNSessionState(path, state)
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-persist-fail-after-proxy",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-persist-fail-after-proxy",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	result, err := vpnManager.Start(req)
	if err == nil {
		t.Fatalf("start must fail when session state cannot be persisted, result=%#v", result)
	}
	if !strings.Contains(err.Error(), "persist VPN session state") {
		t.Fatalf("start error must report persist failure, got %v", err)
	}
	if proxy.restoreCalls != 1 {
		t.Fatalf("failed start must try to restore applied system proxy once, got %d", proxy.restoreCalls)
	}
	if writeCalls != 2 {
		t.Fatalf("failed start must write recovery state after restore failure, got %d writes", writeCalls)
	}
	if !recoveryState.SystemProxyApplied {
		t.Fatalf("recovery state must keep system_proxy_applied=true after restore failure: %#v", recoveryState)
	}
	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), req.SessionID)
	raw, readErr := os.ReadFile(statePath)
	if readErr != nil {
		t.Fatalf("recovery state must be persisted for cleanup retry: %v", readErr)
	}
	var persisted agentVPNSessionState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode recovery state: %v", err)
	}
	if !persisted.SystemProxyApplied || persisted.SessionID != req.SessionID {
		t.Fatalf("unexpected recovery state: %#v", persisted)
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed start must not leave a running session in memory")
	}
}

func TestAgentVPNStartPersistsRecoveryStateWhenPersistFailsAndTunRestoreFails(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{restoreErr: errors.New("tun restore failed")}
	vpnManager.tunManager = tun
	writeCalls := 0
	var recoveryState agentVPNSessionState
	vpnManager.sessionStateWriter = func(path string, state agentVPNSessionState) error {
		writeCalls++
		if writeCalls == 1 {
			return errors.New("disk full")
		}
		recoveryState = state
		return writeAgentVPNSessionState(path, state)
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-persist-fail-after-tun",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-persist-fail-after-tun",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	req = withTestVPNBridgeAddress(t, req)
	result, err := vpnManager.Start(req)
	if err == nil {
		t.Fatalf("start must fail when TUN session state cannot be persisted, result=%#v", result)
	}
	if !strings.Contains(err.Error(), "persist VPN session state") {
		t.Fatalf("start error must report persist failure, got %v", err)
	}
	if tun.snapshotCalls != 1 {
		t.Fatalf("failed start must snapshot TUN state before sidecar start, got %d", tun.snapshotCalls)
	}
	if tun.restoreCalls != 1 {
		t.Fatalf("failed start must try to restore TUN state once, got %d", tun.restoreCalls)
	}
	if writeCalls != 2 {
		t.Fatalf("failed start must write recovery state after TUN restore failure, got %d writes", writeCalls)
	}
	if recoveryState.TunSnapshotPath == "" {
		t.Fatalf("recovery state must keep tun_snapshot_path after restore failure: %#v", recoveryState)
	}
	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), req.SessionID)
	raw, readErr := os.ReadFile(statePath)
	if readErr != nil {
		t.Fatalf("recovery state must be persisted for TUN cleanup retry: %v", readErr)
	}
	var persisted agentVPNSessionState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode recovery state: %v", err)
	}
	if persisted.TunSnapshotPath == "" || persisted.SessionID != req.SessionID {
		t.Fatalf("unexpected recovery state: %#v", persisted)
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed start must not leave a running TUN session in memory")
	}
}

func TestAgentVPNStartPersistFailureReportsCleanupLogs(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{}
	tun := &recordingVPNTunManager{}
	vpnManager.systemProxyManager = proxy
	vpnManager.tunManager = tun
	vpnManager.sessionStateWriter = func(path string, state agentVPNSessionState) error {
		return errors.New("state disk unavailable")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-persist-fail-cleanup-logs",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-persist-fail-cleanup-logs",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	result, err := vpnManager.Start(req)
	if err == nil {
		t.Fatalf("start must fail when session state cannot be persisted, result=%#v", result)
	}
	logs := strings.Join(result.Logs, "\n")
	if !strings.Contains(logs, "system_proxy_restore=ok") {
		t.Fatalf("persist failure result must report system proxy cleanup, got %#v", result.Logs)
	}
	if !strings.Contains(logs, "rollback=bridge-closed,sidecar-stopped,relay-closed") {
		t.Fatalf("persist failure result must report bridge/sidecar/relay rollback, got %#v", result.Logs)
	}
	if proxy.restoreCalls != 1 || tun.restoreCalls != 0 {
		t.Fatalf("system proxy persist failure must restore proxy only, proxy=%d tun=%d", proxy.restoreCalls, tun.restoreCalls)
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed start must not leave a running session in memory")
	}
}

func TestAgentVPNTunStartPersistFailureReportsCleanupLogs(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{}
	vpnManager.tunManager = tun
	vpnManager.sessionStateWriter = func(path string, state agentVPNSessionState) error {
		return errors.New("state disk unavailable")
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-tun-persist-fail-cleanup-logs",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-tun-persist-fail-cleanup-logs",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	req = withTestVPNBridgeAddress(t, req)
	result, err := vpnManager.Start(req)
	if err == nil {
		t.Fatalf("start must fail when TUN session state cannot be persisted, result=%#v", result)
	}
	logs := strings.Join(result.Logs, "\n")
	if !strings.Contains(logs, "tun_restore=ok") {
		t.Fatalf("persist failure result must report TUN cleanup, got %#v", result.Logs)
	}
	if !strings.Contains(logs, "rollback=bridge-closed,sidecar-stopped,relay-closed") {
		t.Fatalf("persist failure result must report bridge/sidecar/relay rollback, got %#v", result.Logs)
	}
	if tun.restoreCalls != 1 {
		t.Fatalf("TUN persist failure must restore TUN exactly once, got %d", tun.restoreCalls)
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed start must not leave a running session in memory")
	}
}

func TestAgentVPNCleanupStaleSessionsRestoresSystemProxyAndRemovesState(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{}
	vpnManager.systemProxyManager = proxy

	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), "vpn-stale-session")
	if err := os.MkdirAll(filepath.Dir(statePath), 0750); err != nil {
		t.Fatal(err)
	}
	state := agentVPNSessionState{
		Version:            1,
		SessionID:          "vpn-stale-session",
		Role:               model.VPNRoleEntry,
		Mode:               model.VPNModeSystemProxy,
		State:              model.VPNStateRunning,
		SystemProxyApplied: true,
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	vpnManager.CleanupStaleSessions()

	if proxy.restoreCalls != 1 {
		t.Fatalf("stale VPN cleanup must restore system proxy once, got %d", proxy.restoreCalls)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("stale session state must be removed after cleanup, stat err=%v", err)
	}
}

func TestAgentVPNCleanupStaleSessionsSkipsActiveTrackedSession(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{}
	vpnManager.systemProxyManager = proxy

	killedPIDs := make([]int, 0, 1)
	vpnManager.staleSidecarKiller = func(pid int) error {
		killedPIDs = append(killedPIDs, pid)
		return nil
	}

	const sessionID = "vpn-active-session"
	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), sessionID)
	if err := os.MkdirAll(filepath.Dir(statePath), 0750); err != nil {
		t.Fatal(err)
	}
	state := agentVPNSessionState{
		Version:            1,
		SessionID:          sessionID,
		Role:               model.VPNRoleEntry,
		Mode:               model.VPNModeSystemProxy,
		State:              model.VPNStateRunning,
		SidecarPID:         424242,
		SystemProxyApplied: true,
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	vpnManager.mu.Lock()
	vpnManager.sessions[sessionID] = &AgentVPNSession{
		Request: model.VPNControlRequest{
			SessionID: sessionID,
			Role:      model.VPNRoleEntry,
			Mode:      model.VPNModeSystemProxy,
		},
		State:              model.VPNStateRunning,
		StatePath:          statePath,
		sidecarPID:         state.SidecarPID,
		systemProxyApplied: true,
	}
	vpnManager.mu.Unlock()

	vpnManager.CleanupStaleSessions()

	if proxy.restoreCalls != 0 {
		t.Fatalf("active session stale cleanup must not restore system proxy, got %d", proxy.restoreCalls)
	}
	if len(killedPIDs) != 0 {
		t.Fatalf("active session stale cleanup must not kill sidecar, got %#v", killedPIDs)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("active session state must be kept, stat err=%v", err)
	}
	if _, ok := vpnManager.Get(sessionID); !ok {
		t.Fatal("active session must remain tracked after stale cleanup")
	}
}

func TestAgentVPNCleanupStaleSessionsSkipsActiveSharedExitRuntime(t *testing.T) {
	resetVPNManagerForTest(t)

	killedPIDs := make([]int, 0, 1)
	vpnManager.staleSidecarKiller = func(pid int) error {
		killedPIDs = append(killedPIDs, pid)
		return nil
	}

	const sessionID = "vpn-active-shared-exit-session"
	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), sessionID)
	if err := os.MkdirAll(filepath.Dir(statePath), 0750); err != nil {
		t.Fatal(err)
	}
	state := agentVPNSessionState{
		Version:    1,
		SessionID:  sessionID,
		Role:       model.VPNRoleExit,
		Mode:       model.VPNModeSystemProxy,
		State:      model.VPNStateRunning,
		SidecarPID: 525252,
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	vpnManager.mu.Lock()
	vpnManager.sharedExitRuntimes["test-core"] = &agentVPNSharedExitRuntime{
		Key:        "test-core",
		sidecarPID: state.SidecarPID,
		refs: map[string]struct{}{
			sessionID: {},
		},
	}
	vpnManager.mu.Unlock()

	vpnManager.CleanupStaleSessions()

	if len(killedPIDs) != 0 {
		t.Fatalf("active shared exit stale cleanup must not kill sidecar, got %#v", killedPIDs)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("active shared exit state must be kept, stat err=%v", err)
	}
}

func TestAgentVPNCleanupStaleSessionsRestoresTunSnapshot(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{}
	vpnManager.tunManager = tun

	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), "vpn-stale-tun-session")
	if err := os.MkdirAll(filepath.Dir(statePath), 0750); err != nil {
		t.Fatal(err)
	}
	state := agentVPNSessionState{
		Version:         1,
		SessionID:       "vpn-stale-tun-session",
		Role:            model.VPNRoleEntry,
		Mode:            model.VPNModeTunSplit,
		State:           model.VPNStateRunning,
		TunSnapshotPath: filepath.Join(filepath.Dir(statePath), "tun-snapshot.json"),
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	vpnManager.CleanupStaleSessions()

	if tun.restoreCalls != 1 || tun.lastRestore.SessionID != state.SessionID {
		t.Fatalf("stale TUN cleanup must restore network snapshot once, got %#v", tun)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("stale TUN session state must be removed after cleanup, stat err=%v", err)
	}
}

func TestAgentVPNCleanupStaleSessionsDoesNotRestoreSystemProxyTwiceWhenTunRetryIsNeeded(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{}
	vpnManager.systemProxyManager = proxy
	tun := &recordingVPNTunManager{restoreErr: errors.New("tun restore failed")}
	vpnManager.tunManager = tun

	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), "vpn-stale-combined-session")
	if err := os.MkdirAll(filepath.Dir(statePath), 0750); err != nil {
		t.Fatal(err)
	}
	state := agentVPNSessionState{
		Version:            1,
		SessionID:          "vpn-stale-combined-session",
		Role:               model.VPNRoleEntry,
		Mode:               model.VPNModeTunSplit,
		State:              model.VPNStateRunning,
		SystemProxyApplied: true,
		TunSnapshotPath:    filepath.Join(filepath.Dir(statePath), "tun-snapshot.json"),
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	vpnManager.CleanupStaleSessions()

	if proxy.restoreCalls != 1 {
		t.Fatalf("first stale cleanup must restore system proxy once, got %d", proxy.restoreCalls)
	}
	if tun.restoreCalls != 1 {
		t.Fatalf("first stale cleanup must attempt TUN restore once, got %d", tun.restoreCalls)
	}
	raw, err = os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("state must be kept when TUN restore fails: %v", err)
	}
	var persisted agentVPNSessionState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode retained stale state: %v", err)
	}
	if persisted.SystemProxyApplied {
		t.Fatal("retained stale state must clear restored system proxy flag before TUN retry")
	}

	vpnManager.CleanupStaleSessions()

	if proxy.restoreCalls != 1 {
		t.Fatalf("second stale cleanup must not restore system proxy twice, got %d", proxy.restoreCalls)
	}
	if tun.restoreCalls != 2 {
		t.Fatalf("second stale cleanup must retry TUN restore, got %d", tun.restoreCalls)
	}
}

func TestAgentVPNCleanupStaleSessionsKeepsStateWhenSidecarKillFails(t *testing.T) {
	resetVPNManagerForTest(t)
	vpnManager.staleSidecarKiller = func(pid int) error {
		if pid != 424242 {
			t.Fatalf("unexpected stale sidecar pid: %d", pid)
		}
		return errors.New("access denied")
	}

	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), "vpn-stale-sidecar-session")
	if err := os.MkdirAll(filepath.Dir(statePath), 0750); err != nil {
		t.Fatal(err)
	}
	state := agentVPNSessionState{
		Version:    1,
		SessionID:  "vpn-stale-sidecar-session",
		Role:       model.VPNRoleEntry,
		Mode:       model.VPNModeSystemProxy,
		State:      model.VPNStateRunning,
		SidecarPID: 424242,
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	vpnManager.CleanupStaleSessions()

	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state must be kept when stale sidecar kill fails for retry: %v", err)
	}
}

func TestAgentVPNCleanupStaleSessionsTreatsMissingSidecarAsCleaned(t *testing.T) {
	resetVPNManagerForTest(t)
	vpnManager.staleSidecarKiller = func(pid int) error {
		if pid != 525252 {
			t.Fatalf("unexpected stale sidecar pid: %d", pid)
		}
		return os.ErrProcessDone
	}

	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), "vpn-stale-missing-sidecar-session")
	if err := os.MkdirAll(filepath.Dir(statePath), 0750); err != nil {
		t.Fatal(err)
	}
	state := agentVPNSessionState{
		Version:    1,
		SessionID:  "vpn-stale-missing-sidecar-session",
		Role:       model.VPNRoleEntry,
		Mode:       model.VPNModeSystemProxy,
		State:      model.VPNStateRunning,
		SidecarPID: 525252,
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	vpnManager.CleanupStaleSessions()

	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state must be removed when stale sidecar is already gone, stat err=%v", err)
	}
}

func TestAgentVPNCleanupStaleSessionsDoesNotKillSidecarTwiceWhenTunRetryIsNeeded(t *testing.T) {
	resetVPNManagerForTest(t)
	killCalls := 0
	vpnManager.staleSidecarKiller = func(pid int) error {
		killCalls++
		if pid != 515151 {
			t.Fatalf("unexpected stale sidecar pid: %d", pid)
		}
		return nil
	}
	tun := &recordingVPNTunManager{restoreErr: errors.New("tun restore failed")}
	vpnManager.tunManager = tun

	statePath := vpnSessionStatePath(vpnManager.effectiveWorkDir(), "vpn-stale-sidecar-tun-session")
	if err := os.MkdirAll(filepath.Dir(statePath), 0750); err != nil {
		t.Fatal(err)
	}
	state := agentVPNSessionState{
		Version:         1,
		SessionID:       "vpn-stale-sidecar-tun-session",
		Role:            model.VPNRoleEntry,
		Mode:            model.VPNModeTunSplit,
		State:           model.VPNStateRunning,
		SidecarPID:      515151,
		TunSnapshotPath: filepath.Join(filepath.Dir(statePath), "tun-snapshot.json"),
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	vpnManager.CleanupStaleSessions()

	if killCalls != 1 {
		t.Fatalf("first stale cleanup must kill sidecar once, got %d", killCalls)
	}
	if tun.restoreCalls != 1 {
		t.Fatalf("first stale cleanup must attempt TUN restore once, got %d", tun.restoreCalls)
	}
	raw, err = os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("state must be kept when TUN restore fails: %v", err)
	}
	var persisted agentVPNSessionState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode retained stale state: %v", err)
	}
	if persisted.SidecarPID != 0 {
		t.Fatalf("retained stale state must clear killed sidecar pid before TUN retry, got %d", persisted.SidecarPID)
	}

	vpnManager.CleanupStaleSessions()

	if killCalls != 1 {
		t.Fatalf("second stale cleanup must not kill sidecar twice, got %d", killCalls)
	}
	if tun.restoreCalls != 2 {
		t.Fatalf("second stale cleanup must retry TUN restore, got %d", tun.restoreCalls)
	}
}

func TestAgentVPNMarksSessionFailedWhenSidecarExitsUnexpectedly(t *testing.T) {
	resetVPNManagerForTest(t)
	process := newBlockingRecordingVPNSidecarProcess()
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	stream := &recordingVPNIOStream{recvCh: make(chan error)}
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
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
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	process.exit(errors.New("sidecar crashed"))
	waitForVPNSessionState(t, req.SessionID, model.VPNStateFailed)

	statusReq := req
	statusReq.Action = model.VPNActionStatus
	payload, err := vpnManager.Status(statusReq)
	if err != nil {
		t.Fatalf("status after sidecar crash: %v", err)
	}
	if payload.State != model.VPNStateFailed {
		t.Fatalf("status must report failed after sidecar crash: %#v", payload)
	}
	if payload.LastError != "sidecar crashed" {
		t.Fatalf("status must include sidecar error, got %#v", payload)
	}
	stream.mu.Lock()
	closed := stream.closed
	stream.mu.Unlock()
	if !closed {
		t.Fatal("sidecar crash must close Dashboard relay stream")
	}
}

func TestAgentVPNLogsActionReturnsSidecarLogTail(t *testing.T) {
	resetVPNManagerForTest(t)
	var started vpnSidecarStartSpec
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		started = spec
		return newBlockingRecordingVPNSidecarProcess(), nil
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
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	if err := os.WriteFile(started.LogPath, []byte("line-1\nline-2\nline-3\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	logReq := req
	logReq.Action = model.VPNActionLogs
	payload, err := vpnManager.Status(logReq)
	if err != nil {
		t.Fatalf("logs action: %v", err)
	}
	if len(payload.Logs) != 3 {
		t.Fatalf("logs action must return sidecar log lines, got %#v", payload.Logs)
	}
	if payload.Logs[0] != "line-1" || payload.Logs[2] != "line-3" {
		t.Fatalf("unexpected log lines: %#v", payload.Logs)
	}
}

func TestAgentVPNReportsFailedTaskResultWhenSidecarExitsUnexpectedly(t *testing.T) {
	resetVPNManagerForTest(t)
	process := newBlockingRecordingVPNSidecarProcess()
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	results := make(chan *pb.TaskResult, 1)
	vpnManager.SetTaskResultSender(func(result *pb.TaskResult) error {
		results <- result
		return nil
	})

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
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	process.exit(errors.New("sidecar crashed"))

	select {
	case result := <-results:
		if result.GetType() != model.TaskTypeVPNControl {
			t.Fatalf("failed sidecar report must use VPN task type, got %d", result.GetType())
		}
		if result.GetSuccessful() {
			t.Fatal("failed sidecar report must be unsuccessful")
		}
		var payload model.VPNControlResult
		if err := json.Unmarshal([]byte(result.GetData()), &payload); err != nil {
			t.Fatalf("decode failed sidecar payload: %v", err)
		}
		if payload.SessionID != req.SessionID || payload.State != model.VPNStateFailed || payload.LastError != "sidecar crashed" {
			t.Fatalf("unexpected failed sidecar payload: %#v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("sidecar crash must emit a failed VPN TaskResult")
	}
}

func TestAgentVPNSidecarCrashDoesNotBlockReportSystemState(t *testing.T) {
	resetVPNManagerForTest(t)
	originalInitialized := initialized
	originalGeoipReported := geoipReported
	t.Cleanup(func() {
		initialized = originalInitialized
		geoipReported = originalGeoipReported
	})
	initialized = true
	geoipReported = true
	agentConfig.IPReportPeriod = 3600
	monitor.InitConfig(&agentConfig)

	process := newBlockingRecordingVPNSidecarProcess()
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	results := make(chan *pb.TaskResult, 1)
	vpnManager.SetTaskResultSender(func(result *pb.TaskResult) error {
		results <- result
		return nil
	})

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-crash-monitor",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-crash-monitor",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	process.exit(errors.New("sidecar crashed"))
	waitForVPNSessionState(t, req.SessionID, model.VPNStateFailed)
	select {
	case <-results:
	case <-time.After(time.Second):
		t.Fatal("sidecar crash must emit failed VPN TaskResult before monitoring assertion")
	}

	stateClient := &recordingReportSystemStateClient{ctx: context.Background()}
	if _, _, err := reportState(stateClient, time.Now(), time.Now()); err != nil {
		t.Fatalf("reportState must keep working after VPN sidecar crash: %v", err)
	}
	if stateClient.sendCalls != 1 || stateClient.recvCalls != 1 {
		t.Fatalf("reportState must send and receive once after VPN sidecar crash, got send=%d recv=%d", stateClient.sendCalls, stateClient.recvCalls)
	}
	if stateClient.lastState == nil {
		t.Fatal("reportState must send a system state payload after VPN sidecar crash")
	}
}

func TestAgentVPNFailedTaskResultReportsCleanupStatusWhenSidecarCrashes(t *testing.T) {
	resetVPNManagerForTest(t)
	process := newBlockingRecordingVPNSidecarProcess()
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return process, nil
	}
	tun := &recordingVPNTunManager{restoreErr: errors.New("tun restore failed")}
	vpnManager.tunManager = tun
	results := make(chan *pb.TaskResult, 1)
	vpnManager.SetTaskResultSender(func(result *pb.TaskResult) error {
		results <- result
		return nil
	})

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-crash-cleanup-status",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-crash-cleanup-status",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	req = withTestVPNBridgeAddress(t, req)
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	process.exit(errors.New("sidecar crashed"))

	select {
	case result := <-results:
		var payload model.VPNControlResult
		if err := json.Unmarshal([]byte(result.GetData()), &payload); err != nil {
			t.Fatalf("decode failed sidecar payload: %v", err)
		}
		logs := strings.Join(payload.Logs, "\n")
		if !strings.Contains(logs, "tun_restore=failed: tun restore failed") {
			t.Fatalf("failed result must report TUN restore failure, logs=%#v", payload.Logs)
		}
		if !strings.Contains(logs, "state=kept-for-restore-retry") {
			t.Fatalf("failed result must report retained state for retry, logs=%#v", payload.Logs)
		}
	case <-time.After(time.Second):
		t.Fatal("sidecar crash must emit a failed VPN TaskResult")
	}
}

func TestAgentVPNEntryStartsBridgeListenerAndForwardsLocalDataToRelay(t *testing.T) {
	resetVPNManagerForTest(t)
	stream := &recordingVPNIOStream{recvCh: make(chan error)}
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		return stream, nil
	}
	bridgeAddr := freeLocalTCPAddrForTest(t)

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-1",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"bridge_addr": bridgeAddr,
		},
	}
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}

	conn, err := dialEventuallyForTest(bridgeAddr)
	if err != nil {
		t.Fatalf("dial entry bridge: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("sidecar-to-dashboard")); err != nil {
		t.Fatalf("write bridge conn: %v", err)
	}
	waitForRecordingVPNStreamSentFrame(t, stream, "sidecar-to-dashboard")
}

func TestAgentVPNExitConnectsBridgeInboundAndForwardsLocalDataToRelay(t *testing.T) {
	resetVPNManagerForTest(t)
	stream := &recordingVPNIOStream{recvFrames: make(chan []byte, 4)}
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		return stream, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleExit,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-exit-stream-1",
		Token:         "session-token",
		Extra: map[string]string{
			"bridge_listen": ln.Addr().String(),
		},
	}
	if _, err := vpnManager.Start(req); err != nil {
		t.Fatalf("start VPN: %v", err)
	}
	stream.recvFrames <- encodeVPNMuxFrameForTest(t, vpnMuxFrame{Type: vpnMuxFrameTypeOpen, ConnID: 1})
	conn, err := acceptEventuallyForTest(ln)
	if err != nil {
		t.Fatalf("accept exit bridge: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("exit-sidecar-to-dashboard")); err != nil {
		t.Fatalf("write exit bridge conn: %v", err)
	}
	waitForRecordingVPNStreamSentBytesContaining(t, stream, "exit-sidecar-to-dashboard")
}

type recordingVPNSidecarProcess struct {
	waitCh    chan error
	stopCalls int
	waitCalls int
}

type recordingVPNSystemProxyManager struct {
	applyCalls   int
	clearCalls   int
	inspectCalls int
	restoreCalls int
	applyErr     error
	clearErr     error
	inspectErr   error
	restoreErr   error
	inspection   vpnSystemProxyInspection
	lastHTTP     string
	lastSOCKS    string
	operations   []string
}

type recordingVPNTunManager struct {
	preflightCalls int
	preflightErr   error
	lastRequest    model.VPNControlRequest
	snapshotCalls  int
	snapshotErr    error
	snapshotPath   string
	lastSnapshot   model.VPNControlRequest
	restoreCalls   int
	restoreErr     error
	lastRestore    model.VPNControlRequest
}

type blockingVPNTunManager struct {
	recordingVPNTunManager
	restoreStarted chan struct{}
	releaseRestore chan struct{}
}

func (m *recordingVPNTunManager) Preflight(req model.VPNControlRequest) error {
	m.preflightCalls++
	m.lastRequest = req
	return m.preflightErr
}

func (m *recordingVPNTunManager) Snapshot(req model.VPNControlRequest, sessionDir string) (string, error) {
	m.snapshotCalls++
	m.lastSnapshot = req
	if m.snapshotErr != nil {
		return "", m.snapshotErr
	}
	if strings.TrimSpace(m.snapshotPath) != "" {
		return m.snapshotPath, nil
	}
	return filepath.Join(sessionDir, "tun-snapshot.json"), nil
}

func (m *recordingVPNTunManager) Restore(req model.VPNControlRequest, snapshotPath string) error {
	m.restoreCalls++
	m.lastRestore = req
	return m.restoreErr
}

func (m *blockingVPNTunManager) Restore(req model.VPNControlRequest, snapshotPath string) error {
	m.restoreCalls++
	m.lastRestore = req
	if m.restoreStarted != nil {
		select {
		case m.restoreStarted <- struct{}{}:
		default:
		}
	}
	if m.releaseRestore != nil {
		<-m.releaseRestore
	}
	return m.restoreErr
}

func (m *recordingVPNSystemProxyManager) Apply(httpAddr string, socksAddr string) error {
	m.applyCalls++
	m.lastHTTP = httpAddr
	m.lastSOCKS = socksAddr
	m.operations = append(m.operations, "apply")
	return m.applyErr
}

func (m *recordingVPNSystemProxyManager) Clear() error {
	m.clearCalls++
	m.operations = append(m.operations, "clear")
	return m.clearErr
}

func (m *recordingVPNSystemProxyManager) Inspect(httpAddr string, socksAddr string) (vpnSystemProxyInspection, error) {
	m.inspectCalls++
	m.lastHTTP = httpAddr
	m.lastSOCKS = socksAddr
	m.operations = append(m.operations, "inspect")
	return m.inspection, m.inspectErr
}

func (m *recordingVPNSystemProxyManager) Restore() error {
	m.restoreCalls++
	m.operations = append(m.operations, "restore")
	return m.restoreErr
}

func freeLocalTCPAddrForTest(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func dialEventuallyForTest(address string) (net.Conn, error) {
	deadline := time.Now().Add(time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !strings.Contains(err.Error(), "refused") {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, lastErr
}

func acceptEventuallyForTest(ln net.Listener) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- result{conn: conn, err: err}
	}()
	select {
	case res := <-ch:
		return res.conn, res.err
	case <-time.After(time.Second):
		return nil, errors.New("timed out waiting for accept")
	}
}

func newBlockingRecordingVPNSidecarProcess() *recordingVPNSidecarProcess {
	return &recordingVPNSidecarProcess{waitCh: make(chan error, 1)}
}

type manualFailVPNSidecarProcess struct {
	waitCh      chan error
	waitStarted chan struct{}
	waitOnce    sync.Once
	stopCalls   int
	waitCalls   int
}

func newManualFailVPNSidecarProcess() *manualFailVPNSidecarProcess {
	return &manualFailVPNSidecarProcess{
		waitCh:      make(chan error, 1),
		waitStarted: make(chan struct{}),
	}
}

func (p *manualFailVPNSidecarProcess) Stop() error {
	p.stopCalls++
	return nil
}

func (p *manualFailVPNSidecarProcess) Wait() error {
	p.waitCalls++
	p.waitOnce.Do(func() { close(p.waitStarted) })
	return <-p.waitCh
}

func (p *manualFailVPNSidecarProcess) exit(err error) {
	p.waitCh <- err
}

func (p *manualFailVPNSidecarProcess) waitForWaitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-p.waitStarted:
	case <-time.After(time.Second):
		t.Fatal("sidecar wait watcher did not start")
	}
}

func (p *recordingVPNSidecarProcess) Stop() error {
	p.stopCalls++
	if p.waitCh != nil {
		select {
		case p.waitCh <- nil:
		default:
		}
	}
	return nil
}

func (p *recordingVPNSidecarProcess) Wait() error {
	p.waitCalls++
	if p.waitCh != nil {
		return <-p.waitCh
	}
	return nil
}

func (p *recordingVPNSidecarProcess) exit(err error) {
	p.waitCh <- err
}

func waitForVPNSessionState(t *testing.T, sessionID string, state string) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		session, ok := vpnManager.Get(sessionID)
		if ok && session.State == state {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("VPN session %s did not reach state %s", sessionID, state)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

type recordingReportSystemStateClient struct {
	ctx       context.Context
	sendCalls int
	recvCalls int
	lastState *pb.State
	sendErr   error
	recvErr   error
}

func (c *recordingReportSystemStateClient) Send(state *pb.State) error {
	c.sendCalls++
	c.lastState = state
	return c.sendErr
}

func (c *recordingReportSystemStateClient) Recv() (*pb.Receipt, error) {
	c.recvCalls++
	if c.recvErr != nil {
		return nil, c.recvErr
	}
	return &pb.Receipt{}, nil
}

func (c *recordingReportSystemStateClient) Header() (metadata.MD, error) {
	return metadata.MD{}, nil
}

func (c *recordingReportSystemStateClient) Trailer() metadata.MD {
	return metadata.MD{}
}

func (c *recordingReportSystemStateClient) CloseSend() error {
	return nil
}

func (c *recordingReportSystemStateClient) Context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

func (c *recordingReportSystemStateClient) SendMsg(any) error {
	return nil
}

func (c *recordingReportSystemStateClient) RecvMsg(any) error {
	return io.EOF
}
