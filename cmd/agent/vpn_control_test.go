package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

func TestHandleVPNControlStartExitRecordsRunningSession(t *testing.T) {
	resetVPNManagerForTest(t)

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleExit,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-exit-stream-1",
		Token:         "session-token",
	}
	result := runVPNControlTaskForTest(t, req)

	if !result.Successful {
		t.Fatalf("expected successful result, got %q", result.Data)
	}
	var payload model.VPNControlResult
	if err := json.Unmarshal([]byte(result.Data), &payload); err != nil {
		t.Fatalf("decode VPN result: %v", err)
	}
	if payload.SessionID != req.SessionID || payload.Role != model.VPNRoleExit || payload.State != model.VPNStateRunning {
		t.Fatalf("unexpected VPN result: %#v", payload)
	}
	session, ok := vpnManager.Get(req.SessionID)
	if !ok {
		t.Fatal("started VPN session must be tracked locally")
	}
	if session.Request.RelayStreamID != req.RelayStreamID || session.State != model.VPNStateRunning {
		t.Fatalf("tracked session mismatch: %#v", session)
	}
}

func TestHandleVPNControlStartAttachesDashboardRelayStream(t *testing.T) {
	resetVPNManagerForTest(t)
	stream := &recordingVPNIOStream{}
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
	}
	result := runVPNControlTaskForTest(t, req)

	if !result.Successful {
		t.Fatalf("expected successful result, got %q", result.Data)
	}
	if len(stream.sent) == 0 {
		t.Fatal("VPN start must attach to Dashboard relay IOStream")
	}
	want := append([]byte{0xff, 0x05, 0xff, 0x05}, []byte(req.RelayStreamID)...)
	if string(stream.sent[0]) != string(want) {
		t.Fatalf("relay stream hello mismatch: want %v got %v", want, stream.sent[0])
	}

	stopReq := req
	stopReq.Action = model.VPNActionStop
	stopResult := runVPNControlTaskForTest(t, stopReq)
	if !stopResult.Successful {
		t.Fatalf("expected successful stop result, got %q", stopResult.Data)
	}
	stream.mu.Lock()
	closed := stream.closed
	stream.mu.Unlock()
	if !closed {
		t.Fatal("VPN stop must close Dashboard relay IOStream")
	}
}

func TestAgentVPNDirectBridgeFailureMarksSessionFailed(t *testing.T) {
	resetVPNManagerForTest(t)
	results := make(chan *pb.TaskResult, 1)
	vpnManager.SetTaskResultSender(func(result *pb.TaskResult) error {
		results <- result
		return nil
	})

	stream := &recordingVPNIOStream{}
	bridge := &AgentVPNBridge{done: make(chan error, 1)}
	session := &AgentVPNSession{
		Request: model.VPNControlRequest{
			SessionID: "vpn-direct-session",
			Action:    model.VPNActionStart,
			Role:      model.VPNRoleEntry,
			RelayMode: model.VPNRelayModeDirect,
		},
		State:  model.VPNStateRunning,
		relay:  stream,
		bridge: bridge,
	}
	vpnManager.mu.Lock()
	vpnManager.sessions[session.Request.SessionID] = session
	vpnManager.mu.Unlock()

	vpnManager.watchBridge(session.Request.SessionID, bridge)
	bridge.finish(io.ErrUnexpectedEOF)

	select {
	case result := <-results:
		if result.GetSuccessful() {
			t.Fatal("direct bridge failure must emit unsuccessful TaskResult")
		}
		var payload model.VPNControlResult
		if err := json.Unmarshal([]byte(result.GetData()), &payload); err != nil {
			t.Fatalf("decode failed direct bridge payload: %v", err)
		}
		if payload.State != model.VPNStateFailed || !strings.Contains(payload.LastError, "VPN bridge relay closed") {
			t.Fatalf("unexpected direct bridge failure payload: %#v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("direct bridge failure must emit failed VPN TaskResult")
	}

	got, ok := vpnManager.Get(session.Request.SessionID)
	if !ok || got.State != model.VPNStateFailed {
		t.Fatalf("direct bridge failure must keep failed session state, got ok=%t session=%#v", ok, got)
	}
	stream.mu.Lock()
	closed := stream.closed
	stream.mu.Unlock()
	if !closed {
		t.Fatal("direct bridge failure must close relay stream")
	}
}

func TestAgentVPNManagersRouteLocalTrafficThroughDashboardRelay(t *testing.T) {
	originalConfig := agentConfig
	agentConfig = model.AgentConfig{VPNAllowSystemProxy: true, VPNAllowTun: true}
	t.Cleanup(func() { agentConfig = originalConfig })

	relay := newFakeDashboardVPNRelay("vpn-entry-stream-e2e", "vpn-exit-stream-e2e")
	entryManager := newTestAgentVPNManagerWithStream(t, relay.entryStream())
	exitManager := newTestAgentVPNManagerWithStream(t, relay.exitStream())
	exitTargetAddr, closeExitTarget := startVPNBridgeEchoTarget(t)
	defer closeExitTarget()

	exitReq := model.VPNControlRequest{
		SessionID:     "vpn-session-e2e",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleExit,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-exit-stream-e2e",
		Token:         "session-token",
		Extra: map[string]string{
			"bridge_listen": exitTargetAddr,
		},
	}
	if _, err := exitManager.Start(exitReq); err != nil {
		t.Fatalf("start exit VPN manager: %v", err)
	}
	defer func() {
		stopReq := exitReq
		stopReq.Action = model.VPNActionStop
		_, _ = exitManager.Stop(stopReq)
	}()

	entryBridgeAddr := freeLocalTCPAddrForTest(t)
	entryReq := model.VPNControlRequest{
		SessionID:     "vpn-session-e2e",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-e2e",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"bridge_addr": entryBridgeAddr,
		},
		Limits: model.VPNLimits{
			MaxConnections: 1,
		},
	}
	if _, err := entryManager.Start(entryReq); err != nil {
		t.Fatalf("start entry VPN manager: %v", err)
	}
	defer func() {
		stopReq := entryReq
		stopReq.Action = model.VPNActionStop
		_, _ = entryManager.Stop(stopReq)
	}()

	conn, err := dialEventuallyForTest(entryBridgeAddr)
	if err != nil {
		t.Fatalf("dial entry bridge: %v", err)
	}
	defer conn.Close()

	reply := roundTripVPNBridgeMessage(t, conn, "via-dashboard-relay")
	if reply != "reply:via-dashboard-relay" {
		t.Fatalf("unexpected VPN round trip reply: %q", reply)
	}
	if !relay.sawTrafficBothWays() {
		t.Fatal("fake Dashboard relay must observe mux bytes in both directions")
	}
}

func TestHandleVPNControlEntryBridgeOwnsRelayMuxReadLoop(t *testing.T) {
	resetVPNManagerForTest(t)
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
	}
	result := runVPNControlTaskForTest(t, req)
	if !result.Successful {
		t.Fatalf("expected successful result, got %q", result.Data)
	}

	stream.recvFrames <- encodeVPNMuxFrameForTest(t, vpnMuxFrame{Type: vpnMuxFrameTypeClose, ConnID: 99})

	stopReq := req
	stopReq.Action = model.VPNActionStop
	stopResult := runVPNControlTaskForTest(t, stopReq)
	if !stopResult.Successful {
		t.Fatalf("entry bridge mux read loop must not break stop, got %q", stopResult.Data)
	}
}

func TestHandleVPNControlStopClosesTrackedSession(t *testing.T) {
	resetVPNManagerForTest(t)

	start := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-1",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
	}
	startResult := runVPNControlTaskForTest(t, start)
	if !startResult.Successful {
		t.Fatalf("start should succeed before stop, got %q", startResult.Data)
	}

	stop := start
	stop.Action = model.VPNActionStop
	result := runVPNControlTaskForTest(t, stop)

	if !result.Successful {
		t.Fatalf("expected successful stop result, got %q", result.Data)
	}
	var payload model.VPNControlResult
	if err := json.Unmarshal([]byte(result.Data), &payload); err != nil {
		t.Fatalf("decode VPN stop result: %v", err)
	}
	if payload.State != model.VPNStateStopped || payload.StoppedAtUnix == 0 {
		t.Fatalf("unexpected stop result: %#v", payload)
	}
	if _, ok := vpnManager.Get(start.SessionID); ok {
		t.Fatal("stopped VPN session must be removed from local tracking")
	}
}

func TestHandleVPNControlStatusReportsRunningSession(t *testing.T) {
	resetVPNManagerForTest(t)

	start := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-1",
		Token:         "session-token",
		ListenHTTP:    "127.0.0.1:8088",
		ListenSOCKS:   "127.0.0.1:1080",
	}
	if result := runVPNControlTaskForTest(t, start); !result.Successful {
		t.Fatalf("start should succeed before status, got %q", result.Data)
	}

	status := start
	status.Action = model.VPNActionStatus
	result := runVPNControlTaskForTest(t, status)
	if !result.Successful {
		t.Fatalf("expected successful status result, got %q", result.Data)
	}
	var payload model.VPNControlResult
	if err := json.Unmarshal([]byte(result.Data), &payload); err != nil {
		t.Fatalf("decode VPN status result: %v", err)
	}
	if payload.State != model.VPNStateRunning || payload.LocalHTTP != start.ListenHTTP || payload.LocalSOCKS != start.ListenSOCKS {
		t.Fatalf("unexpected status result: %#v", payload)
	}
}

func TestHandleVPNControlStatusAllowsMissingTokenForRecoveryQueries(t *testing.T) {
	resetVPNManagerForTest(t)

	start := model.VPNControlRequest{
		SessionID:     "vpn-session-recovery-status",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-recovery-status",
		Token:         "session-token",
		ListenHTTP:    "127.0.0.1:8088",
	}
	if result := runVPNControlTaskForTest(t, start); !result.Successful {
		t.Fatalf("start should succeed before status, got %q", result.Data)
	}

	status := start
	status.Action = model.VPNActionStatus
	status.Token = ""
	result := runVPNControlTaskForTest(t, status)
	if !result.Successful {
		t.Fatalf("status without token must be allowed for dashboard recovery, got %q", result.Data)
	}
	var payload model.VPNControlResult
	if err := json.Unmarshal([]byte(result.Data), &payload); err != nil {
		t.Fatalf("decode VPN status result: %v", err)
	}
	if payload.State != model.VPNStateRunning || payload.SessionID != start.SessionID {
		t.Fatalf("unexpected recovery status result: %#v", payload)
	}
}

func TestHandleVPNControlRecoveryActionsValidateRoleAndRelayMode(t *testing.T) {
	resetVPNManagerForTest(t)

	req := model.VPNControlRequest{
		SessionID: "vpn-session-invalid-status-role",
		Action:    model.VPNActionStatus,
		Role:      "attacker",
		RelayMode: model.VPNRelayModeDashboard,
	}
	result := runVPNControlTaskForTest(t, req)

	if result.Successful {
		t.Fatalf("status with invalid role must fail validation, got %q", result.Data)
	}
	var payload model.VPNControlResult
	if err := json.Unmarshal([]byte(result.Data), &payload); err != nil {
		t.Fatalf("invalid status validation payload: %v", err)
	}
	if payload.State != model.VPNStateFailed || !strings.Contains(payload.LastError, `unsupported VPN role "attacker"`) {
		t.Fatalf("status validation error must mention invalid role, got %#v", payload)
	}
}

func TestAgentVPNStreamsIncrementalSidecarLogs(t *testing.T) {
	resetVPNManagerForTest(t)
	results := make(chan *pb.TaskResult, 4)
	vpnManager.SetTaskResultSender(func(result *pb.TaskResult) error {
		results <- result
		return nil
	})
	vpnManager.logPollInterval = 10 * time.Millisecond

	start := model.VPNControlRequest{
		SessionID:     "vpn-session-logs",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-logs",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
	}
	if result := runVPNControlTaskForTest(t, start); !result.Successful {
		t.Fatalf("start should succeed before log streaming, got %q", result.Data)
	}
	session, ok := vpnManager.Get(start.SessionID)
	if !ok {
		t.Fatal("started VPN session must be tracked locally")
	}
	if err := os.WriteFile(session.LogPath, []byte("first log line\n"), 0600); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-results:
		var payload model.VPNControlResult
		if err := json.Unmarshal([]byte(result.GetData()), &payload); err != nil {
			t.Fatalf("decode streamed VPN log result: %v", err)
		}
		if result.GetType() != model.TaskTypeVPNControl || payload.SessionID != start.SessionID || payload.Action != model.VPNActionLogs {
			t.Fatalf("unexpected streamed log result: type=%d payload=%+v", result.GetType(), payload)
		}
		if len(payload.Logs) != 1 || payload.Logs[0] != "first log line" {
			t.Fatalf("expected incremental log line, got %#v", payload.Logs)
		}
	case <-time.After(time.Second):
		t.Fatal("expected VPN sidecar log line to be streamed")
	}
}

func TestHandleVPNControlRestartReplacesTrackedSession(t *testing.T) {
	resetVPNManagerForTest(t)

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-1",
		Action:        model.VPNActionRestart,
		Role:          model.VPNRoleExit,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-exit-stream-1",
		Token:         "session-token",
	}
	result := runVPNControlTaskForTest(t, req)
	if !result.Successful {
		t.Fatalf("expected successful restart result, got %q", result.Data)
	}
	session, ok := vpnManager.Get(req.SessionID)
	if !ok {
		t.Fatal("restart must leave a running tracked session")
	}
	if session.Request.Action != model.VPNActionRestart || session.State != model.VPNStateRunning {
		t.Fatalf("unexpected restarted session: %#v", session)
	}
}

func TestHandleVPNControlRestartRestoresExistingEntrySession(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{}
	vpnManager.systemProxyManager = proxy
	processes := make([]*recordingVPNSidecarProcess, 0, 2)
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		process := &recordingVPNSidecarProcess{}
		processes = append(processes, process)
		return process, nil
	}
	streams := make([]*recordingVPNIOStream, 0, 2)
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		stream := &recordingVPNIOStream{}
		streams = append(streams, stream)
		return stream, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-restart-entry",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-restart-entry",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	if result := runVPNControlTaskForTest(t, req); !result.Successful {
		t.Fatalf("start should succeed before restart, got %q", result.Data)
	}
	if proxy.applyCalls != 1 {
		t.Fatalf("start must apply system proxy once, got %d", proxy.applyCalls)
	}
	if proxy.inspectCalls != 1 || proxy.clearCalls != 1 {
		t.Fatalf("start must inspect and clear foreign system proxy once, got %#v", proxy)
	}

	restart := req
	restart.Action = model.VPNActionRestart
	result := runVPNControlTaskForTest(t, restart)
	if !result.Successful {
		t.Fatalf("restart should succeed, got %q", result.Data)
	}
	if proxy.restoreCalls != 1 {
		t.Fatalf("restart must restore old system proxy before new start, got %d", proxy.restoreCalls)
	}
	if proxy.clearCalls != 3 {
		t.Fatalf("restart must clear foreign system proxy before apply and old proxy before restore, got %d", proxy.clearCalls)
	}
	if proxy.applyCalls != 2 {
		t.Fatalf("restart must apply system proxy for new session, got %d", proxy.applyCalls)
	}
	if got, want := strings.Join(proxy.operations, ","), "inspect,clear,apply,clear,restore,inspect,clear,apply"; got != want {
		t.Fatalf("restart system proxy operations mismatch: want %s got %s", want, got)
	}
	if len(processes) != 2 {
		t.Fatalf("restart must create a fresh sidecar process, got %d", len(processes))
	}
	if processes[0].stopCalls != 1 {
		t.Fatalf("restart must stop the old sidecar once, got %#v", processes[0])
	}
	if len(streams) != 2 {
		t.Fatalf("restart must create a fresh relay stream, got %d", len(streams))
	}
	streams[0].mu.Lock()
	oldStreamClosed := streams[0].closed
	streams[0].mu.Unlock()
	if !oldStreamClosed {
		t.Fatal("restart must close the old relay stream")
	}
	session, ok := vpnManager.Get(req.SessionID)
	if !ok {
		t.Fatal("restart must leave a running tracked session")
	}
	if session.Request.Action != model.VPNActionRestart || session.State != model.VPNStateRunning {
		t.Fatalf("unexpected restarted session: %#v", session)
	}
}

func TestHandleVPNControlRestartRejectsWhenOldSystemProxyRestoreFails(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{restoreErr: errors.New("proxy restore failed")}
	vpnManager.systemProxyManager = proxy
	processes := make([]*recordingVPNSidecarProcess, 0, 2)
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		process := &recordingVPNSidecarProcess{}
		processes = append(processes, process)
		return process, nil
	}
	streams := make([]*recordingVPNIOStream, 0, 2)
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		stream := &recordingVPNIOStream{}
		streams = append(streams, stream)
		return stream, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-restart-proxy-restore-fails",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-restart-proxy-restore-fails",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	if result := runVPNControlTaskForTest(t, req); !result.Successful {
		t.Fatalf("start should succeed before restart, got %q", result.Data)
	}

	restart := req
	restart.Action = model.VPNActionRestart
	result := runVPNControlTaskForTest(t, restart)
	if result.Successful {
		t.Fatalf("restart must fail when old system proxy restore fails, got %q", result.Data)
	}
	if !strings.Contains(result.Data, "proxy restore failed") {
		t.Fatalf("restart failure must include restore error, got %q", result.Data)
	}
	var failurePayload model.VPNControlResult
	if err := json.Unmarshal([]byte(result.Data), &failurePayload); err != nil {
		t.Fatalf("restart failure payload must be valid JSON: %v", err)
	}
	logs := strings.Join(failurePayload.Logs, "\n")
	if !strings.Contains(logs, "system_proxy_restore=failed: proxy restore failed") {
		t.Fatalf("restart failure must include system proxy cleanup log, got %#v", failurePayload.Logs)
	}
	if !strings.Contains(logs, "state=kept-for-restore-retry") {
		t.Fatalf("restart failure must keep recovery state for restore retry, got %#v", failurePayload.Logs)
	}
	if len(processes) != 1 {
		t.Fatalf("failed restart must not create a new sidecar, got %d", len(processes))
	}
	if len(streams) != 1 {
		t.Fatalf("failed restart must not create a new relay stream, got %d", len(streams))
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed restart must not keep an unsafe running session in memory")
	}
}

func TestHandleVPNControlRestartRejectsWhenOldTunRestoreFails(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{restoreErr: errors.New("tun restore failed")}
	vpnManager.tunManager = tun
	processes := make([]*recordingVPNSidecarProcess, 0, 2)
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		process := &recordingVPNSidecarProcess{}
		processes = append(processes, process)
		return process, nil
	}
	streams := make([]*recordingVPNIOStream, 0, 2)
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		stream := &recordingVPNIOStream{}
		streams = append(streams, stream)
		return stream, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-restart-tun-restore-fails",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-restart-tun-restore-fails",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	if result := runVPNControlTaskForTest(t, req); !result.Successful {
		t.Fatalf("start should succeed before restart, got %q", result.Data)
	}

	restart := req
	restart.Action = model.VPNActionRestart
	result := runVPNControlTaskForTest(t, restart)
	if result.Successful {
		t.Fatalf("restart must fail when old TUN restore fails, got %q", result.Data)
	}
	if !strings.Contains(result.Data, "tun restore failed") {
		t.Fatalf("restart failure must include restore error, got %q", result.Data)
	}
	var failurePayload model.VPNControlResult
	if err := json.Unmarshal([]byte(result.Data), &failurePayload); err != nil {
		t.Fatalf("restart failure payload must be valid JSON: %v", err)
	}
	logs := strings.Join(failurePayload.Logs, "\n")
	if !strings.Contains(logs, "tun_restore=failed: tun restore failed") {
		t.Fatalf("restart failure must include TUN cleanup log, got %#v", failurePayload.Logs)
	}
	if !strings.Contains(logs, "state=kept-for-restore-retry") {
		t.Fatalf("restart failure must keep recovery state for restore retry, got %#v", failurePayload.Logs)
	}
	if len(processes) != 1 {
		t.Fatalf("failed restart must not create a new sidecar, got %d", len(processes))
	}
	if len(streams) != 1 {
		t.Fatalf("failed restart must not create a new relay stream, got %d", len(streams))
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed restart must not keep an unsafe running session in memory")
	}
}

func TestAgentVPNStartReplacesExistingSessionSafely(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{}
	vpnManager.systemProxyManager = proxy
	processes := make([]*recordingVPNSidecarProcess, 0, 2)
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		process := &recordingVPNSidecarProcess{}
		processes = append(processes, process)
		return process, nil
	}
	streams := make([]*recordingVPNIOStream, 0, 2)
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		stream := &recordingVPNIOStream{}
		streams = append(streams, stream)
		return stream, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-duplicate-start",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-duplicate-start",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	if result := runVPNControlTaskForTest(t, req); !result.Successful {
		t.Fatalf("start should succeed before duplicate start, got %q", result.Data)
	}
	if result := runVPNControlTaskForTest(t, req); !result.Successful {
		t.Fatalf("duplicate start should succeed after safely replacing old session, got %q", result.Data)
	}

	if proxy.restoreCalls != 1 {
		t.Fatalf("duplicate start must restore old system proxy before replacement, got %d", proxy.restoreCalls)
	}
	if proxy.applyCalls != 2 {
		t.Fatalf("duplicate start must apply system proxy for the replacement session, got %d", proxy.applyCalls)
	}
	if len(processes) != 2 {
		t.Fatalf("duplicate start must create a fresh sidecar process, got %d", len(processes))
	}
	if processes[0].stopCalls != 1 {
		t.Fatalf("duplicate start must stop the old sidecar once, got %#v", processes[0])
	}
	if len(streams) != 2 {
		t.Fatalf("duplicate start must create a fresh relay stream, got %d", len(streams))
	}
	streams[0].mu.Lock()
	oldStreamClosed := streams[0].closed
	streams[0].mu.Unlock()
	if !oldStreamClosed {
		t.Fatal("duplicate start must close the old relay stream")
	}
	session, ok := vpnManager.Get(req.SessionID)
	if !ok {
		t.Fatal("duplicate start must leave a running tracked session")
	}
	if session.State != model.VPNStateRunning || session.sidecar == nil {
		t.Fatalf("unexpected replacement session: %#v", session)
	}
}

func TestAgentVPNStartRejectsReplacementWhenOldTunRestoreFails(t *testing.T) {
	resetVPNManagerForTest(t)
	tun := &recordingVPNTunManager{restoreErr: errors.New("restore failed")}
	vpnManager.tunManager = tun
	processes := make([]*recordingVPNSidecarProcess, 0, 2)
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		process := &recordingVPNSidecarProcess{}
		processes = append(processes, process)
		return process, nil
	}
	streams := make([]*recordingVPNIOStream, 0, 2)
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		stream := &recordingVPNIOStream{}
		streams = append(streams, stream)
		return stream, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-duplicate-tun-start",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeTunSplit,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-duplicate-tun-start",
		Token:         "session-token",
		TunName:       "nezha-vpn",
	}
	if result := runVPNControlTaskForTest(t, req); !result.Successful {
		t.Fatalf("start should succeed before duplicate TUN start, got %q", result.Data)
	}
	result := runVPNControlTaskForTest(t, req)
	if result.Successful {
		t.Fatalf("duplicate TUN start must fail when old TUN restore fails, got %q", result.Data)
	}
	if !strings.Contains(result.Data, "restore failed") {
		t.Fatalf("duplicate TUN start error must include restore failure, got %q", result.Data)
	}
	var failurePayload model.VPNControlResult
	if err := json.Unmarshal([]byte(result.Data), &failurePayload); err != nil {
		t.Fatalf("duplicate TUN start failure payload must be valid JSON: %v", err)
	}
	logs := strings.Join(failurePayload.Logs, "\n")
	if !strings.Contains(logs, "tun_restore=failed: restore failed") {
		t.Fatalf("duplicate TUN start failure must include TUN cleanup log, got %#v", failurePayload.Logs)
	}
	if !strings.Contains(logs, "state=kept-for-restore-retry") {
		t.Fatalf("duplicate TUN start failure must keep recovery state for restore retry, got %#v", failurePayload.Logs)
	}
	if len(processes) != 1 {
		t.Fatalf("failed TUN replacement must not create a new sidecar, got %d", len(processes))
	}
	if len(streams) != 1 {
		t.Fatalf("failed TUN replacement must not create a new relay stream, got %d", len(streams))
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed TUN replacement must not keep an unsafe running session in memory")
	}
}

func TestAgentVPNStartRejectsReplacementWhenOldSystemProxyRestoreFails(t *testing.T) {
	resetVPNManagerForTest(t)
	proxy := &recordingVPNSystemProxyManager{restoreErr: errors.New("proxy restore failed")}
	vpnManager.systemProxyManager = proxy
	processes := make([]*recordingVPNSidecarProcess, 0, 2)
	vpnManager.sidecarRunner = func(ctx context.Context, spec vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		process := &recordingVPNSidecarProcess{}
		processes = append(processes, process)
		return process, nil
	}
	streams := make([]*recordingVPNIOStream, 0, 2)
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		stream := &recordingVPNIOStream{}
		streams = append(streams, stream)
		return stream, nil
	}

	req := model.VPNControlRequest{
		SessionID:     "vpn-session-duplicate-proxy-start",
		Action:        model.VPNActionStart,
		Role:          model.VPNRoleEntry,
		Mode:          model.VPNModeSystemProxy,
		RelayMode:     model.VPNRelayModeDashboard,
		RelayStreamID: "vpn-entry-stream-duplicate-proxy-start",
		Token:         "session-token",
		ListenSOCKS:   "127.0.0.1:1080",
		Extra: map[string]string{
			"set_system_proxy": "true",
		},
	}
	req = withTestVPNBridgeAddress(t, req)
	if result := runVPNControlTaskForTest(t, req); !result.Successful {
		t.Fatalf("start should succeed before duplicate system proxy start, got %q", result.Data)
	}
	result := runVPNControlTaskForTest(t, req)
	if result.Successful {
		t.Fatalf("duplicate system proxy start must fail when old system proxy restore fails, got %q", result.Data)
	}
	if !strings.Contains(result.Data, "proxy restore failed") {
		t.Fatalf("duplicate system proxy start error must include restore failure, got %q", result.Data)
	}
	var failurePayload model.VPNControlResult
	if err := json.Unmarshal([]byte(result.Data), &failurePayload); err != nil {
		t.Fatalf("duplicate system proxy start failure payload must be valid JSON: %v", err)
	}
	logs := strings.Join(failurePayload.Logs, "\n")
	if !strings.Contains(logs, "system_proxy_restore=failed: proxy restore failed") {
		t.Fatalf("duplicate system proxy start failure must include system proxy cleanup log, got %#v", failurePayload.Logs)
	}
	if !strings.Contains(logs, "state=kept-for-restore-retry") {
		t.Fatalf("duplicate system proxy start failure must keep recovery state for restore retry, got %#v", failurePayload.Logs)
	}
	if proxy.restoreCalls != 1 {
		t.Fatalf("failed proxy replacement must try restoring old system proxy once, got %d", proxy.restoreCalls)
	}
	if proxy.applyCalls != 1 {
		t.Fatalf("failed proxy replacement must not apply system proxy for a new session, got %d", proxy.applyCalls)
	}
	if len(processes) != 1 {
		t.Fatalf("failed proxy replacement must not create a new sidecar, got %d", len(processes))
	}
	if len(streams) != 1 {
		t.Fatalf("failed proxy replacement must not create a new relay stream, got %d", len(streams))
	}
	if _, ok := vpnManager.Get(req.SessionID); ok {
		t.Fatal("failed proxy replacement must not keep an unsafe running session in memory")
	}
}

func TestHandleVPNControlRejectsMalformedPayload(t *testing.T) {
	resetVPNManagerForTest(t)

	result := doTask(&pb.Task{
		Id:   9,
		Type: model.TaskTypeVPNControl,
		Data: "{",
	})
	if result == nil {
		t.Fatal("malformed VPN control task must return a TaskResult")
	}
	if result.Successful {
		t.Fatal("malformed VPN control task must not be successful")
	}
	if !strings.Contains(result.Data, "invalid VPN control request") {
		t.Fatalf("unexpected error message: %q", result.Data)
	}
}

func runVPNControlTaskForTest(t *testing.T, req model.VPNControlRequest) *pb.TaskResult {
	t.Helper()

	req = withTestVPNBridgeAddress(t, req)
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	result := doTask(&pb.Task{
		Id:   7,
		Type: model.TaskTypeVPNControl,
		Data: string(data),
	})
	if result == nil {
		t.Fatal("VPN control task must return a TaskResult")
	}
	return result
}

func withTestVPNBridgeAddress(t *testing.T, req model.VPNControlRequest) model.VPNControlRequest {
	t.Helper()

	if req.Extra == nil {
		req.Extra = make(map[string]string)
	}
	switch req.Role {
	case model.VPNRoleEntry:
		if strings.TrimSpace(req.Extra["bridge_addr"]) == "" {
			req.Extra["bridge_addr"] = freeLocalTCPAddrForTest(t)
		}
	case model.VPNRoleExit:
		if strings.TrimSpace(req.Extra["bridge_listen"]) == "" {
			req.Extra["bridge_listen"] = freeLocalTCPAddrForTest(t)
		}
	}
	return req
}

func resetVPNManagerForTest(t *testing.T) {
	t.Helper()

	original := vpnManager
	originalConfig := agentConfig
	vpnManager = NewAgentVPNManager()
	agentConfig = model.AgentConfig{VPNAllowSystemProxy: true, VPNAllowTun: true}
	vpnManager.workDir = t.TempDir()
	vpnManager.corePath = filepath.Join(vpnManager.workDir, "core", "sing-box")
	if err := os.MkdirAll(filepath.Dir(vpnManager.corePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vpnManager.corePath, []byte("test-core"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vpnWintunTargetPath(vpnManager.effectiveWorkDir()), []byte("test-wintun"), 0600); err != nil {
		t.Fatal(err)
	}
	vpnManager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		return &recordingVPNIOStream{}, nil
	}
	vpnManager.sidecarRunner = func(context.Context, vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return &recordingVPNSidecarProcess{}, nil
	}
	t.Cleanup(func() {
		vpnManager = original
		agentConfig = originalConfig
	})
}

func newTestAgentVPNManagerWithStream(t *testing.T, stream vpnIOStream) *AgentVPNManager {
	t.Helper()

	manager := NewAgentVPNManager()
	manager.workDir = t.TempDir()
	manager.corePath = filepath.Join(manager.workDir, "core", "sing-box")
	if err := os.MkdirAll(filepath.Dir(manager.corePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.corePath, []byte("test-core"), 0600); err != nil {
		t.Fatal(err)
	}
	manager.ioStreamFactory = func(context.Context) (vpnIOStream, error) {
		return stream, nil
	}
	manager.sidecarRunner = func(context.Context, vpnSidecarStartSpec) (vpnSidecarProcess, error) {
		return &recordingVPNSidecarProcess{}, nil
	}
	return manager
}

type recordingVPNIOStream struct {
	mu         sync.Mutex
	sent       [][]byte
	closed     bool
	recvCh     chan error
	recvFrames chan []byte
}

func (s *recordingVPNIOStream) Send(data *pb.IOStreamData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sent = append(s.sent, append([]byte(nil), data.GetData()...))
	return nil
}

func (s *recordingVPNIOStream) Recv() (*pb.IOStreamData, error) {
	if s.recvFrames != nil {
		data, ok := <-s.recvFrames
		if !ok {
			return nil, io.EOF
		}
		return &pb.IOStreamData{Data: data}, nil
	}
	if s.recvCh != nil {
		err := <-s.recvCh
		if err == nil {
			return &pb.IOStreamData{}, nil
		}
		return nil, err
	}
	return nil, io.EOF
}

func (s *recordingVPNIOStream) CloseSend() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	return nil
}

func (s *recordingVPNIOStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (s *recordingVPNIOStream) Trailer() metadata.MD         { return metadata.MD{} }
func (s *recordingVPNIOStream) Context() context.Context     { return context.Background() }
func (s *recordingVPNIOStream) SendMsg(any) error            { return nil }
func (s *recordingVPNIOStream) RecvMsg(any) error            { return io.EOF }

type fakeDashboardVPNRelay struct {
	entryID string
	exitID  string
	entry   *fakeDashboardVPNRelayStream
	exit    *fakeDashboardVPNRelayStream

	mu            sync.Mutex
	entryAttached bool
	exitAttached  bool
	entryBytes    int
	exitBytes     int
	readyOnce     sync.Once
	ready         chan struct{}
}

type fakeDashboardVPNRelayStream struct {
	relay      *fakeDashboardVPNRelay
	expectedID string
	in         chan *pb.IOStreamData
	closed     chan struct{}
	closeOnce  sync.Once
}

func newFakeDashboardVPNRelay(entryID string, exitID string) *fakeDashboardVPNRelay {
	relay := &fakeDashboardVPNRelay{
		entryID: entryID,
		exitID:  exitID,
		ready:   make(chan struct{}),
	}
	relay.entry = &fakeDashboardVPNRelayStream{
		relay:      relay,
		expectedID: entryID,
		in:         make(chan *pb.IOStreamData, 64),
		closed:     make(chan struct{}),
	}
	relay.exit = &fakeDashboardVPNRelayStream{
		relay:      relay,
		expectedID: exitID,
		in:         make(chan *pb.IOStreamData, 64),
		closed:     make(chan struct{}),
	}
	return relay
}

func (r *fakeDashboardVPNRelay) entryStream() vpnIOStream {
	return r.entry
}

func (r *fakeDashboardVPNRelay) exitStream() vpnIOStream {
	return r.exit
}

func (r *fakeDashboardVPNRelay) attach(stream *fakeDashboardVPNRelayStream, payload []byte) error {
	streamID := string(payload[4:])
	if streamID != stream.expectedID {
		return io.ErrUnexpectedEOF
	}

	r.mu.Lock()
	if streamID == r.entryID {
		r.entryAttached = true
	} else if streamID == r.exitID {
		r.exitAttached = true
	}
	entryAttached := r.entryAttached
	exitAttached := r.exitAttached
	r.mu.Unlock()

	if entryAttached && exitAttached {
		r.readyOnce.Do(func() { close(r.ready) })
	}
	return nil
}

func (r *fakeDashboardVPNRelay) forward(stream *fakeDashboardVPNRelayStream, payload []byte) error {
	select {
	case <-r.ready:
	case <-time.After(time.Second):
		return io.ErrClosedPipe
	}

	var peer *fakeDashboardVPNRelayStream
	r.mu.Lock()
	if stream == r.entry {
		r.entryBytes += len(payload)
		peer = r.exit
	} else {
		r.exitBytes += len(payload)
		peer = r.entry
	}
	r.mu.Unlock()

	select {
	case <-stream.closed:
		return io.ErrClosedPipe
	case <-peer.closed:
		return io.ErrClosedPipe
	case peer.in <- &pb.IOStreamData{Data: append([]byte(nil), payload...)}:
		return nil
	case <-time.After(time.Second):
		return io.ErrClosedPipe
	}
}

func (r *fakeDashboardVPNRelay) sawTrafficBothWays() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.entryBytes > 0 && r.exitBytes > 0
}

func (s *fakeDashboardVPNRelayStream) Send(data *pb.IOStreamData) error {
	payload := append([]byte(nil), data.GetData()...)
	if len(payload) >= 4 && payload[0] == 0xff && payload[1] == 0x05 && payload[2] == 0xff && payload[3] == 0x05 {
		return s.relay.attach(s, payload)
	}
	return s.relay.forward(s, payload)
}

func (s *fakeDashboardVPNRelayStream) Recv() (*pb.IOStreamData, error) {
	select {
	case data := <-s.in:
		return data, nil
	case <-s.closed:
		return nil, io.ErrClosedPipe
	case <-time.After(3 * time.Second):
		return nil, io.ErrClosedPipe
	}
}

func (s *fakeDashboardVPNRelayStream) CloseSend() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func waitForRecordingVPNStreamClosed(t *testing.T, stream *recordingVPNIOStream) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		stream.mu.Lock()
		closed := stream.closed
		stream.mu.Unlock()
		if closed {
			return
		}
		select {
		case <-deadline:
			t.Fatal("test stream must close after fake Recv returns")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func waitForRecordingVPNStreamSentFrame(t *testing.T, stream *recordingVPNIOStream, want string) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		stream.mu.Lock()
		for _, sent := range stream.sent {
			if string(sent) == want {
				stream.mu.Unlock()
				return
			}
		}
		stream.mu.Unlock()
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for VPN stream frame %q", want)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func waitForRecordingVPNStreamSentMuxPayload(t *testing.T, stream *recordingVPNIOStream, want string) {
	t.Helper()

	deadline := time.After(time.Second)
	var consumed int
	var raw []byte
	for {
		stream.mu.Lock()
		sent := append([][]byte(nil), stream.sent...)
		stream.mu.Unlock()
		for consumed < len(sent) {
			raw = append(raw, sent[consumed]...)
			consumed++
			if vpnMuxPayloadExists(raw, want) {
				return
			}
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for VPN mux payload %q", want)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func waitForRecordingVPNStreamSentBytesContaining(t *testing.T, stream *recordingVPNIOStream, want string) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		stream.mu.Lock()
		sent := append([][]byte(nil), stream.sent...)
		stream.mu.Unlock()
		for _, raw := range sent {
			if strings.Contains(string(raw), want) {
				return
			}
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for VPN stream bytes containing %q", want)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}
