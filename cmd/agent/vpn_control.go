package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

type AgentVPNSession struct {
	Request              model.VPNControlRequest
	State                string
	StartedAt            time.Time
	cancel               context.CancelFunc
	relay                vpnIOStream
	sidecar              *AgentVPNSidecar
	bridge               *AgentVPNBridge
	ConfigPath           string
	LogPath              string
	CorePath             string
	CoreCleanupDir       string
	StatePath            string
	LastError            string
	sidecarPID           int
	tunSnapshotPath      string
	systemProxyApplied   bool
	coreTemporary        bool
	sharedExitRuntimeKey string
}

type AgentVPNManager struct {
	mu                 sync.Mutex
	sessions           map[string]*AgentVPNSession
	ioStreamFactory    func(context.Context) (vpnIOStream, error)
	sidecarRunner      vpnSidecarRunner
	httpClient         vpnHTTPClient
	directRelay        *AgentVPNDirectManager
	taskResultSender   func(*pb.TaskResult) error
	systemProxyManager vpnSystemProxyManager
	tunManager         vpnTunManager
	tunHealthProbe     func(context.Context, model.VPNControlRequest) error
	egressProbe        func(context.Context, model.VPNControlRequest) []string
	sessionStateWriter func(string, agentVPNSessionState) error
	staleSidecarKiller func(int) error
	workDir            string
	corePath           string
	logPollInterval    time.Duration
	sharedExitRuntimes map[string]*agentVPNSharedExitRuntime
}

type agentVPNSharedExitRuntime struct {
	Key            string
	Request        model.VPNControlRequest
	sidecar        *AgentVPNSidecar
	CorePath       string
	CoreCleanupDir string
	sidecarPID     int
	stopping       bool
	refs           map[string]struct{}
}

var vpnRuleSetStatusFiles = []string{"manifest.json", "geosite-cn.srs", "geoip-cn.srs"}

const (
	defaultVPNRulesDownloadBaseURL   = "https://github.com/dagve11/sb-rules/releases/latest/download"
	defaultVPNRulesCNDownloadBaseURL = "https://gitee.com/AGZZY11/sb-rules/raw/main/dist"
)

var vpnManager = NewAgentVPNManager()

func NewAgentVPNManager() *AgentVPNManager {
	return &AgentVPNManager{
		sessions:           make(map[string]*AgentVPNSession),
		ioStreamFactory:    defaultVPNIOStreamFactory,
		sidecarRunner:      defaultVPNSidecarRunner,
		httpClient:         httpClient,
		directRelay:        defaultAgentVPNDirectManager,
		systemProxyManager: defaultVPNSystemProxyManager(),
		tunManager:         defaultVPNTunManager(),
		tunHealthProbe:     defaultVPNTunHealthProbe,
		egressProbe:        defaultVPNEgressProbe,
		sessionStateWriter: writeAgentVPNSessionState,
		staleSidecarKiller: killStaleVPNSidecarProcess,
		workDir:            defaultVPNWorkDir(),
		logPollInterval:    2 * time.Second,
		sharedExitRuntimes: make(map[string]*agentVPNSharedExitRuntime),
	}
}

type vpnIOStream interface {
	Send(*pb.IOStreamData) error
	Recv() (*pb.IOStreamData, error)
	CloseSend() error
}

type agentVPNSessionState struct {
	Version            int       `json:"version"`
	SessionID          string    `json:"session_id"`
	Role               string    `json:"role"`
	Mode               string    `json:"mode"`
	State              string    `json:"state"`
	ConfigPath         string    `json:"config_path,omitempty"`
	LogPath            string    `json:"log_path,omitempty"`
	CorePath           string    `json:"core_path,omitempty"`
	CoreCleanupDir     string    `json:"core_cleanup_dir,omitempty"`
	CoreTemporary      bool      `json:"core_temporary,omitempty"`
	TunName            string    `json:"tun_name,omitempty"`
	DNSServer          string    `json:"dns_server,omitempty"`
	SidecarPID         int       `json:"sidecar_pid,omitempty"`
	SystemProxyApplied bool      `json:"system_proxy_applied,omitempty"`
	TunSnapshotPath    string    `json:"tun_snapshot_path,omitempty"`
	StartedAt          time.Time `json:"started_at,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
}

func defaultVPNIOStreamFactory(ctx context.Context) (vpnIOStream, error) {
	if client == nil {
		return nil, errors.New("dashboard client is not connected")
	}
	return client.IOStream(ctx)
}

func (m *AgentVPNManager) Start(req model.VPNControlRequest) (model.VPNControlResult, error) {
	if err := validateVPNControlRequest(req); err != nil {
		return vpnFailedResult(req, err), err
	}
	if err := vpnDisabledByConfig(); err != nil {
		return vpnFailedResult(req, err), err
	}
	if err := vpnModeAllowedByConfig(req.Mode); err != nil {
		return vpnFailedResult(req, err), err
	}
	if err := m.preflightTun(req); err != nil {
		return vpnFailedResult(req, err), err
	}
	ensureVPNRuntimeControlExtra(&req)
	cleanupLogs, err := m.stopExistingSessionBeforeStart(req)
	if err != nil {
		return vpnFailedResultWithLogs(req, err, cleanupLogs), err
	}

	now := time.Now()
	sessionCtx, sessionCancel := context.WithCancel(context.Background())
	session := &AgentVPNSession{
		Request:   req,
		State:     model.VPNStateRunning,
		StartedAt: now,
		cancel:    sessionCancel,
	}
	workDir := m.effectiveWorkDir()
	session.StatePath = vpnSessionStatePath(workDir, req.SessionID)
	if err := m.snapshotSessionTun(session); err != nil {
		sessionCancel()
		return vpnFailedResult(req, err), err
	}
	coreTarget := m.effectiveCoreTarget(req)
	session.CorePath = coreTarget.Path
	session.CoreCleanupDir = coreTarget.CleanupDir
	session.coreTemporary = coreTarget.Temporary
	var sidecar *AgentVPNSidecar
	if req.Role == model.VPNRoleExit {
		corePath, sharedSidecar, sharedKey, err := m.acquireSharedExitRuntime(context.Background(), &req, workDir, coreTarget)
		if err != nil {
			cleanupLogs := m.restoreSessionTunForStartupFailure(session)
			sessionCancel()
			return vpnFailedResultWithLogs(req, err, cleanupLogs), err
		}
		session.Request = req
		session.CorePath = corePath
		session.sharedExitRuntimeKey = sharedKey
		sidecar = sharedSidecar
	} else {
		corePath, err := prepareVPNCore(context.Background(), req.Core, coreTarget.Path, m.httpClient)
		if err != nil {
			cleanupLogs := m.restoreSessionTunForStartupFailure(session)
			sessionCancel()
			return vpnFailedResultWithLogs(req, err, cleanupLogs), err
		}
		session.CorePath = corePath
	}
	relay, err := m.attachVPNRelay(req)
	if err != nil {
		cleanupLogs := m.restoreSessionTunForStartupFailure(session)
		cleanupLogs = append(cleanupLogs, m.releaseSharedExitRuntime(session)...)
		sessionCancel()
		return vpnFailedResultWithLogs(req, err, cleanupLogs), err
	}
	session.relay = relay
	if req.Role != model.VPNRoleExit {
		sidecar, err = startAgentVPNSidecar(context.Background(), req, workDir, session.CorePath, m.sidecarRunner)
		if err != nil {
			go drainVPNRelayStream(relay)
			cleanupLogs := m.restoreSessionTunForStartupFailure(session)
			sessionCancel()
			err = vpnSidecarStartError(req, err)
			return vpnFailedResultWithLogs(req, err, cleanupLogs), err
		}
	}
	session.sidecar = sidecar
	session.sidecarPID = vpnSidecarPID(sidecar)
	session.ConfigPath, session.LogPath = vpnSidecarMetadata(sidecar)
	bridge, err := startAgentVPNBridge(context.Background(), req, relay)
	if err != nil {
		cleanupLogs := m.restoreSessionTunForStartupFailure(session)
		if session.sharedExitRuntimeKey != "" {
			cleanupLogs = append(cleanupLogs, m.releaseSharedExitRuntime(session)...)
		} else {
			_ = sidecar.Stop()
		}
		go drainVPNRelayStream(relay)
		sessionCancel()
		err = fmt.Errorf("start VPN bridge for session %s role %s: %w", req.SessionID, req.Role, err)
		return vpnFailedResultWithLogs(req, err, cleanupLogs), err
	}
	session.bridge = bridge
	if err := m.probeSessionTunHealth(req); err != nil {
		_ = bridge.Close()
		cleanupLogs := m.restoreSessionTunForStartupFailure(session)
		if session.sharedExitRuntimeKey != "" {
			cleanupLogs = append(cleanupLogs, m.releaseSharedExitRuntime(session)...)
		} else {
			_ = sidecar.Stop()
		}
		_ = relay.CloseSend()
		sessionCancel()
		err = fmt.Errorf("VPN TUN health probe failed for session %s: %w", req.SessionID, err)
		return vpnFailedResultWithLogs(req, err, append(cleanupLogs, fmt.Sprintf("[tun-health] %s rollback=sidecar-stopped,relay-closed", err.Error()))), err
	}
	if shouldApplyVPNSystemProxy(req) {
		if err := m.clearForeignSystemProxyBeforeApply(req); err != nil {
			_ = bridge.Close()
			cleanupLogs := m.restoreSessionTunForStartupFailure(session)
			if session.sharedExitRuntimeKey != "" {
				cleanupLogs = append(cleanupLogs, m.releaseSharedExitRuntime(session)...)
			} else {
				_ = sidecar.Stop()
			}
			_ = relay.CloseSend()
			sessionCancel()
			err = fmt.Errorf("clear foreign VPN system proxy before apply for session %s: %w", req.SessionID, err)
			cleanupLogs = append(cleanupLogs, "[cleanup] system_proxy_clear=failed: "+err.Error())
			cleanupLogs = append(cleanupLogs, "[cleanup] rollback=bridge-closed,sidecar-stopped,relay-closed")
			return vpnFailedResultWithLogs(req, err, cleanupLogs), err
		}
		if err := m.systemProxyManager.Apply(req.ListenHTTP, req.ListenSOCKS); err != nil {
			_ = bridge.Close()
			cleanupLogs := m.restoreSessionTunForStartupFailure(session)
			if session.sharedExitRuntimeKey != "" {
				cleanupLogs = append(cleanupLogs, m.releaseSharedExitRuntime(session)...)
			} else {
				_ = sidecar.Stop()
			}
			_ = relay.CloseSend()
			sessionCancel()
			err = fmt.Errorf("apply VPN system proxy for session %s: %w", req.SessionID, err)
			cleanupLogs = append(cleanupLogs, "[cleanup] rollback=bridge-closed,sidecar-stopped,relay-closed")
			return vpnFailedResultWithLogs(req, err, cleanupLogs), err
		}
		session.systemProxyApplied = true
	}
	if err := m.persistSessionState(session); err != nil {
		cleanupLogs := make([]string, 0, 4)
		systemProxyRestoreErr := m.restoreSessionSystemProxy(session)
		if systemProxyRestoreErr != nil {
			cleanupLogs = append(cleanupLogs, "[cleanup] system_proxy_restore=failed: "+systemProxyRestoreErr.Error())
		} else if shouldApplyVPNSystemProxy(req) {
			cleanupLogs = append(cleanupLogs, "[cleanup] system_proxy_restore=ok")
		}
		_ = bridge.Close()
		if session.sharedExitRuntimeKey != "" {
			cleanupLogs = append(cleanupLogs, m.releaseSharedExitRuntime(session)...)
		} else {
			_ = sidecar.Stop()
		}
		_ = relay.CloseSend()
		tunRestoreErr := m.restoreSessionTun(session)
		if tunRestoreErr != nil {
			cleanupLogs = append(cleanupLogs, "[cleanup] tun_restore=failed: "+tunRestoreErr.Error())
		} else if isVPNTunMode(req.Mode) {
			cleanupLogs = append(cleanupLogs, "[cleanup] tun_restore=ok")
		}
		if systemProxyRestoreErr != nil || tunRestoreErr != nil {
			m.persistSessionRecoveryState(session)
		}
		sessionCancel()
		err = fmt.Errorf("persist VPN session state for session %s: %w", req.SessionID, err)
		cleanupLogs = append(cleanupLogs, "[cleanup] rollback=bridge-closed,sidecar-stopped,relay-closed")
		if systemProxyRestoreErr != nil || tunRestoreErr != nil {
			if strings.TrimSpace(session.StatePath) != "" {
				cleanupLogs = append(cleanupLogs, "[cleanup] state=kept-for-restore-retry path="+session.StatePath)
			}
		}
		return vpnFailedResultWithLogs(req, err, cleanupLogs), err
	}
	logs := m.probeSessionEgress(req)

	m.mu.Lock()
	m.sessions[req.SessionID] = session
	m.mu.Unlock()
	if session.sharedExitRuntimeKey == "" {
		m.watchSidecar(req.SessionID, sidecar)
	}
	if req.RelayMode == model.VPNRelayModeDirect {
		m.watchBridge(req.SessionID, bridge)
	}
	m.watchSidecarLogs(sessionCtx, req.SessionID, session.LogPath)
	if req.RelayMode == model.VPNRelayModeDirect && req.Role == model.VPNRoleEntry {
		m.watchDirectTraffic(sessionCtx, req.SessionID)
	}

	return model.VPNControlResult{
		SessionID:          req.SessionID,
		Action:             req.Action,
		Role:               req.Role,
		State:              model.VPNStateRunning,
		LocalHTTP:          req.ListenHTTP,
		LocalSOCKS:         req.ListenSOCKS,
		TunName:            req.TunName,
		SystemProxyApplied: trackedVPNSystemProxyApplied(req, session),
		Logs:               logs,
		StartedAtUnix:      now.Unix(),
	}, nil
}

func (m *AgentVPNManager) Prepare(req model.VPNControlRequest) (model.VPNControlResult, error) {
	if err := validateVPNControlRequest(req); err != nil {
		return vpnFailedResult(req, err), err
	}
	if err := vpnDisabledByConfig(); err != nil {
		return vpnFailedResult(req, err), err
	}
	if err := vpnModeAllowedByConfig(req.Mode); err != nil {
		return vpnFailedResult(req, err), err
	}

	coreTarget := m.effectiveCoreTarget(req)
	_, statErr := os.Stat(coreTarget.Path)
	corePath, err := prepareVPNCore(context.Background(), req.Core, coreTarget.Path, m.httpClient)
	if err != nil {
		logs := []string{"[core] prepare=failed error=" + err.Error()}
		return vpnFailedResultWithLogs(req, err, logs), err
	}

	status := "reused"
	if errors.Is(statErr, os.ErrNotExist) {
		status = "downloaded"
	} else if statErr != nil {
		status = "ready"
	}
	return model.VPNControlResult{
		SessionID:   req.SessionID,
		Action:      req.Action,
		Role:        req.Role,
		State:       model.VPNStatePrepared,
		CoreVersion: req.Core.Version,
		Logs: []string{
			fmt.Sprintf("[core] prepare=%s path=%s temporary=%t", status, corePath, coreTarget.Temporary),
		},
	}, nil
}

func (m *AgentVPNManager) stopExistingSessionBeforeStart(req model.VPNControlRequest) ([]string, error) {
	sessionID := strings.TrimSpace(req.SessionID)
	m.mu.Lock()
	_, exists := m.sessions[sessionID]
	m.mu.Unlock()
	if !exists {
		return nil, nil
	}
	logs, err := m.stopTrackedSession(model.VPNControlRequest{
		SessionID: sessionID,
		Action:    model.VPNActionStop,
	}, true, false, req.Action == model.VPNActionRestart)
	if err != nil {
		printf("VPN existing session cleanup failed before start %s: %v", sessionID, err)
		return logs, err
	}
	return logs, nil
}

func (m *AgentVPNManager) Stop(req model.VPNControlRequest) (model.VPNControlResult, error) {
	logs, err := m.stopTrackedSession(req, false, false, false)
	if err != nil {
		return vpnFailedResult(req, err), err
	}
	return model.VPNControlResult{
		SessionID:     req.SessionID,
		Action:        req.Action,
		Role:          req.Role,
		State:         model.VPNStateStopped,
		Logs:          logs,
		StoppedAtUnix: time.Now().Unix(),
	}, nil
}

func (m *AgentVPNManager) Cleanup(req model.VPNControlRequest) (model.VPNControlResult, error) {
	logs, err := m.stopTrackedSession(req, false, true, false)
	if err != nil {
		return vpnFailedResult(req, err), err
	}
	return model.VPNControlResult{
		SessionID:     req.SessionID,
		Action:        req.Action,
		Role:          req.Role,
		State:         model.VPNStateStopped,
		Logs:          logs,
		StoppedAtUnix: time.Now().Unix(),
	}, nil
}

func (m *AgentVPNManager) PrepareRules(req model.VPNControlRequest) (model.VPNControlResult, error) {
	if err := validateVPNControlRequest(req); err != nil {
		return vpnFailedResult(req, err), err
	}
	if err := vpnDisabledByConfig(); err != nil {
		return vpnFailedResult(req, err), err
	}
	if err := vpnModeAllowedByConfig(req.Mode); err != nil {
		return vpnFailedResult(req, err), err
	}

	rulesDir := m.effectiveRuleSetDir(req)
	source, err := prepareVPNRuleSet(context.Background(), rulesDir, m.httpClient)
	if err != nil {
		logs := []string{"[rules] prepare=failed error=" + err.Error()}
		return vpnFailedResultWithLogs(req, err, logs), err
	}
	return model.VPNControlResult{
		SessionID:    req.SessionID,
		Action:       req.Action,
		Role:         req.Role,
		State:        model.VPNStatePrepared,
		RulesStatus:  "ready",
		RulesPath:    rulesDir,
		RulesVersion: readVPNRulesManifestVersion(filepath.Join(rulesDir, "manifest.json")),
		Logs: []string{
			fmt.Sprintf("[rules] prepare=downloaded path=%s source=%s", rulesDir, source),
		},
	}, nil
}

func (m *AgentVPNManager) CleanupRules(req model.VPNControlRequest) (model.VPNControlResult, error) {
	if err := validateVPNControlRequest(req); err != nil {
		return vpnFailedResult(req, err), err
	}
	rulesDir := m.effectiveRuleSetDir(req)
	if m.activeRuntimeUsesRules(rulesDir) {
		return model.VPNControlResult{
			SessionID:     req.SessionID,
			Action:        req.Action,
			Role:          req.Role,
			State:         model.VPNStateStopped,
			RulesStatus:   "ready",
			RulesPath:     rulesDir,
			StoppedAtUnix: time.Now().Unix(),
			Logs: []string{
				fmt.Sprintf("[rules] cleanup=skipped path=%s reason=rules-in-use", rulesDir),
			},
		}, nil
	}
	if err := cleanupVPNRuleSet(rulesDir); err != nil {
		logs := []string{"[rules] cleanup=failed error=" + err.Error()}
		return vpnFailedResultWithLogs(req, err, logs), err
	}
	return model.VPNControlResult{
		SessionID:     req.SessionID,
		Action:        req.Action,
		Role:          req.Role,
		State:         model.VPNStateStopped,
		RulesStatus:   "missing",
		RulesPath:     rulesDir,
		StoppedAtUnix: time.Now().Unix(),
		Logs: []string{
			fmt.Sprintf("[rules] cleanup=ok path=%s", rulesDir),
		},
	}, nil
}

func (m *AgentVPNManager) stopTrackedSession(req model.VPNControlRequest, failOnTunRestore bool, cleanupCore bool, clearSystemProxyBeforeRestore bool) ([]string, error) {
	if strings.TrimSpace(req.SessionID) == "" {
		return nil, errors.New("session_id is required")
	}
	logs := make([]string, 0, 3)

	m.mu.Lock()
	session := m.sessions[req.SessionID]
	delete(m.sessions, req.SessionID)
	m.mu.Unlock()
	if session == nil {
		if recovered, ok := m.recoverSessionFromState(req); ok {
			session = recovered
			logs = append(logs, "[cleanup] state=recovered path="+session.StatePath)
		}
	}
	if session != nil && session.cancel != nil {
		session.cancel()
	}
	systemProxyWasApplied := session != nil && session.systemProxyApplied
	var systemProxyRestoreErr error
	if clearSystemProxyBeforeRestore && systemProxyWasApplied {
		if clearErr := m.clearSessionSystemProxy(); clearErr != nil {
			systemProxyRestoreErr = fmt.Errorf("clear VPN system proxy before restore for session %s: %w", req.SessionID, clearErr)
			logs = append(logs, "[cleanup] system_proxy_clear=failed: "+clearErr.Error())
		} else {
			logs = append(logs, "[cleanup] system_proxy_clear=ok")
		}
	}
	if systemProxyRestoreErr == nil {
		systemProxyRestoreErr = m.restoreSessionSystemProxy(session)
		if systemProxyRestoreErr != nil {
			logs = append(logs, "[cleanup] system_proxy_restore=failed: "+systemProxyRestoreErr.Error())
		} else if systemProxyWasApplied {
			logs = append(logs, "[cleanup] system_proxy_restore=ok")
		}
	}
	if session != nil && session.relay != nil {
		_ = session.relay.CloseSend()
	}
	if session != nil && session.bridge != nil {
		_ = session.bridge.Close()
	}
	sidecarPID := vpnTrackedSessionSidecarPID(session)
	if session != nil && session.sharedExitRuntimeKey != "" {
		logs = append(logs, m.releaseSharedExitRuntime(session)...)
	} else if session != nil && session.sidecar != nil {
		if err := session.sidecar.Stop(); err != nil && !isStaleSidecarAlreadyGone(err) {
			logs = append(logs, "[cleanup] sidecar_stop=failed: "+err.Error())
		}
		logs = append(logs, m.cleanupSessionSidecarProcess(session, sidecarPID)...)
		logs = append(logs, m.cleanupVPNPortSidecars(req)...)
	} else {
		logs = append(logs, m.cleanupSessionSidecarProcess(session, sidecarPID)...)
		logs = append(logs, m.cleanupVPNPortSidecars(req)...)
	}
	sidecarCleanupFailed := vpnSidecarCleanupFailed(logs)
	if cleanupCore && session != nil {
		logs = append(logs, m.cleanupSessionCore(session)...)
	} else if cleanupCore {
		coreTarget := m.effectiveCoreTarget(req)
		logs = append(logs, m.cleanupSessionCore(&AgentVPNSession{
			CoreCleanupDir: coreTarget.CleanupDir,
			coreTemporary:  coreTarget.Temporary,
		})...)
	}
	tunRestoreErr := m.restoreSessionTun(session)
	if tunRestoreErr != nil {
		printf("VPN TUN restore failed: %v", tunRestoreErr)
		logs = append(logs, "[cleanup] tun_restore=failed: "+tunRestoreErr.Error())
	} else if session != nil && strings.TrimSpace(session.tunSnapshotPath) != "" {
		logs = append(logs, "[cleanup] tun_restore=ok")
	}
	statePath := ""
	if session != nil {
		statePath = session.StatePath
	}
	if statePath == "" {
		statePath = vpnSessionStatePath(m.effectiveWorkDir(), req.SessionID)
	}
	if systemProxyRestoreErr == nil && tunRestoreErr == nil && !sidecarCleanupFailed {
		if err := removeAgentVPNSessionState(statePath); err != nil {
			printf("VPN session state remove failed: %v", err)
		}
	} else {
		printf("VPN session state kept for restore retry: %s", statePath)
		logs = append(logs, "[cleanup] state=kept-for-restore-retry path="+statePath)
		if failOnTunRestore {
			if systemProxyRestoreErr != nil {
				return logs, fmt.Errorf("restore VPN system proxy before replacement for session %s: %w", req.SessionID, systemProxyRestoreErr)
			}
			if tunRestoreErr != nil {
				return logs, fmt.Errorf("restore VPN TUN state before replacement for session %s: %w", req.SessionID, tunRestoreErr)
			}
		}
	}

	return logs, nil
}

func vpnSidecarCleanupFailed(logs []string) bool {
	for _, line := range logs {
		if strings.Contains(line, "sidecar_stop=failed") ||
			strings.Contains(line, "kill=failed") {
			return true
		}
	}
	return false
}

func (m *AgentVPNManager) StopAll(reason string) {
	m.mu.Lock()
	requests := make([]model.VPNControlRequest, 0, len(m.sessions))
	for _, session := range m.sessions {
		if session == nil {
			continue
		}
		req := session.Request
		req.Action = model.VPNActionStop
		requests = append(requests, req)
	}
	m.mu.Unlock()

	for _, req := range requests {
		if _, err := m.Stop(req); err != nil {
			printf("VPN stop all failed for session %s (%s): %v", req.SessionID, reason, err)
		}
	}
}

func (m *AgentVPNManager) attachVPNRelay(req model.VPNControlRequest) (vpnIOStream, error) {
	switch strings.TrimSpace(req.RelayMode) {
	case "", model.VPNRelayModeDashboard:
		return m.attachDashboardRelay(req)
	case model.VPNRelayModeDirect:
		if m.directRelay == nil {
			return nil, errors.New("VPN direct relay is unavailable")
		}
		if req.Role == model.VPNRoleExit {
			return m.directRelay.Register(req)
		}
		if req.Role == model.VPNRoleEntry {
			return m.directRelay.Dial(context.Background(), req)
		}
		return nil, fmt.Errorf("unsupported VPN role %q", req.Role)
	default:
		return nil, fmt.Errorf("unsupported VPN relay mode %q", req.RelayMode)
	}
}

func (m *AgentVPNManager) attachDashboardRelay(req model.VPNControlRequest) (vpnIOStream, error) {
	stream, err := m.ioStreamFactory(context.Background())
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&pb.IOStreamData{Data: append([]byte{0xff, 0x05, 0xff, 0x05}, []byte(req.RelayStreamID)...)}); err != nil {
		_ = stream.CloseSend()
		return nil, err
	}
	return stream, nil
}

func drainVPNRelayStream(stream vpnIOStream) {
	if stream == nil {
		return
	}
	_ = stream.CloseSend()
	for {
		if _, err := stream.Recv(); err != nil {
			if !errors.Is(err, io.EOF) {
				printf("VPN relay stream closed: %v", err)
			}
			return
		}
	}
}

func (m *AgentVPNManager) acquireSharedExitRuntime(ctx context.Context, req *model.VPNControlRequest, workDir string, coreTarget vpnCoreTarget) (string, *AgentVPNSidecar, string, error) {
	if req == nil {
		return "", nil, "", errors.New("VPN control request is required")
	}
	ensureVPNExitBridgeListen(req, "")
	key := vpnSharedExitRuntimeKey(coreTarget.Path)

	m.mu.Lock()
	if m.sharedExitRuntimes == nil {
		m.sharedExitRuntimes = make(map[string]*agentVPNSharedExitRuntime)
	}
	if runtime := m.sharedExitRuntimes[key]; runtime != nil && runtime.sidecar != nil {
		if err := verifyVPNCoreSHA256(runtime.CorePath, req.Core.SHA256); err != nil {
			m.mu.Unlock()
			return "", nil, "", err
		}
		ensureVPNExitBridgeListen(req, runtime.Request.Extra["bridge_listen"])
		runtime.refs[req.SessionID] = struct{}{}
		corePath := runtime.CorePath
		sidecar := runtime.sidecar
		m.mu.Unlock()
		return corePath, sidecar, key, nil
	}

	corePath, err := prepareVPNCore(ctx, req.Core, coreTarget.Path, m.httpClient)
	if err != nil {
		m.mu.Unlock()
		return "", nil, "", err
	}
	key = vpnSharedExitRuntimeKey(corePath)
	if runtime := m.sharedExitRuntimes[key]; runtime != nil && runtime.sidecar != nil {
		if err := verifyVPNCoreSHA256(runtime.CorePath, req.Core.SHA256); err != nil {
			m.mu.Unlock()
			return "", nil, "", err
		}
		ensureVPNExitBridgeListen(req, runtime.Request.Extra["bridge_listen"])
		runtime.refs[req.SessionID] = struct{}{}
		sidecar := runtime.sidecar
		m.mu.Unlock()
		return runtime.CorePath, sidecar, key, nil
	}

	runtimeReq := *req
	runtimeReq.SessionID = defaultVPNPolicyCoreID
	sidecar, err := startAgentVPNSidecar(ctx, runtimeReq, workDir, corePath, m.sidecarRunner)
	if err != nil {
		m.mu.Unlock()
		return "", nil, "", vpnSidecarStartError(*req, err)
	}
	runtime := &agentVPNSharedExitRuntime{
		Key:            key,
		Request:        runtimeReq,
		sidecar:        sidecar,
		CorePath:       corePath,
		CoreCleanupDir: coreTarget.CleanupDir,
		sidecarPID:     vpnSidecarPID(sidecar),
		refs: map[string]struct{}{
			req.SessionID: struct{}{},
		},
	}
	m.sharedExitRuntimes[key] = runtime
	m.mu.Unlock()

	m.watchSharedExitRuntime(key, sidecar)
	return corePath, sidecar, key, nil
}

func ensureVPNExitBridgeListen(req *model.VPNControlRequest, address string) {
	if req == nil {
		return
	}
	if req.Extra == nil {
		req.Extra = make(map[string]string)
	}
	address = firstNonEmpty(address, req.Extra["bridge_listen"], defaultVPNExitBridge)
	req.Extra["bridge_listen"] = address
}

func vpnSharedExitRuntimeKey(corePath string) string {
	return filepath.Clean(strings.TrimSpace(corePath))
}

func (m *AgentVPNManager) releaseSharedExitRuntime(session *AgentVPNSession) []string {
	if session == nil || strings.TrimSpace(session.sharedExitRuntimeKey) == "" {
		return nil
	}
	key := session.sharedExitRuntimeKey
	sessionID := session.Request.SessionID

	m.mu.Lock()
	runtime := m.sharedExitRuntimes[key]
	if runtime == nil {
		m.mu.Unlock()
		return nil
	}
	delete(runtime.refs, sessionID)
	remaining := len(runtime.refs)
	if remaining > 0 {
		m.mu.Unlock()
		return []string{fmt.Sprintf("[cleanup] exit_core=shared keep=running refs=%d", remaining)}
	}
	delete(m.sharedExitRuntimes, key)
	runtime.stopping = true
	sidecar := runtime.sidecar
	sidecarPID := runtime.sidecarPID
	runtimeReq := runtime.Request
	m.mu.Unlock()

	logs := []string{"[cleanup] exit_core=shared refs=0"}
	if sidecar != nil {
		if err := sidecar.Stop(); err != nil && !isStaleSidecarAlreadyGone(err) {
			logs = append(logs, "[cleanup] sidecar_stop=failed: "+err.Error())
		}
	}
	logs = append(logs, m.cleanupSessionSidecarProcess(&AgentVPNSession{sidecarPID: sidecarPID}, sidecarPID)...)
	logs = append(logs, m.cleanupVPNPortSidecars(runtimeReq)...)
	return logs
}

func (m *AgentVPNManager) watchSharedExitRuntime(key string, sidecar *AgentVPNSidecar) {
	if sidecar == nil {
		return
	}
	go func() {
		err := sidecar.Wait()
		if err == nil {
			return
		}
		m.markSharedExitRuntimeFailed(key, err)
	}()
}

func (m *AgentVPNManager) markSharedExitRuntimeFailed(key string, err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	runtime := m.sharedExitRuntimes[key]
	if runtime == nil {
		m.mu.Unlock()
		return
	}
	if runtime.stopping {
		m.mu.Unlock()
		return
	}
	delete(m.sharedExitRuntimes, key)
	sessionIDs := make([]string, 0, len(runtime.refs))
	for sessionID := range runtime.refs {
		sessionIDs = append(sessionIDs, sessionID)
	}
	m.mu.Unlock()

	for _, sessionID := range sessionIDs {
		m.markSessionFailed(sessionID, err)
	}
}

func (m *AgentVPNManager) Status(req model.VPNControlRequest) (model.VPNControlResult, error) {
	if strings.TrimSpace(req.SessionID) == "" {
		err := errors.New("session_id is required")
		return vpnFailedResult(req, err), err
	}

	m.mu.Lock()
	session := m.sessions[req.SessionID]
	m.mu.Unlock()
	if session == nil {
		payload := model.VPNControlResult{
			SessionID: req.SessionID,
			Action:    req.Action,
			Role:      req.Role,
			State:     model.VPNStateStopped,
		}
		m.attachStatusFileState(&payload, req, nil)
		return payload, nil
	}
	payload := model.VPNControlResult{
		SessionID:          req.SessionID,
		Action:             req.Action,
		Role:               req.Role,
		State:              session.State,
		LocalHTTP:          session.Request.ListenHTTP,
		LocalSOCKS:         session.Request.ListenSOCKS,
		TunName:            session.Request.TunName,
		SystemProxyApplied: trackedVPNSystemProxyApplied(session.Request, session),
		LastError:          session.LastError,
		StartedAtUnix:      session.StartedAt.Unix(),
	}
	attachVPNBridgeStats(&payload, session.bridge)
	payload.Logs = readVPNLogTail(session.LogPath, 200)
	if req.Action == model.VPNActionLogs {
		return payload, nil
	}
	m.attachStatusFileState(&payload, req, session)
	return payload, nil
}

func (m *AgentVPNManager) attachStatusFileState(payload *model.VPNControlResult, req model.VPNControlRequest, session *AgentVPNSession) {
	if payload == nil {
		return
	}
	payload.CheckID = strings.TrimSpace(req.Extra["status_check_id"])
	statusReq := req
	if session != nil {
		statusReq = session.Request
	}
	if payload.LocalHTTP == "" {
		payload.LocalHTTP = statusReq.ListenHTTP
	}
	if payload.LocalSOCKS == "" {
		payload.LocalSOCKS = statusReq.ListenSOCKS
	}
	if payload.TunName == "" {
		payload.TunName = statusReq.TunName
	}
	payload.ModeStatus = normalizedVPNRuntimeMode(statusReq.Mode)
	coreError := ""
	payload.CoreStatus, payload.CorePath, coreError = m.inspectVPNCoreStatus(statusReq, session)
	if coreError != "" {
		if payload.LastError != "" {
			payload.LastError += "; " + coreError
		} else {
			payload.LastError = coreError
		}
	}
	if payload.CoreStatus == "ready" {
		payload.CoreVersion = strings.TrimSpace(statusReq.Core.Version)
	}
	rulesDetail := ""
	payload.RulesStatus, payload.RulesPath, rulesDetail = m.inspectVPNRulesStatus(statusReq)
	if payload.RulesStatus == "ready" {
		payload.RulesVersion = rulesDetail
	}
	systemProxyStatus, systemProxyLog := inspectVPNSystemProxyStatus(statusReq)
	if systemProxyStatus.Status != "" {
		payload.SystemProxyStatus = systemProxyStatus.Status
		payload.SystemProxyCurrent = systemProxyStatus.Current
		payload.SystemProxyExpected = systemProxyStatus.Expected
		applied := systemProxyStatus.Applied
		payload.SystemProxyApplied = &applied
	}
	payload.TunStatus, payload.TunInterface = inspectVPNTunStatus(statusReq)
	runtimeStatus, ruleModeStatus, runtimeLog := inspectVPNRuntimeRuleStatus(statusReq, session)
	payload.RuntimeStatus = runtimeStatus
	payload.RuleModeStatus = ruleModeStatus

	logs := []string{
		fmt.Sprintf("[mode] status=%s rule_mode=%s", emptyVPNStatusValue(payload.ModeStatus), emptyVPNStatusValue(payload.RuleModeStatus)),
		fmt.Sprintf("[core] status=%s path=%s", payload.CoreStatus, emptyVPNStatusValue(payload.CorePath)),
		fmt.Sprintf("[rules] status=%s path=%s", payload.RulesStatus, emptyVPNStatusValue(payload.RulesPath)),
		fmt.Sprintf("[tun] status=%s interface=%s", emptyVPNStatusValue(payload.TunStatus), emptyVPNStatusValue(payload.TunInterface)),
	}
	if payload.CoreVersion != "" {
		logs[1] += " version=" + payload.CoreVersion
	}
	if coreError != "" {
		logs[1] += " error=" + coreError
	}
	if payload.RulesVersion != "" {
		logs[2] += " version=" + payload.RulesVersion
	} else if rulesDetail != "" {
		logs[2] += " detail=" + rulesDetail
	}
	if runtimeLog != "" {
		logs = append(logs, runtimeLog)
	}
	if systemProxyLog != "" {
		logs = append(logs, systemProxyLog)
	}
	payload.Logs = append(payload.Logs, logs...)
}

func (m *AgentVPNManager) inspectVPNCoreStatus(req model.VPNControlRequest, session *AgentVPNSession) (string, string, string) {
	coreTarget := m.effectiveCoreTarget(req)
	corePath := strings.TrimSpace(coreTarget.Path)
	if session != nil && strings.TrimSpace(session.CorePath) != "" {
		corePath = strings.TrimSpace(session.CorePath)
	}
	if corePath == "" {
		return "unknown", "", "core path is empty"
	}
	info, err := os.Stat(corePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "missing", corePath, ""
		}
		return "error", corePath, err.Error()
	}
	if info.IsDir() {
		return "error", corePath, "core path is a directory"
	}
	if err := verifyVPNCoreSHA256(corePath, req.Core.SHA256); err != nil {
		return "error", corePath, err.Error()
	}
	return "ready", corePath, ""
}

func (m *AgentVPNManager) inspectVPNRulesStatus(req model.VPNControlRequest) (string, string, string) {
	rulesDir := m.effectiveRuleSetDir(req)
	missing := make([]string, 0, len(vpnRuleSetStatusFiles))
	for _, name := range vpnRuleSetStatusFiles {
		path := filepath.Join(rulesDir, name)
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				missing = append(missing, name)
				continue
			}
			return "error", rulesDir, err.Error()
		}
		if info.IsDir() {
			return "error", rulesDir, name + " is a directory"
		}
	}
	if len(missing) > 0 {
		return "missing", rulesDir, "missing=" + strings.Join(missing, ",")
	}
	return "ready", rulesDir, readVPNRulesManifestVersion(filepath.Join(rulesDir, "manifest.json"))
}

func inspectVPNTunStatus(req model.VPNControlRequest) (string, string) {
	if req.Role != model.VPNRoleEntry || !isVPNTunMode(req.Mode) {
		return "inactive", ""
	}
	tunName := strings.TrimSpace(req.TunName)
	if tunName == "" {
		tunName = "nezha-vpn"
	}
	iface, err := net.InterfaceByName(tunName)
	if err == nil && iface != nil {
		return "present", iface.Name
	}
	if err == nil {
		return "missing", tunName
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "no such network interface") ||
		strings.Contains(message, "no such device") ||
		strings.Contains(message, "not found") {
		return "missing", tunName
	}
	return "unknown", tunName
}

func (m *AgentVPNManager) effectiveRuleSetDir(req model.VPNControlRequest) string {
	if dir := strings.TrimSpace(req.Extra["rules_dir"]); dir != "" {
		return dir
	}
	coreTarget := m.effectiveCoreTarget(req)
	if strings.TrimSpace(coreTarget.CleanupDir) != "" {
		return filepath.Join(coreTarget.CleanupDir, "rules")
	}
	return filepath.Join(defaultVPNSessionCoreCleanupDir(vpnCoreSessionIDFromRequest(req)), "rules")
}

func readVPNRulesManifestVersion(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return ""
	}
	for _, key := range []string{"version", "tag", "generated_at", "updated_at"} {
		if value, ok := manifest[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func emptyVPNStatusValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func prepareVPNRuleSet(ctx context.Context, rulesDir string, httpClient vpnHTTPClient) (string, error) {
	rulesDir = strings.TrimSpace(rulesDir)
	if rulesDir == "" {
		return "", errors.New("VPN rules directory is required")
	}
	if !isSafeVPNRuleSetDir(rulesDir) {
		return "", fmt.Errorf("refusing to write unsafe VPN rules directory %q", rulesDir)
	}
	preferCN := detectVPNCoreCNNetwork(ctx, httpClient)
	baseURLs := orderedVPNRuleSetBaseURLs(preferCN)
	if len(baseURLs) == 0 {
		return "", errors.New("no VPN rule-set download URLs")
	}
	stageDir := rulesDir + ".tmp"
	_ = os.RemoveAll(stageDir)
	if err := os.MkdirAll(stageDir, 0750); err != nil {
		return "", err
	}
	var firstSource string
	for _, name := range vpnRuleSetStatusFiles {
		source, err := downloadVPNRuleSetAsset(ctx, baseURLs, name, filepath.Join(stageDir, name), httpClient)
		if err != nil {
			_ = os.RemoveAll(stageDir)
			return "", err
		}
		if firstSource == "" {
			firstSource = source
		}
	}
	if err := os.MkdirAll(filepath.Dir(rulesDir), 0750); err != nil {
		_ = os.RemoveAll(stageDir)
		return "", err
	}
	if err := os.RemoveAll(rulesDir); err != nil {
		_ = os.RemoveAll(stageDir)
		return "", err
	}
	if err := os.Rename(stageDir, rulesDir); err != nil {
		_ = os.RemoveAll(stageDir)
		return "", err
	}
	return firstSource, nil
}

func orderedVPNRuleSetBaseURLs(preferCN bool) []string {
	globalURL := strings.TrimSpace(os.Getenv("NZ_VPN_RULES_BASE_URL"))
	cnURL := strings.TrimSpace(os.Getenv("NZ_VPN_RULES_CN_BASE_URL"))
	if globalURL == "" {
		globalURL = defaultVPNRulesDownloadBaseURL
	}
	if cnURL == "" {
		cnURL = defaultVPNRulesCNDownloadBaseURL
	}
	if preferCN {
		return compactVPNCoreURLs(cnURL, globalURL)
	}
	return compactVPNCoreURLs(globalURL, cnURL)
}

func downloadVPNRuleSetAsset(ctx context.Context, baseURLs []string, asset string, targetPath string, httpClient vpnHTTPClient) (string, error) {
	var lastErr error
	for _, baseURL := range baseURLs {
		assetURL, err := joinVPNCoreAssetURL(baseURL, asset)
		if err != nil {
			lastErr = err
			continue
		}
		if err := downloadVPNRuleSetFile(ctx, assetURL, targetPath, httpClient); err != nil {
			lastErr = err
			continue
		}
		return assetURL, nil
	}
	if lastErr != nil {
		return "", fmt.Errorf("download VPN rule-set %s failed: %w", asset, lastErr)
	}
	return "", fmt.Errorf("download VPN rule-set %s failed: no candidate URLs", asset)
}

func downloadVPNRuleSetFile(ctx context.Context, rawURL string, targetPath string, httpClient vpnHTTPClient) error {
	resp, err := openVPNCoreDownload(ctx, rawURL, httpClient)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("download VPN rule-set failed: %s", resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
		return err
	}
	tmpPath := targetPath + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, resp.Body)
	closeErr := file.Close()
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

func cleanupVPNRuleSet(rulesDir string) error {
	rulesDir = strings.TrimSpace(rulesDir)
	if rulesDir == "" {
		return errors.New("VPN rules directory is required")
	}
	if !isSafeVPNRuleSetDir(rulesDir) {
		return fmt.Errorf("refusing to remove unsafe VPN rules directory %q", rulesDir)
	}
	return os.RemoveAll(rulesDir)
}

func isSafeVPNRuleSetDir(rulesDir string) bool {
	if filepath.Base(rulesDir) != "rules" {
		return false
	}
	root, err := filepath.Abs(filepath.Join(os.TempDir(), "nezha-agent-vpn", "sessions"))
	if err != nil {
		return false
	}
	target, err := filepath.Abs(rulesDir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

func (m *AgentVPNManager) Get(sessionID string) (*AgentVPNSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session := m.sessions[sessionID]
	if session == nil {
		return nil, false
	}
	clone := *session
	return &clone, true
}

func (m *AgentVPNManager) recoverSessionFromState(req model.VPNControlRequest) (*AgentVPNSession, bool) {
	statePath := vpnSessionStatePath(m.effectiveWorkDir(), req.SessionID)
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return nil, false
	}
	var state agentVPNSessionState
	if err := json.Unmarshal(raw, &state); err != nil || strings.TrimSpace(state.SessionID) == "" {
		return nil, false
	}
	recoveredReq := req
	if strings.TrimSpace(recoveredReq.Role) == "" {
		recoveredReq.Role = state.Role
	}
	if strings.TrimSpace(recoveredReq.Mode) == "" {
		recoveredReq.Mode = state.Mode
	}
	if strings.TrimSpace(recoveredReq.TunName) == "" {
		recoveredReq.TunName = state.TunName
	}
	if strings.TrimSpace(recoveredReq.DNSServer) == "" {
		recoveredReq.DNSServer = state.DNSServer
	}
	return &AgentVPNSession{
		Request:            recoveredReq,
		State:              state.State,
		StartedAt:          state.StartedAt,
		ConfigPath:         state.ConfigPath,
		LogPath:            state.LogPath,
		CorePath:           state.CorePath,
		CoreCleanupDir:     state.CoreCleanupDir,
		StatePath:          statePath,
		sidecarPID:         state.SidecarPID,
		tunSnapshotPath:    state.TunSnapshotPath,
		systemProxyApplied: state.SystemProxyApplied,
		coreTemporary:      state.CoreTemporary,
	}, true
}

func (m *AgentVPNManager) cleanupSessionSidecarProcess(session *AgentVPNSession, pid int) []string {
	if session == nil || pid <= 0 {
		return nil
	}
	killer := m.staleSidecarKiller
	if killer == nil {
		killer = killStaleVPNSidecarProcess
	}
	if err := killer(pid); err != nil {
		if isStaleSidecarAlreadyGone(err) {
			return []string{fmt.Sprintf("[cleanup] sidecar_pid=%d already-gone", pid)}
		}
		return []string{fmt.Sprintf("[cleanup] sidecar_pid=%d kill=failed: %s", pid, err.Error())}
	}
	session.sidecarPID = 0
	return []string{fmt.Sprintf("[cleanup] sidecar_pid=%d kill=ok", pid)}
}

func vpnTrackedSessionSidecarPID(session *AgentVPNSession) int {
	if session == nil {
		return 0
	}
	if pid := vpnSidecarPID(session.sidecar); pid > 0 {
		return pid
	}
	return session.sidecarPID
}

func (m *AgentVPNManager) watchSidecar(sessionID string, sidecar *AgentVPNSidecar) {
	if sidecar == nil {
		return
	}
	go func() {
		err := sidecar.Wait()
		if err == nil {
			return
		}
		m.markSessionFailed(sessionID, err)
	}()
}

func (m *AgentVPNManager) watchBridge(sessionID string, bridge *AgentVPNBridge) {
	if bridge == nil || bridge.Done() == nil {
		return
	}
	go func() {
		err, ok := <-bridge.Done()
		if !ok || err == nil {
			return
		}
		m.markBridgeFailed(sessionID, fmt.Errorf("VPN bridge relay closed: %w", err))
	}()
}

func (m *AgentVPNManager) markBridgeFailed(sessionID string, err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	session := m.sessions[sessionID]
	if session == nil {
		m.mu.Unlock()
		return
	}
	sidecar := session.sidecar
	sidecarPID := vpnTrackedSessionSidecarPID(session)
	sharedExitRuntime := session.sharedExitRuntimeKey != ""
	m.mu.Unlock()

	m.markSessionFailed(sessionID, err)

	if sharedExitRuntime {
		_ = m.releaseSharedExitRuntime(session)
	} else if sidecar != nil {
		if stopErr := sidecar.Stop(); stopErr != nil && !isStaleSidecarAlreadyGone(stopErr) {
			printf("VPN bridge sidecar stop failed: %v", stopErr)
		}
		_ = m.cleanupSessionSidecarProcess(session, sidecarPID)
	}
}

func (m *AgentVPNManager) markSessionFailed(sessionID string, err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	session := m.sessions[sessionID]
	if session == nil {
		m.mu.Unlock()
		return
	}
	if session.State == model.VPNStateFailed {
		m.mu.Unlock()
		return
	}
	session.LastError = err.Error()
	cancel := session.cancel
	systemProxyApplied := session.systemProxyApplied
	relay := session.relay
	bridge := session.bridge
	send := m.taskResultSender
	m.mu.Unlock()
	cleanupLogs := make([]string, 0, 3)

	if cancel != nil {
		cancel()
	}
	var systemProxyRestoreErr error
	if systemProxyApplied {
		if systemProxyRestoreErr = m.restoreSessionSystemProxy(session); systemProxyRestoreErr != nil {
			cleanupLogs = append(cleanupLogs, "[cleanup] system_proxy_restore=failed: "+systemProxyRestoreErr.Error())
		} else {
			cleanupLogs = append(cleanupLogs, "[cleanup] system_proxy_restore=ok")
		}
	}
	if relay != nil {
		_ = relay.CloseSend()
	}
	if bridge != nil {
		_ = bridge.Close()
	}
	tunRestoreErr := m.restoreSessionTun(session)
	if tunRestoreErr != nil {
		printf("VPN TUN restore failed: %v", tunRestoreErr)
		cleanupLogs = append(cleanupLogs, "[cleanup] tun_restore=failed: "+tunRestoreErr.Error())
	} else if session != nil && strings.TrimSpace(session.tunSnapshotPath) != "" {
		cleanupLogs = append(cleanupLogs, "[cleanup] tun_restore=ok")
	}
	if statePath := session.StatePath; statePath != "" {
		if tunRestoreErr == nil {
			if err := removeAgentVPNSessionState(statePath); err != nil {
				printf("VPN session state remove failed: %v", err)
			}
		} else {
			printf("VPN session state kept for restore retry: %s", statePath)
			cleanupLogs = append(cleanupLogs, "[cleanup] state=kept-for-restore-retry path="+statePath)
		}
	}
	m.mu.Lock()
	if current := m.sessions[sessionID]; current == session {
		session.State = model.VPNStateFailed
		session.cancel = nil
		session.relay = nil
		session.bridge = nil
		if systemProxyApplied && systemProxyRestoreErr == nil {
			session.systemProxyApplied = false
		}
	}
	result := m.failedTaskResultLocked(session)
	m.mu.Unlock()
	if result != nil && len(cleanupLogs) > 0 {
		var payload model.VPNControlResult
		if err := json.Unmarshal([]byte(result.Data), &payload); err == nil {
			payload.Logs = append(payload.Logs, cleanupLogs...)
			if data, err := json.Marshal(payload); err == nil {
				result.Data = string(data)
			}
		}
	}
	if send != nil && result != nil {
		if sendErr := send(result); sendErr != nil {
			printf("VPN failed result send failed: %v", sendErr)
		}
	}
}

func (m *AgentVPNManager) CleanupStaleSessions() {
	states := loadAgentVPNSessionStates(m.effectiveWorkDir())
	for _, state := range states {
		if m.staleStateBelongsToActiveSession(state) {
			continue
		}
		if state.SystemProxyApplied && m.systemProxyManager != nil {
			if err := m.systemProxyManager.Restore(); err != nil {
				printf("VPN stale system proxy restore failed for session %s: %v", state.SessionID, err)
				continue
			}
			state.SystemProxyApplied = false
			if err := writeAgentVPNSessionState(vpnSessionStatePath(m.effectiveWorkDir(), state.SessionID), state); err != nil {
				printf("VPN stale system proxy state update failed for session %s: %v", state.SessionID, err)
				continue
			}
		}
		if state.SidecarPID > 0 {
			killer := m.staleSidecarKiller
			if killer == nil {
				killer = killStaleVPNSidecarProcess
			}
			if err := killer(state.SidecarPID); err != nil {
				if isStaleSidecarAlreadyGone(err) {
					printf("VPN stale sidecar already gone for session %s pid %d", state.SessionID, state.SidecarPID)
				} else {
					printf("VPN stale sidecar cleanup failed for session %s pid %d: %v", state.SessionID, state.SidecarPID, err)
					continue
				}
			}
			state.SidecarPID = 0
			if err := writeAgentVPNSessionState(vpnSessionStatePath(m.effectiveWorkDir(), state.SessionID), state); err != nil {
				printf("VPN stale sidecar state update failed for session %s: %v", state.SessionID, err)
				continue
			}
		}
		if isVPNTunMode(state.Mode) && strings.TrimSpace(state.TunSnapshotPath) != "" && m.tunManager != nil {
			req := model.VPNControlRequest{
				SessionID: state.SessionID,
				Role:      state.Role,
				Mode:      state.Mode,
				TunName:   state.TunName,
				DNSServer: state.DNSServer,
			}
			if err := m.tunManager.Restore(req, state.TunSnapshotPath); err != nil {
				printf("VPN stale TUN restore failed for session %s: %v", state.SessionID, err)
				continue
			}
		}
		if err := removeAgentVPNSessionState(vpnSessionStatePath(m.effectiveWorkDir(), state.SessionID)); err != nil {
			printf("VPN stale session state remove failed for session %s: %v", state.SessionID, err)
		}
	}
}

func (m *AgentVPNManager) staleStateBelongsToActiveSession(state agentVPNSessionState) bool {
	if m == nil || strings.TrimSpace(state.SessionID) == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if session := m.sessions[state.SessionID]; session != nil {
		return true
	}
	for _, runtime := range m.sharedExitRuntimes {
		if runtime == nil {
			continue
		}
		if _, ok := runtime.refs[state.SessionID]; ok {
			return true
		}
		if state.SidecarPID > 0 && runtime.sidecarPID == state.SidecarPID {
			return true
		}
	}
	return false
}

func isStaleSidecarAlreadyGone(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrProcessDone) || errors.Is(err, os.ErrNotExist) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"process already finished",
		"no such process",
		"process not found",
		"invalid process",
		"cannot find the process",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func (m *AgentVPNManager) persistSessionState(session *AgentVPNSession) error {
	if session == nil {
		return nil
	}
	path := session.StatePath
	if path == "" {
		path = vpnSessionStatePath(m.effectiveWorkDir(), session.Request.SessionID)
		session.StatePath = path
	}
	state := agentVPNSessionState{
		Version:            1,
		SessionID:          session.Request.SessionID,
		Role:               session.Request.Role,
		Mode:               session.Request.Mode,
		State:              session.State,
		ConfigPath:         session.ConfigPath,
		LogPath:            session.LogPath,
		CorePath:           session.CorePath,
		CoreCleanupDir:     session.CoreCleanupDir,
		CoreTemporary:      session.coreTemporary,
		TunName:            session.Request.TunName,
		DNSServer:          session.Request.DNSServer,
		SidecarPID:         vpnTrackedSessionSidecarPID(session),
		SystemProxyApplied: session.systemProxyApplied,
		TunSnapshotPath:    session.tunSnapshotPath,
		StartedAt:          session.StartedAt,
		UpdatedAt:          time.Now(),
	}
	writer := m.sessionStateWriter
	if writer == nil {
		writer = writeAgentVPNSessionState
	}
	return writer(path, state)
}

func (m *AgentVPNManager) persistSessionRecoveryState(session *AgentVPNSession) {
	if session == nil {
		return
	}
	writer := m.sessionStateWriter
	if writer == nil {
		writer = writeAgentVPNSessionState
	}
	state := agentVPNSessionState{
		Version:            1,
		SessionID:          session.Request.SessionID,
		Role:               session.Request.Role,
		Mode:               session.Request.Mode,
		State:              session.State,
		ConfigPath:         session.ConfigPath,
		LogPath:            session.LogPath,
		CorePath:           session.CorePath,
		CoreCleanupDir:     session.CoreCleanupDir,
		CoreTemporary:      session.coreTemporary,
		TunName:            session.Request.TunName,
		DNSServer:          session.Request.DNSServer,
		SidecarPID:         vpnTrackedSessionSidecarPID(session),
		SystemProxyApplied: session.systemProxyApplied,
		TunSnapshotPath:    session.tunSnapshotPath,
		StartedAt:          session.StartedAt,
		UpdatedAt:          time.Now(),
	}
	if err := writer(session.StatePath, state); err != nil {
		printf("VPN recovery session state write failed: %v", err)
	}
}

func (m *AgentVPNManager) snapshotSessionTun(session *AgentVPNSession) error {
	if session == nil || session.Request.Role != model.VPNRoleEntry || !isVPNTunMode(session.Request.Mode) {
		return nil
	}
	if m.tunManager == nil {
		return errors.New("VPN TUN manager is not available")
	}
	path, err := m.tunManager.Snapshot(session.Request, filepath.Dir(session.StatePath))
	if err != nil {
		return fmt.Errorf("snapshot VPN TUN state for session %s: %w", session.Request.SessionID, err)
	}
	session.tunSnapshotPath = path
	return nil
}

func (m *AgentVPNManager) restoreSessionTun(session *AgentVPNSession) error {
	if session == nil || session.Request.Role != model.VPNRoleEntry || !isVPNTunMode(session.Request.Mode) || strings.TrimSpace(session.tunSnapshotPath) == "" {
		return nil
	}
	if m.tunManager == nil {
		return errors.New("VPN TUN manager is not available")
	}
	if err := m.tunManager.Restore(session.Request, session.tunSnapshotPath); err != nil {
		return err
	}
	session.tunSnapshotPath = ""
	return nil
}

func (m *AgentVPNManager) restoreSessionTunForStartupFailure(session *AgentVPNSession) []string {
	if session == nil {
		return nil
	}
	hadSnapshot := strings.TrimSpace(session.tunSnapshotPath) != ""
	if err := m.restoreSessionTun(session); err != nil {
		m.persistSessionRecoveryState(session)
		logs := []string{"[cleanup] tun_restore=failed: " + err.Error()}
		if strings.TrimSpace(session.StatePath) != "" {
			logs = append(logs, "[cleanup] state=kept-for-restore-retry path="+session.StatePath)
		}
		return logs
	}
	if hadSnapshot {
		return []string{"[cleanup] tun_restore=ok"}
	}
	return nil
}

func (m *AgentVPNManager) preflightTun(req model.VPNControlRequest) error {
	if req.Role != model.VPNRoleEntry || !isVPNTunMode(req.Mode) {
		return nil
	}
	if m.tunManager == nil {
		return errors.New("VPN TUN manager is not available")
	}
	if err := ensureVPNWintunAvailable(context.Background(), req, m.effectiveWorkDir(), m.httpClient); err != nil {
		return fmt.Errorf("VPN Wintun preflight failed for session %s: %w", req.SessionID, err)
	}
	if err := m.tunManager.Preflight(req); err != nil {
		return fmt.Errorf("VPN TUN preflight failed for session %s: %w", req.SessionID, err)
	}
	return nil
}

func (m *AgentVPNManager) clearForeignSystemProxyBeforeApply(req model.VPNControlRequest) error {
	if m.systemProxyManager == nil {
		return nil
	}
	inspection, err := m.systemProxyManager.Inspect(req.ListenHTTP, req.ListenSOCKS)
	if err == nil && inspection.Applied {
		return nil
	}
	return m.clearSessionSystemProxy()
}

func (m *AgentVPNManager) restoreSessionSystemProxy(session *AgentVPNSession) error {
	if session == nil || !session.systemProxyApplied || m.systemProxyManager == nil {
		return nil
	}
	if err := m.systemProxyManager.Restore(); err != nil {
		printf("VPN system proxy restore failed: %v", err)
		return err
	}
	session.systemProxyApplied = false
	return nil
}

func (m *AgentVPNManager) clearSessionSystemProxy() error {
	if m.systemProxyManager == nil {
		return nil
	}
	if err := m.systemProxyManager.Clear(); err != nil {
		printf("VPN system proxy clear failed: %v", err)
		return err
	}
	return nil
}

func (m *AgentVPNManager) probeSessionTunHealth(req model.VPNControlRequest) error {
	if req.Role != model.VPNRoleEntry || !isVPNTunMode(req.Mode) {
		return nil
	}
	if m.tunHealthProbe == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), vpnTunHealthProbeTimeout(req))
	defer cancel()
	return m.tunHealthProbe(ctx, req)
}

func (m *AgentVPNManager) probeSessionEgress(req model.VPNControlRequest) []string {
	if req.Role != model.VPNRoleEntry || strings.TrimSpace(req.Extra["egress_probe_url"]) == "" || m.egressProbe == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), vpnEgressProbeTimeout(req))
	defer cancel()
	return m.egressProbe(ctx, req)
}

func (m *AgentVPNManager) SetTaskResultSender(send func(*pb.TaskResult) error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.taskResultSender = send
}

func (m *AgentVPNManager) failedTaskResultLocked(session *AgentVPNSession) *pb.TaskResult {
	if session == nil {
		return nil
	}
	payload := model.VPNControlResult{
		SessionID: session.Request.SessionID,
		Action:    model.VPNActionStatus,
		Role:      session.Request.Role,
		State:     model.VPNStateFailed,
		LastError: session.LastError,
		Logs:      readVPNLogTail(session.LogPath, 200),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return &pb.TaskResult{
		Type:       model.TaskTypeVPNControl,
		Successful: false,
		Data:       string(data),
	}
}

func (m *AgentVPNManager) watchSidecarLogs(ctx context.Context, sessionID string, path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	interval := m.logPollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var offset int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lines, nextOffset := readVPNLogLinesSince(path, offset)
				offset = nextOffset
				if len(lines) == 0 {
					continue
				}
				m.sendSidecarLogLines(sessionID, lines)
			}
		}
	}()
}

func (m *AgentVPNManager) sendSidecarLogLines(sessionID string, lines []string) {
	m.mu.Lock()
	session := m.sessions[sessionID]
	send := m.taskResultSender
	m.mu.Unlock()
	if session == nil || send == nil || len(lines) == 0 {
		return
	}
	payload := model.VPNControlResult{
		SessionID: session.Request.SessionID,
		Action:    model.VPNActionLogs,
		Role:      session.Request.Role,
		State:     session.State,
		Logs:      lines,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	if err := send(&pb.TaskResult{
		Type:       model.TaskTypeVPNControl,
		Successful: true,
		Data:       string(data),
	}); err != nil {
		printf("VPN log result send failed: %v", err)
	}
}

func (m *AgentVPNManager) watchDirectTraffic(ctx context.Context, sessionID string) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var lastUpload uint64
		var lastDownload uint64
		var lastActive uint32
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				upload, download, active, sent := m.sendDirectTrafficStatus(sessionID, lastUpload, lastDownload, lastActive)
				if sent {
					lastUpload, lastDownload, lastActive = upload, download, active
				}
			}
		}
	}()
}

func (m *AgentVPNManager) sendDirectTrafficStatus(sessionID string, lastUpload uint64, lastDownload uint64, lastActive uint32) (uint64, uint64, uint32, bool) {
	m.mu.Lock()
	session := m.sessions[sessionID]
	send := m.taskResultSender
	m.mu.Unlock()
	if session == nil || send == nil || session.Request.RelayMode != model.VPNRelayModeDirect || session.Request.Role != model.VPNRoleEntry {
		return lastUpload, lastDownload, lastActive, false
	}
	upload, download, active := vpnBridgeStatsSnapshot(session.bridge)
	if upload == lastUpload && download == lastDownload && active == lastActive {
		return lastUpload, lastDownload, lastActive, false
	}
	payload := model.VPNControlResult{
		SessionID:       session.Request.SessionID,
		Action:          model.VPNActionStatus,
		Role:            session.Request.Role,
		State:           session.State,
		TrafficReported: true,
		UploadBytes:     upload,
		DownloadBytes:   download,
		ActiveConns:     active,
		StartedAtUnix:   session.StartedAt.Unix(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return lastUpload, lastDownload, lastActive, false
	}
	if err := send(&pb.TaskResult{
		Type:       model.TaskTypeVPNControl,
		Successful: true,
		Data:       string(data),
	}); err != nil {
		printf("VPN direct traffic result send failed: %v", err)
		return lastUpload, lastDownload, lastActive, false
	}
	return upload, download, active, true
}

func attachVPNBridgeStats(payload *model.VPNControlResult, bridge *AgentVPNBridge) {
	if payload == nil {
		return
	}
	if bridge == nil || bridge.stats == nil {
		return
	}
	payload.TrafficReported = true
	payload.UploadBytes, payload.DownloadBytes, payload.ActiveConns = vpnBridgeStatsSnapshot(bridge)
}

func vpnBridgeStatsSnapshot(bridge *AgentVPNBridge) (uint64, uint64, uint32) {
	if bridge == nil || bridge.stats == nil {
		return 0, 0, 0
	}
	return bridge.stats.Snapshot()
}

func readVPNLogLinesSince(path string, offset int64) ([]string, int64) {
	if strings.TrimSpace(path) == "" {
		return nil, offset
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, offset
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, offset
	}
	size := stat.Size()
	if offset > size {
		offset = 0
	}
	if offset == size {
		return nil, offset
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, offset
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, offset
	}
	nextOffset := size
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	parts := strings.Split(text, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	lines := make([]string, 0, len(parts))
	for _, line := range parts {
		if line = strings.TrimRight(line, "\r"); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nextOffset
}

func readVPNLogTail(path string, maxLines int) []string {
	if strings.TrimSpace(path) == "" || maxLines <= 0 {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines
}

func vpnSessionStatePath(workDir string, sessionID string) string {
	if strings.TrimSpace(workDir) == "" {
		workDir = defaultVPNWorkDir()
	}
	return filepath.Join(workDir, "sessions", safeVPNPathName(sessionID), "state.json")
}

func writeAgentVPNSessionState(path string, state agentVPNSessionState) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("VPN session state path is required")
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}

func loadAgentVPNSessionStates(workDir string) []agentVPNSessionState {
	pattern := filepath.Join(workDir, "sessions", "*", "state.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	states := make([]agentVPNSessionState, 0, len(matches))
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			printf("VPN session state read failed for %s: %v", path, err)
			continue
		}
		var state agentVPNSessionState
		if err := json.Unmarshal(raw, &state); err != nil {
			printf("VPN session state decode failed for %s: %v", path, err)
			continue
		}
		if strings.TrimSpace(state.SessionID) == "" {
			continue
		}
		states = append(states, state)
	}
	return states
}

func removeAgentVPNSessionState(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func handleVPNControlTask(task *pb.Task, result *pb.TaskResult) {
	var req model.VPNControlRequest
	if err := json.Unmarshal([]byte(task.GetData()), &req); err != nil {
		result.Data = "invalid VPN control request: " + err.Error()
		return
	}
	if err := validateVPNControlRequest(req); err != nil {
		payload := vpnFailedResult(req, err)
		data, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			result.Data = marshalErr.Error()
			return
		}
		result.Data = string(data)
		result.Successful = false
		return
	}

	var payload model.VPNControlResult
	var err error
	switch req.Action {
	case model.VPNActionPrepare:
		payload, err = vpnManager.Prepare(req)
	case model.VPNActionStart:
		payload, err = vpnManager.Start(req)
	case model.VPNActionStop:
		payload, err = vpnManager.Stop(req)
	case model.VPNActionControl:
		payload, err = vpnManager.Control(req)
	case model.VPNActionCleanup:
		payload, err = vpnManager.Cleanup(req)
	case model.VPNActionRulesPrepare:
		payload, err = vpnManager.PrepareRules(req)
	case model.VPNActionRulesCleanup:
		payload, err = vpnManager.CleanupRules(req)
	case model.VPNActionStatus, model.VPNActionLogs:
		payload, err = vpnManager.Status(req)
	case model.VPNActionRestart:
		payload, err = vpnManager.Start(req)
	default:
		err = fmt.Errorf("unsupported VPN action %q", req.Action)
		payload = vpnFailedResult(req, err)
	}

	data, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		result.Data = marshalErr.Error()
		return
	}
	result.Data = string(data)
	result.Successful = err == nil
}

func validateVPNControlRequest(req model.VPNControlRequest) error {
	if strings.TrimSpace(req.SessionID) == "" {
		return errors.New("session_id is required")
	}
	if req.Role != model.VPNRoleEntry && req.Role != model.VPNRoleExit {
		return fmt.Errorf("unsupported VPN role %q", req.Role)
	}
	if strings.TrimSpace(req.RelayMode) == "" {
		return errors.New("relay_mode is required")
	}
	if req.RelayMode != model.VPNRelayModeDashboard && req.RelayMode != model.VPNRelayModeDirect {
		return fmt.Errorf("unsupported VPN relay mode %q", req.RelayMode)
	}
	if !vpnControlActionKnown(req.Action) {
		return fmt.Errorf("unsupported VPN action %q", req.Action)
	}
	if vpnControlActionPreparesCore(req.Action) {
		if err := validateVPNCoreSpec(req.Core); err != nil {
			return err
		}
	}
	if vpnControlActionStartsRuntime(req.Action) {
		if strings.TrimSpace(req.RelayStreamID) == "" {
			return errors.New("relay_stream_id is required")
		}
		if strings.TrimSpace(req.Token) == "" {
			return errors.New("token is required")
		}
		if err := validateVPNWintunSpec(req); err != nil {
			return err
		}
		if err := validateVPNTunHealthURL(req); err != nil {
			return err
		}
	}
	return nil
}

func vpnControlActionKnown(action string) bool {
	switch action {
	case model.VPNActionPrepare,
		model.VPNActionStart,
		model.VPNActionStop,
		model.VPNActionRestart,
		model.VPNActionControl,
		model.VPNActionStatus,
		model.VPNActionLogs,
		model.VPNActionCleanup,
		model.VPNActionRulesPrepare,
		model.VPNActionRulesCleanup:
		return true
	default:
		return false
	}
}

func vpnControlActionStartsRuntime(action string) bool {
	return action == model.VPNActionStart || action == model.VPNActionRestart
}

func vpnControlActionPreparesCore(action string) bool {
	return action == model.VPNActionPrepare || vpnControlActionStartsRuntime(action)
}

func (m *AgentVPNManager) effectiveWorkDir() string {
	if strings.TrimSpace(agentConfig.VPNStateDir) != "" {
		return strings.TrimSpace(agentConfig.VPNStateDir)
	}
	if strings.TrimSpace(m.workDir) != "" {
		return m.workDir
	}
	return defaultVPNWorkDir()
}

type vpnCoreTarget struct {
	Path       string
	CleanupDir string
	Temporary  bool
}

func (m *AgentVPNManager) effectiveCoreTarget(req model.VPNControlRequest) vpnCoreTarget {
	spec := req.Core
	if path := resolveVPNCorePath("", spec); path != "" {
		return vpnCoreTarget{Path: path}
	}
	if strings.TrimSpace(agentConfig.VPNCoreDir) != "" {
		return vpnCoreTarget{Path: filepath.Join(strings.TrimSpace(agentConfig.VPNCoreDir), vpnCoreFileName(spec))}
	}
	if strings.TrimSpace(m.corePath) != "" {
		return vpnCoreTarget{Path: resolveVPNCorePath(m.corePath, spec)}
	}
	cleanupDir := defaultVPNSessionCoreCleanupDir(vpnCoreSessionIDFromRequest(req))
	return vpnCoreTarget{
		Path:       filepath.Join(cleanupDir, "core", vpnCoreFileName(spec)),
		CleanupDir: cleanupDir,
		Temporary:  true,
	}
}

func (m *AgentVPNManager) effectiveCorePath(spec model.VPNCoreSpec) string {
	return m.effectiveCoreTarget(model.VPNControlRequest{SessionID: "session", Core: spec}).Path
}

func vpnCoreFileName(spec model.VPNCoreSpec) string {
	name := "sing-box"
	if strings.TrimSpace(spec.Name) != "" && !filepath.IsAbs(spec.Name) {
		name = filepath.Base(strings.TrimSpace(spec.Name))
	}
	if !strings.HasSuffix(strings.ToLower(name), ".exe") && isWindowsRuntime() {
		name += ".exe"
	}
	return name
}

func defaultVPNSessionCoreCleanupDir(sessionID string) string {
	return filepath.Join(os.TempDir(), "nezha-agent-vpn", "sessions", safeVPNPathName(sessionID))
}

func vpnCoreSessionIDFromRequest(req model.VPNControlRequest) string {
	return defaultVPNPolicyCoreID
}

func (m *AgentVPNManager) cleanupSessionCore(session *AgentVPNSession) []string {
	if session == nil {
		return nil
	}
	if m.activeRuntimeUsesCore(session.CoreCleanupDir) {
		return []string{"[cleanup] core_remove=skipped: shared core in use"}
	}
	if err := cleanupTemporaryVPNCore(session.CoreCleanupDir, session.coreTemporary); err != nil {
		return []string{"[cleanup] core_remove=failed: " + err.Error()}
	}
	if session.coreTemporary && strings.TrimSpace(session.CoreCleanupDir) != "" {
		session.CorePath = ""
		session.CoreCleanupDir = ""
		session.coreTemporary = false
		return []string{"[cleanup] core_remove=ok"}
	}
	return nil
}

func (m *AgentVPNManager) activeRuntimeUsesCore(cleanupDir string) bool {
	cleanupDir = strings.TrimSpace(cleanupDir)
	if cleanupDir == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, session := range m.sessions {
		if session != nil && strings.TrimSpace(session.CoreCleanupDir) == cleanupDir {
			return true
		}
	}
	for _, runtime := range m.sharedExitRuntimes {
		if runtime != nil && strings.TrimSpace(runtime.CoreCleanupDir) == cleanupDir {
			return true
		}
	}
	return false
}

func (m *AgentVPNManager) activeRuntimeUsesRules(rulesDir string) bool {
	rulesDir = strings.TrimSpace(rulesDir)
	if rulesDir == "" {
		return false
	}
	rulesDir = filepath.Clean(rulesDir)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, session := range m.sessions {
		if session == nil {
			continue
		}
		if filepath.Clean(m.effectiveRuleSetDir(session.Request)) == rulesDir {
			return true
		}
	}
	for _, runtime := range m.sharedExitRuntimes {
		if runtime == nil {
			continue
		}
		if filepath.Clean(m.effectiveRuleSetDir(runtime.Request)) == rulesDir {
			return true
		}
	}
	return false
}

func cleanupTemporaryVPNCore(cleanupDir string, temporary bool) error {
	if !temporary || strings.TrimSpace(cleanupDir) == "" {
		return nil
	}
	if !isSafeVPNSessionCoreCleanupDir(cleanupDir) {
		return fmt.Errorf("refusing to remove unsafe VPN core directory %q", cleanupDir)
	}
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		if err := os.RemoveAll(cleanupDir); err != nil {
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return nil
}

func isSafeVPNSessionCoreCleanupDir(cleanupDir string) bool {
	root, err := filepath.Abs(filepath.Join(os.TempDir(), "nezha-agent-vpn", "sessions"))
	if err != nil {
		return false
	}
	target, err := filepath.Abs(cleanupDir)
	if err != nil {
		return false
	}
	if target == root {
		return false
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

func vpnFailedResult(req model.VPNControlRequest, err error) model.VPNControlResult {
	message := ""
	if err != nil {
		message = err.Error()
	}
	return model.VPNControlResult{
		SessionID: req.SessionID,
		Action:    req.Action,
		Role:      req.Role,
		State:     model.VPNStateFailed,
		LastError: message,
	}
}

func vpnFailedResultWithLogs(req model.VPNControlRequest, err error, logs []string) model.VPNControlResult {
	result := vpnFailedResult(req, err)
	if len(logs) > 0 {
		result.Logs = append(result.Logs, logs...)
	}
	return result
}
