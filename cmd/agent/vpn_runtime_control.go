package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nezhahq/agent/model"
)

const vpnRuntimeAPIExtraKey = "runtime_api_addr"

func ensureVPNRuntimeControlExtra(req *model.VPNControlRequest) {
	if req == nil || req.Role != model.VPNRoleEntry {
		return
	}
	if req.Extra == nil {
		req.Extra = map[string]string{}
	}
	if strings.TrimSpace(req.Extra[vpnRuntimeAPIExtraKey]) == "" {
		req.Extra[vpnRuntimeAPIExtraKey] = defaultVPNRuntimeControlAddress(req.SessionID)
	}
}

func defaultVPNRuntimeControlAddress(sessionID string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.TrimSpace(sessionID)))
	return fmt.Sprintf("127.0.0.1:%d", 19092+int(h.Sum32()%20000))
}

func vpnRuntimeControlAddress(req model.VPNControlRequest) string {
	if req.Extra == nil {
		return ""
	}
	return strings.TrimSpace(req.Extra[vpnRuntimeAPIExtraKey])
}

func vpnSelectorOutboundsForRuleMode(req model.VPNControlRequest) (string, string, string) {
	switch vpnRuntimeRuleMode(req) {
	case model.VPNRuleModeGlobal:
		return vpnOutboundExit, vpnOutboundExit, vpnOutboundExit
	case model.VPNRuleModeDirect:
		return vpnOutboundDirect, vpnOutboundDirect, vpnOutboundDirect
	default:
		finalOutbound := vpnOutboundDirect
		if _, ok := activeVPNRuleSetRouteItems(req); ok {
			finalOutbound = vpnOutboundExit
		}
		return finalOutbound, vpnOutboundExit, vpnOutboundDirect
	}
}

func vpnRuntimeRuleMode(req model.VPNControlRequest) string {
	switch strings.TrimSpace(req.Rules.Mode) {
	case model.VPNRuleModeGlobal:
		return model.VPNRuleModeGlobal
	case model.VPNRuleModeIP:
		return model.VPNRuleModeIP
	case model.VPNRuleModeDirect:
		return model.VPNRuleModeDirect
	default:
		if req.Mode == model.VPNModeTunGlobal {
			return model.VPNRuleModeGlobal
		}
		return model.VPNRuleModeDomain
	}
}

func (m *AgentVPNManager) Control(req model.VPNControlRequest) (model.VPNControlResult, error) {
	if err := validateVPNControlRequest(req); err != nil {
		return vpnFailedResult(req, err), err
	}
	if req.Role != model.VPNRoleEntry {
		err := errors.New("runtime VPN controls are only supported on entry agent")
		return vpnFailedResult(req, err), err
	}
	if err := vpnDisabledByConfig(); err != nil {
		return vpnFailedResult(req, err), err
	}
	if err := vpnModeAllowedByConfig(req.Mode); err != nil {
		return vpnFailedResult(req, err), err
	}

	m.mu.Lock()
	session := m.sessions[req.SessionID]
	m.mu.Unlock()
	if session == nil || session.State != model.VPNStateRunning {
		err := fmt.Errorf("VPN session %s is not running on entry agent", req.SessionID)
		return vpnFailedResult(req, err), err
	}
	if !vpnRuntimeModesCompatible(session.Request.Mode, req.Mode) {
		err := fmt.Errorf("changing VPN runtime from %s to %s requires session restart", normalizedVPNRuntimeMode(session.Request.Mode), normalizedVPNRuntimeMode(req.Mode))
		return vpnFailedResult(req, err), err
	}

	logs := make([]string, 0, 3)
	if vpnRuntimeRuleMode(session.Request) != vpnRuntimeRuleMode(req) {
		if err := m.applySessionRouteMode(session, req); err != nil {
			return vpnFailedResult(req, err), err
		}
		logs = append(logs, "[control] rule_mode="+vpnRuntimeRuleMode(req))
	}
	proxyLog, err := m.applySessionSystemProxyControl(session, req)
	if err != nil {
		return vpnFailedResult(req, err), err
	}
	if proxyLog != "" {
		logs = append(logs, proxyLog)
	}

	m.mu.Lock()
	session.Request = mergeVPNRuntimeControlRequest(session.Request, req)
	session.LastError = ""
	m.mu.Unlock()
	if err := m.persistSessionState(session); err != nil {
		err = fmt.Errorf("persist VPN runtime control state for session %s: %w", req.SessionID, err)
		return vpnFailedResult(req, err), err
	}

	return model.VPNControlResult{
		SessionID:          req.SessionID,
		RuntimeInstanceID:  session.Request.RuntimeInstanceID,
		Action:             req.Action,
		Role:               req.Role,
		State:              model.VPNStateRunning,
		LocalHTTP:          req.ListenHTTP,
		LocalSOCKS:         req.ListenSOCKS,
		TunName:            req.TunName,
		SystemProxyApplied: trackedVPNSystemProxyApplied(req, session),
		Logs:               logs,
		StartedAtUnix:      session.StartedAt.Unix(),
	}, nil
}

func (m *AgentVPNManager) applySessionRouteMode(session *AgentVPNSession, req model.VPNControlRequest) error {
	addr := vpnRuntimeControlAddress(session.Request)
	if addr == "" {
		return errors.New("sing-box runtime control API is unavailable; restart this session after upgrading agent")
	}
	finalOutbound, ruleMatchOutbound, ruleDirectOutbound := vpnSelectorOutboundsForRuleMode(req)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, item := range []struct {
		selector string
		outbound string
	}{
		{selector: vpnOutboundRuleMatch, outbound: ruleMatchOutbound},
		{selector: vpnOutboundRuleDirect, outbound: ruleDirectOutbound},
		{selector: vpnOutboundModeSelector, outbound: finalOutbound},
	} {
		if err := setSingBoxSelector(ctx, addr, item.selector, item.outbound); err != nil {
			return fmt.Errorf("set sing-box selector %s=%s: %w", item.selector, item.outbound, err)
		}
	}
	return nil
}

func (m *AgentVPNManager) applySessionSystemProxyControl(session *AgentVPNSession, req model.VPNControlRequest) (string, error) {
	wantSystemProxy := shouldApplyVPNSystemProxy(req)
	if wantSystemProxy {
		if m.systemProxyManager == nil {
			return "", errors.New("VPN system proxy manager is unavailable")
		}
		if err := m.systemProxyManager.Apply(req.ListenHTTP, req.ListenSOCKS); err != nil {
			return "", fmt.Errorf("apply VPN system proxy for session %s: %w", req.SessionID, err)
		}
		session.systemProxyApplied = true
		return "[control] system_proxy=applied", nil
	}
	if session.systemProxyApplied {
		if err := m.restoreSessionSystemProxy(session); err != nil {
			return "", fmt.Errorf("restore VPN system proxy for session %s: %w", req.SessionID, err)
		}
		return "[control] system_proxy=cleared", nil
	}
	return "[control] system_proxy=disabled", nil
}

func setSingBoxSelector(ctx context.Context, apiAddr string, selector string, outbound string) error {
	endpoint := "http://" + strings.TrimSpace(apiAddr) + "/proxies/" + url.PathEscape(selector)
	body, err := json.Marshal(map[string]string{"name": outbound})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
	return fmt.Errorf("sing-box API returned %s: %s", response.Status, strings.TrimSpace(string(raw)))
}

func inspectVPNRuntimeRuleStatus(req model.VPNControlRequest, session *AgentVPNSession) (string, string, string) {
	if req.Role != model.VPNRoleEntry {
		return "", "", ""
	}
	if session == nil || session.State != model.VPNStateRunning {
		return "inactive", "unknown", "[runtime] status=inactive rule_mode=unknown"
	}
	addr := vpnRuntimeControlAddress(req)
	if addr == "" {
		return "unknown", "unknown", "[runtime] status=unknown rule_mode=unknown error=runtime_api_missing"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	finalOutbound, err := getSingBoxSelectorNow(ctx, addr, vpnOutboundModeSelector)
	if err != nil {
		return "unknown", "unknown", "[runtime] status=unknown rule_mode=unknown error=" + err.Error()
	}
	ruleMatchOutbound, err := getSingBoxSelectorNow(ctx, addr, vpnOutboundRuleMatch)
	if err != nil {
		return "unknown", "unknown", "[runtime] status=unknown rule_mode=unknown error=" + err.Error()
	}
	ruleDirectOutbound, err := getSingBoxSelectorNow(ctx, addr, vpnOutboundRuleDirect)
	if err != nil {
		return "unknown", "unknown", "[runtime] status=unknown rule_mode=unknown error=" + err.Error()
	}
	ruleMode := vpnRuleModeFromRuntimeSelectors(req, finalOutbound, ruleMatchOutbound, ruleDirectOutbound)
	log := fmt.Sprintf("[runtime] status=available rule_mode=%s selectors=%s/%s/%s", ruleMode, finalOutbound, ruleMatchOutbound, ruleDirectOutbound)
	return "available", ruleMode, log
}

func getSingBoxSelectorNow(ctx context.Context, apiAddr string, selector string) (string, error) {
	endpoint := "http://" + strings.TrimSpace(apiAddr) + "/proxies/" + url.PathEscape(selector)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("sing-box API returned %s: %s", response.Status, strings.TrimSpace(string(raw)))
	}
	var payload struct {
		Now  string `json:"now"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	now := strings.TrimSpace(payload.Now)
	if now == "" {
		now = strings.TrimSpace(payload.Name)
	}
	if now == "" {
		return "", errors.New("sing-box selector response missing selected outbound")
	}
	return now, nil
}

func vpnRuleModeFromRuntimeSelectors(req model.VPNControlRequest, finalOutbound string, ruleMatchOutbound string, ruleDirectOutbound string) string {
	finalOutbound = strings.TrimSpace(finalOutbound)
	ruleMatchOutbound = strings.TrimSpace(ruleMatchOutbound)
	ruleDirectOutbound = strings.TrimSpace(ruleDirectOutbound)
	switch {
	case finalOutbound == vpnOutboundExit && ruleMatchOutbound == vpnOutboundExit && ruleDirectOutbound == vpnOutboundExit:
		return model.VPNRuleModeGlobal
	case finalOutbound == vpnOutboundDirect && ruleMatchOutbound == vpnOutboundDirect && ruleDirectOutbound == vpnOutboundDirect:
		return model.VPNRuleModeDirect
	case ruleMatchOutbound == vpnOutboundExit && ruleDirectOutbound == vpnOutboundDirect:
		switch vpnRuntimeRuleMode(req) {
		case model.VPNRuleModeIP:
			return model.VPNRuleModeIP
		default:
			return model.VPNRuleModeDomain
		}
	default:
		return "custom"
	}
}

func mergeVPNRuntimeControlRequest(current model.VPNControlRequest, next model.VPNControlRequest) model.VPNControlRequest {
	merged := current
	merged.Mode = normalizedVPNRuntimeMode(next.Mode)
	merged.ListenHTTP = next.ListenHTTP
	merged.ListenSOCKS = next.ListenSOCKS
	merged.TunName = next.TunName
	merged.DNSServer = next.DNSServer
	merged.Rules = next.Rules
	if merged.Extra == nil {
		merged.Extra = map[string]string{}
	}
	for key, value := range next.Extra {
		merged.Extra[key] = value
	}
	return merged
}

func vpnRuntimeModesCompatible(current string, next string) bool {
	return vpnRuntimeModeFamily(current) == vpnRuntimeModeFamily(next)
}

func vpnRuntimeModeFamily(mode string) string {
	if isVPNTunMode(normalizedVPNRuntimeMode(mode)) {
		return "tun"
	}
	return model.VPNModeSystemProxy
}

func normalizedVPNRuntimeMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case model.VPNModeTunSplit:
		return model.VPNModeTunSplit
	case model.VPNModeTunGlobal:
		return model.VPNModeTunGlobal
	default:
		return model.VPNModeSystemProxy
	}
}
