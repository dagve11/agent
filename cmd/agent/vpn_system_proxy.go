package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/nezhahq/agent/model"
)

type vpnSystemProxyManager interface {
	Apply(httpAddr string, socksAddr string) error
	Restore() error
}

type unsupportedVPNSystemProxyManager struct{}

func defaultVPNSystemProxyManager() vpnSystemProxyManager {
	return newPlatformVPNSystemProxyManager()
}

func (unsupportedVPNSystemProxyManager) Apply(string, string) error {
	return errors.New("VPN system proxy setup is not supported on " + runtime.GOOS)
}

func (unsupportedVPNSystemProxyManager) Restore() error {
	return nil
}

func shouldApplyVPNSystemProxy(req model.VPNControlRequest) bool {
	if req.Role != model.VPNRoleEntry || req.Mode != model.VPNModeSystemProxy {
		return false
	}
	return vpnBoolExtra(req.Extra, "set_system_proxy") || vpnBoolExtra(req.Extra, "apply_system_proxy")
}

func trackedVPNSystemProxyApplied(req model.VPNControlRequest, session *AgentVPNSession) *bool {
	if req.Role != model.VPNRoleEntry || req.Mode != model.VPNModeSystemProxy {
		return nil
	}
	applied := session != nil && session.systemProxyApplied
	return &applied
}

func inspectVPNSystemProxyApplied(req model.VPNControlRequest) (*bool, string) {
	if req.Role != model.VPNRoleEntry || req.Mode != model.VPNModeSystemProxy {
		return nil, ""
	}
	if !shouldApplyVPNSystemProxy(req) {
		applied := false
		return &applied, "[system_proxy] status=cleared"
	}
	applied, detail, err := platformVPNSystemProxyApplied(req.ListenHTTP, req.ListenSOCKS)
	if err != nil {
		return nil, "[system_proxy] status=unknown error=" + err.Error()
	}
	status := "drifted"
	if applied {
		status = "applied"
	}
	if detail != "" {
		detail = " " + detail
	}
	return &applied, fmt.Sprintf("[system_proxy] status=%s%s", status, detail)
}

func vpnBoolExtra(values map[string]string, key string) bool {
	if values == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(values[key])) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
