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

type vpnSystemProxyInspection struct {
	Applied  bool
	Status   string
	Current  string
	Expected string
	Detail   string
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

func inspectVPNSystemProxyStatus(req model.VPNControlRequest) (vpnSystemProxyInspection, string) {
	if req.Role != model.VPNRoleEntry {
		return vpnSystemProxyInspection{}, ""
	}
	if req.Mode != model.VPNModeSystemProxy {
		return vpnSystemProxyInspection{Status: "inactive"}, "[system_proxy] status=inactive"
	}
	inspection, err := platformVPNSystemProxyStatus(req.ListenHTTP, req.ListenSOCKS)
	if err != nil {
		expected := formatVPNSystemProxyExpected(req.ListenHTTP, req.ListenSOCKS)
		return vpnSystemProxyInspection{
			Status:   "unknown",
			Expected: expected,
		}, "[system_proxy] status=unknown expected=" + emptyVPNStatusValue(expected) + " error=" + err.Error()
	}
	status := strings.TrimSpace(inspection.Status)
	if status == "" {
		if inspection.Applied {
			status = "applied"
		} else {
			status = "overridden"
		}
		inspection.Status = status
	}
	parts := []string{"[system_proxy] status=" + status}
	if inspection.Current != "" {
		parts = append(parts, "current="+inspection.Current)
	}
	if inspection.Expected != "" {
		parts = append(parts, "expected="+inspection.Expected)
	}
	if inspection.Detail != "" {
		parts = append(parts, inspection.Detail)
	}
	return inspection, strings.Join(parts, " ")
}

func formatVPNSystemProxyExpected(httpAddr string, socksAddr string) string {
	httpAddr = strings.TrimSpace(httpAddr)
	socksAddr = strings.TrimSpace(socksAddr)
	parts := make([]string, 0, 3)
	if httpAddr != "" {
		parts = append(parts, "http="+httpAddr, "https="+httpAddr)
	}
	if socksAddr != "" {
		parts = append(parts, "socks="+socksAddr)
	}
	return strings.Join(parts, ";")
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
