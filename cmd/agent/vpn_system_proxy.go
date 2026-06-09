package main

import (
	"errors"
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
