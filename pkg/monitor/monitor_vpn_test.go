package monitor

import (
	"testing"

	"github.com/nezhahq/agent/model"
)

func TestGetHostReportsVPNCapabilities(t *testing.T) {
	originalConfig := agentConfig
	originalVersion := Version
	t.Cleanup(func() {
		agentConfig = originalConfig
		Version = originalVersion
	})

	Version = "1.2.3-test"
	InitConfig(&model.AgentConfig{
		DisableVPN:          false,
		VPNAllowSystemProxy: true,
		VPNAllowTun:         true,
	})

	host := GetHost()
	payload := host.PB()

	if !payload.GetVpnEnabled() {
		t.Fatal("host report must advertise Agent VPN enabled when disable_vpn=false")
	}
	if !payload.GetVpnAllowSystemProxy() {
		t.Fatal("host report must advertise system proxy capability")
	}
	if !payload.GetVpnAllowTun() {
		t.Fatal("host report must advertise TUN capability")
	}
	if payload.GetVpnCoreVersion() != Version {
		t.Fatalf("host report must include VPN core display version, got %q", payload.GetVpnCoreVersion())
	}
	if payload.GetVpnLastError() != "" {
		t.Fatalf("host report must not include a stale VPN error, got %q", payload.GetVpnLastError())
	}
}

func TestGetHostDoesNotReportVPNCapabilitiesWhenDisabled(t *testing.T) {
	originalConfig := agentConfig
	originalVersion := Version
	t.Cleanup(func() {
		agentConfig = originalConfig
		Version = originalVersion
	})

	Version = "1.2.3-test"
	InitConfig(&model.AgentConfig{
		DisableVPN:          true,
		VPNAllowSystemProxy: true,
		VPNAllowTun:         true,
	})

	payload := GetHost().PB()
	if payload.GetVpnEnabled() {
		t.Fatal("host report must not advertise Agent VPN when disable_vpn=true")
	}
	if payload.GetVpnAllowSystemProxy() || payload.GetVpnAllowTun() {
		t.Fatalf("disabled VPN must not advertise mode capabilities: system_proxy=%v tun=%v", payload.GetVpnAllowSystemProxy(), payload.GetVpnAllowTun())
	}
	if payload.GetVpnCoreVersion() != "" {
		t.Fatalf("disabled VPN must not report a core version, got %q", payload.GetVpnCoreVersion())
	}
}

func TestGetHostReportsOnlyAllowedVPNModes(t *testing.T) {
	originalConfig := agentConfig
	originalVersion := Version
	t.Cleanup(func() {
		agentConfig = originalConfig
		Version = originalVersion
	})

	Version = "1.2.3-test"
	InitConfig(&model.AgentConfig{
		DisableVPN:          false,
		VPNAllowSystemProxy: true,
		VPNAllowTun:         false,
	})

	payload := GetHost().PB()
	if !payload.GetVpnEnabled() {
		t.Fatal("host report must advertise Agent VPN when disable_vpn=false")
	}
	if !payload.GetVpnAllowSystemProxy() {
		t.Fatal("host report must advertise allowed system_proxy mode")
	}
	if payload.GetVpnAllowTun() {
		t.Fatal("host report must not advertise disabled TUN mode")
	}
}
