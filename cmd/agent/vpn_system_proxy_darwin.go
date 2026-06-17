//go:build darwin

package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

type darwinVPNSystemProxyManager struct {
	mu      sync.Mutex
	applied bool
	states  []darwinVPNProxyState
}

func newPlatformVPNSystemProxyManager() vpnSystemProxyManager {
	return &darwinVPNSystemProxyManager{}
}

func (m *darwinVPNSystemProxyManager) Apply(httpAddr string, socksAddr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	servicesRaw, err := runVPNTunCommandOutput("networksetup", "-listallnetworkservices")
	if err != nil {
		return err
	}
	services := parseDarwinNetworkServices(servicesRaw)
	if !m.applied {
		states, err := collectDarwinProxyStates(services)
		if err != nil {
			return err
		}
		m.states = states
	}
	commands, err := buildDarwinSystemProxyApplyCommands(services, httpAddr, socksAddr)
	if err != nil {
		return err
	}
	for _, command := range commands {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	m.applied = true
	return nil
}

func (m *darwinVPNSystemProxyManager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.applied {
		return nil
	}
	for _, command := range buildDarwinSystemProxyRestoreCommands(m.states) {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	m.applied = false
	m.states = nil
	return nil
}

func (m *darwinVPNSystemProxyManager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	servicesRaw, err := runVPNTunCommandOutput("networksetup", "-listallnetworkservices")
	if err != nil {
		return err
	}
	for _, command := range buildDarwinSystemProxyClearCommands(parseDarwinNetworkServices(servicesRaw)) {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	return nil
}

func (m *darwinVPNSystemProxyManager) Inspect(httpAddr string, socksAddr string) (vpnSystemProxyInspection, error) {
	return platformVPNSystemProxyStatus(httpAddr, socksAddr)
}

func collectDarwinProxyStates(services []string) ([]darwinVPNProxyState, error) {
	var states []darwinVPNProxyState
	for _, service := range services {
		for _, kind := range darwinProxyKinds {
			raw, err := runVPNTunCommandOutput("networksetup", darwinProxyGetCommand(kind), service)
			if err != nil {
				return nil, err
			}
			states = append(states, parseDarwinProxyState(service, kind, raw))
		}
	}
	return states, nil
}

func platformVPNSystemProxyStatus(httpAddr string, socksAddr string) (vpnSystemProxyInspection, error) {
	servicesRaw, err := runVPNTunCommandOutput("networksetup", "-listallnetworkservices")
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	services := parseDarwinNetworkServices(servicesRaw)
	if len(services) == 0 {
		return vpnSystemProxyInspection{}, errors.New("no macOS network service found for system proxy")
	}
	states, err := collectDarwinProxyStates(services)
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	httpHost, httpPort, hasHTTP, err := darwinSplitProxyListen(httpAddr)
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	socksHost, socksPort, hasSOCKS, err := darwinSplitProxyListen(socksAddr)
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	if !hasHTTP && !hasSOCKS {
		return vpnSystemProxyInspection{}, errors.New("system proxy requires http or socks listen address")
	}
	totalExpected := 0
	matched := 0
	enabled := 0
	for _, state := range states {
		if state.Enabled {
			enabled++
		}
		switch state.Kind {
		case darwinProxyKindWeb, darwinProxyKindSecureWeb:
			if !hasHTTP {
				continue
			}
			totalExpected++
			if state.Enabled && darwinProxyStateMatches(state, httpHost, httpPort) {
				matched++
			}
		case darwinProxyKindSocks:
			if !hasSOCKS {
				continue
			}
			totalExpected++
			if state.Enabled && darwinProxyStateMatches(state, socksHost, socksPort) {
				matched++
			}
		}
	}
	status := "overridden"
	if totalExpected > 0 && matched == totalExpected {
		status = "applied"
	} else if enabled == 0 {
		status = "disabled"
	}
	return vpnSystemProxyInspection{
		Applied:  status == "applied",
		Status:   status,
		Current:  fmt.Sprintf("services=%d matched=%d enabled=%d %s", len(services), matched, enabled, darwinProxyCurrentSummary(states)),
		Expected: formatVPNSystemProxyExpected(httpAddr, socksAddr),
	}, nil
}

func darwinProxyStateMatches(state darwinVPNProxyState, host string, port string) bool {
	return strings.EqualFold(strings.TrimSpace(state.Server), strings.TrimSpace(host)) &&
		strings.TrimSpace(state.Port) == strings.TrimSpace(port)
}

func darwinProxyCurrentSummary(states []darwinVPNProxyState) string {
	parts := make([]string, 0, 3)
	for _, state := range states {
		if !state.Enabled || strings.TrimSpace(state.Server) == "" || strings.TrimSpace(state.Port) == "" {
			continue
		}
		parts = append(parts, state.Kind+"="+state.Server+":"+state.Port)
		if len(parts) >= 3 {
			break
		}
	}
	return "proxy=" + emptyVPNStatusValue(strings.Join(parts, "|"))
}
