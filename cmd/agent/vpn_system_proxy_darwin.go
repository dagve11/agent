//go:build darwin

package main

import "sync"

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
