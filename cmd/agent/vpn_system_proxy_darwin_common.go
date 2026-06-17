package main

import (
	"errors"
	"strings"
)

const (
	darwinProxyKindWeb       = "web"
	darwinProxyKindSecureWeb = "secureweb"
	darwinProxyKindSocks     = "socks"
)

var darwinProxyKinds = []string{
	darwinProxyKindWeb,
	darwinProxyKindSecureWeb,
	darwinProxyKindSocks,
}

type darwinVPNProxyState struct {
	Service string `json:"service"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	Server  string `json:"server,omitempty"`
	Port    string `json:"port,omitempty"`
}

func parseDarwinProxyState(service string, kind string, raw string) darwinVPNProxyState {
	state := darwinVPNProxyState{
		Service: service,
		Kind:    kind,
	}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "enabled":
			state.Enabled = strings.EqualFold(value, "yes") || value == "1"
		case "server":
			state.Server = value
		case "port":
			state.Port = value
		}
	}
	return state
}

func buildDarwinSystemProxyApplyCommands(services []string, httpAddr string, socksAddr string) ([]vpnTunCommand, error) {
	httpHost, httpPort, hasHTTP, err := darwinSplitProxyListen(httpAddr)
	if err != nil {
		return nil, err
	}
	socksHost, socksPort, hasSOCKS, err := darwinSplitProxyListen(socksAddr)
	if err != nil {
		return nil, err
	}
	if !hasHTTP && !hasSOCKS {
		return nil, errors.New("system proxy requires http or socks listen address")
	}

	var commands []vpnTunCommand
	for _, service := range services {
		service = strings.TrimSpace(service)
		if service == "" {
			continue
		}
		if hasHTTP {
			commands = append(commands,
				vpnTunCommand{Name: "networksetup", Args: []string{"-setwebproxy", service, httpHost, httpPort}},
				vpnTunCommand{Name: "networksetup", Args: []string{"-setwebproxystate", service, "on"}},
				vpnTunCommand{Name: "networksetup", Args: []string{"-setsecurewebproxy", service, httpHost, httpPort}},
				vpnTunCommand{Name: "networksetup", Args: []string{"-setsecurewebproxystate", service, "on"}},
			)
		}
		if hasSOCKS {
			commands = append(commands,
				vpnTunCommand{Name: "networksetup", Args: []string{"-setsocksfirewallproxy", service, socksHost, socksPort}},
				vpnTunCommand{Name: "networksetup", Args: []string{"-setsocksfirewallproxystate", service, "on"}},
			)
		}
	}
	return commands, nil
}

func buildDarwinSystemProxyRestoreCommands(states []darwinVPNProxyState) []vpnTunCommand {
	var commands []vpnTunCommand
	for _, state := range states {
		if strings.TrimSpace(state.Service) == "" {
			continue
		}
		if state.Server != "" && state.Port != "" {
			commands = append(commands, vpnTunCommand{
				Name: "networksetup",
				Args: []string{darwinProxySetCommand(state.Kind), state.Service, state.Server, state.Port},
			})
		}
		commands = append(commands, vpnTunCommand{
			Name: "networksetup",
			Args: []string{darwinProxyStateCommand(state.Kind), state.Service, darwinProxyStateValue(state.Enabled)},
		})
	}
	return commands
}

func buildDarwinSystemProxyClearCommands(services []string) []vpnTunCommand {
	var commands []vpnTunCommand
	for _, service := range services {
		service = strings.TrimSpace(service)
		if service == "" {
			continue
		}
		for _, kind := range darwinProxyKinds {
			commands = append(commands, vpnTunCommand{
				Name: "networksetup",
				Args: []string{darwinProxyStateCommand(kind), service, "off"},
			})
		}
	}
	return commands
}

func darwinSplitProxyListen(address string) (string, string, bool, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", "", false, nil
	}
	host, port, err := splitListenAddress(address)
	if err != nil {
		return "", "", false, err
	}
	return host, intString(port), true, nil
}

func darwinProxyGetCommand(kind string) string {
	switch kind {
	case darwinProxyKindSecureWeb:
		return "-getsecurewebproxy"
	case darwinProxyKindSocks:
		return "-getsocksfirewallproxy"
	default:
		return "-getwebproxy"
	}
}

func darwinProxySetCommand(kind string) string {
	switch kind {
	case darwinProxyKindSecureWeb:
		return "-setsecurewebproxy"
	case darwinProxyKindSocks:
		return "-setsocksfirewallproxy"
	default:
		return "-setwebproxy"
	}
}

func darwinProxyStateCommand(kind string) string {
	switch kind {
	case darwinProxyKindSecureWeb:
		return "-setsecurewebproxystate"
	case darwinProxyKindSocks:
		return "-setsocksfirewallproxystate"
	default:
		return "-setwebproxystate"
	}
}

func darwinProxyStateValue(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}
