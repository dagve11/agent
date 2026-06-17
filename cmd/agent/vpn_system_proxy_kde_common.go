package main

import (
	"errors"
	"strings"
)

const linuxKDEProxyConfigFile = "kioslaverc"
const linuxKDEProxyConfigGroup = "Proxy Settings"

var linuxKDEProxyKeys = []string{
	"ProxyType",
	"Authmode",
	"httpProxy",
	"httpsProxy",
	"socksProxy",
	"NoProxyFor",
}

type linuxKDEProxyState struct {
	Key string `json:"key"`
	Raw string `json:"raw"`
}

func buildLinuxKDEProxyReadCommands(readCommand string) []vpnTunCommand {
	commands := make([]vpnTunCommand, 0, len(linuxKDEProxyKeys))
	for _, key := range linuxKDEProxyKeys {
		commands = append(commands, linuxKDEConfigCommand(readCommand, key))
	}
	return commands
}

func buildLinuxKDEProxyApplyCommands(writeCommand string, httpAddr string, socksAddr string) ([]vpnTunCommand, error) {
	httpHost, httpPort, hasHTTP, err := linuxSplitProxyListen(httpAddr)
	if err != nil {
		return nil, err
	}
	socksHost, socksPort, hasSOCKS, err := linuxSplitProxyListen(socksAddr)
	if err != nil {
		return nil, err
	}
	if !hasHTTP && !hasSOCKS {
		return nil, errors.New("system proxy requires http or socks listen address")
	}

	httpProxy := ""
	httpsProxy := ""
	if hasHTTP {
		httpProxy = "http://" + httpHost + ":" + httpPort
		httpsProxy = httpProxy
	}
	socksProxy := ""
	if hasSOCKS {
		socksProxy = "socks://" + socksHost + ":" + socksPort
	}
	return []vpnTunCommand{
		linuxKDEConfigSetCommand(writeCommand, "ProxyType", "1"),
		linuxKDEConfigSetCommand(writeCommand, "Authmode", "0"),
		linuxKDEConfigSetCommand(writeCommand, "httpProxy", httpProxy),
		linuxKDEConfigSetCommand(writeCommand, "httpsProxy", httpsProxy),
		linuxKDEConfigSetCommand(writeCommand, "socksProxy", socksProxy),
	}, nil
}

func buildLinuxKDEProxyRestoreCommands(writeCommand string, states []linuxKDEProxyState) []vpnTunCommand {
	commands := make([]vpnTunCommand, 0, len(states))
	for _, state := range states {
		if strings.TrimSpace(state.Key) == "" {
			continue
		}
		commands = append(commands, linuxKDEConfigSetCommand(writeCommand, state.Key, state.Raw))
	}
	return commands
}

func buildLinuxKDEProxyClearCommands(writeCommand string) []vpnTunCommand {
	return []vpnTunCommand{
		linuxKDEConfigSetCommand(writeCommand, "ProxyType", "0"),
		linuxKDEConfigSetCommand(writeCommand, "Authmode", "0"),
		linuxKDEConfigSetCommand(writeCommand, "httpProxy", ""),
		linuxKDEConfigSetCommand(writeCommand, "httpsProxy", ""),
		linuxKDEConfigSetCommand(writeCommand, "socksProxy", ""),
	}
}

func linuxKDEConfigCommand(name string, key string) vpnTunCommand {
	return vpnTunCommand{
		Name: name,
		Args: []string{
			"--file", linuxKDEProxyConfigFile,
			"--group", linuxKDEProxyConfigGroup,
			"--key", key,
		},
	}
}

func linuxKDEConfigSetCommand(name string, key string, value string) vpnTunCommand {
	command := linuxKDEConfigCommand(name, key)
	command.Args = append(command.Args, value)
	return command
}

func linuxKDEProxyNotifyCommand(name string) vpnTunCommand {
	return vpnTunCommand{
		Name: name,
		Args: []string{
			"--type=signal",
			"/KIO/Scheduler",
			"org.kde.KIO.Scheduler.reparseSlaveConfiguration",
			"string:",
		},
	}
}
