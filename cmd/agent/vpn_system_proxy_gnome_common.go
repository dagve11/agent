package main

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

type linuxSystemProxyBackend struct {
	Name          string
	ReadCommand   string
	WriteCommand  string
	NotifyCommand string
}

type linuxGSettingsProxyState struct {
	Schema string `json:"schema"`
	Key    string `json:"key"`
	Raw    string `json:"raw"`
}

var linuxGSettingsProxyKeys = []linuxGSettingsProxyState{
	{Schema: "org.gnome.system.proxy.http", Key: "host"},
	{Schema: "org.gnome.system.proxy.http", Key: "port"},
	{Schema: "org.gnome.system.proxy.http", Key: "enabled"},
	{Schema: "org.gnome.system.proxy.https", Key: "host"},
	{Schema: "org.gnome.system.proxy.https", Key: "port"},
	{Schema: "org.gnome.system.proxy.socks", Key: "host"},
	{Schema: "org.gnome.system.proxy.socks", Key: "port"},
	{Schema: "org.gnome.system.proxy", Key: "mode"},
}

func buildLinuxGSettingsProxyApplyCommands(httpAddr string, socksAddr string) ([]vpnTunCommand, error) {
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

	var commands []vpnTunCommand
	if hasHTTP {
		commands = append(commands,
			linuxGSettingsSetCommand("org.gnome.system.proxy.http", "host", linuxGVariantString(httpHost)),
			linuxGSettingsSetCommand("org.gnome.system.proxy.http", "port", httpPort),
			linuxGSettingsSetCommand("org.gnome.system.proxy.http", "enabled", "true"),
			linuxGSettingsSetCommand("org.gnome.system.proxy.https", "host", linuxGVariantString(httpHost)),
			linuxGSettingsSetCommand("org.gnome.system.proxy.https", "port", httpPort),
		)
	} else {
		commands = append(commands,
			linuxGSettingsSetCommand("org.gnome.system.proxy.http", "host", "''"),
			linuxGSettingsSetCommand("org.gnome.system.proxy.http", "port", "0"),
			linuxGSettingsSetCommand("org.gnome.system.proxy.http", "enabled", "false"),
			linuxGSettingsSetCommand("org.gnome.system.proxy.https", "host", "''"),
			linuxGSettingsSetCommand("org.gnome.system.proxy.https", "port", "0"),
		)
	}
	if hasSOCKS {
		commands = append(commands,
			linuxGSettingsSetCommand("org.gnome.system.proxy.socks", "host", linuxGVariantString(socksHost)),
			linuxGSettingsSetCommand("org.gnome.system.proxy.socks", "port", socksPort),
		)
	} else {
		commands = append(commands,
			linuxGSettingsSetCommand("org.gnome.system.proxy.socks", "host", "''"),
			linuxGSettingsSetCommand("org.gnome.system.proxy.socks", "port", "0"),
		)
	}
	commands = append(commands, linuxGSettingsSetCommand("org.gnome.system.proxy", "mode", "'manual'"))
	return commands, nil
}

func buildLinuxGSettingsProxyRestoreCommands(states []linuxGSettingsProxyState) []vpnTunCommand {
	commands := make([]vpnTunCommand, 0, len(states))
	for _, state := range states {
		if strings.TrimSpace(state.Schema) == "" || strings.TrimSpace(state.Key) == "" {
			continue
		}
		commands = append(commands, linuxGSettingsSetCommand(state.Schema, state.Key, strings.TrimSpace(state.Raw)))
	}
	return commands
}

func linuxSplitProxyListen(address string) (string, string, bool, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", "", false, nil
	}
	host, port, err := splitListenAddress(address)
	if err != nil {
		return "", "", false, err
	}
	return host, strconv.Itoa(port), true, nil
}

func linuxGVariantString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "\\'") + "'"
}

func linuxGSettingsSetCommand(schema string, key string, value string) vpnTunCommand {
	return vpnTunCommand{Name: "gsettings", Args: []string{"set", schema, key, value}}
}

type linuxEnvProxyState struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Set   bool   `json:"set"`
}

var linuxEnvProxyKeys = []string{
	"http_proxy",
	"https_proxy",
	"HTTP_PROXY",
	"HTTPS_PROXY",
	"all_proxy",
	"ALL_PROXY",
}

func buildLinuxEnvProxyApplyCommands(backend linuxSystemProxyBackend, httpAddr string, socksAddr string) ([]vpnTunCommand, error) {
	assignments, err := buildLinuxEnvProxyAssignments(httpAddr, socksAddr)
	if err != nil {
		return nil, err
	}

	var commands []vpnTunCommand
	if strings.TrimSpace(backend.WriteCommand) != "" {
		commands = append(commands, vpnTunCommand{
			Name: backend.WriteCommand,
			Args: append([]string{"--user", "set-environment"}, assignments...),
		})
	}
	if strings.TrimSpace(backend.NotifyCommand) != "" {
		commands = append(commands, vpnTunCommand{
			Name: backend.NotifyCommand,
			Args: append([]string{"--systemd"}, assignments...),
		})
	}
	if len(commands) == 0 {
		return nil, errors.New("linux environment proxy backend requires systemctl or dbus-update-activation-environment")
	}
	return commands, nil
}

func buildLinuxEnvProxyRestoreCommands(writeCommand string, notifyCommand string, states []linuxEnvProxyState) []vpnTunCommand {
	var setAssignments []string
	var unsetNames []string
	var dbusAssignments []string
	for _, state := range states {
		name := strings.TrimSpace(state.Name)
		if name == "" {
			continue
		}
		if state.Set {
			assignment := name + "=" + state.Value
			setAssignments = append(setAssignments, assignment)
			dbusAssignments = append(dbusAssignments, assignment)
		} else {
			unsetNames = append(unsetNames, name)
			// D-Bus activation environment has no unset operation; empty value is the closest reversible fallback.
			dbusAssignments = append(dbusAssignments, name+"=")
		}
	}

	var commands []vpnTunCommand
	if strings.TrimSpace(writeCommand) != "" {
		if len(setAssignments) > 0 {
			commands = append(commands, vpnTunCommand{
				Name: writeCommand,
				Args: append([]string{"--user", "set-environment"}, setAssignments...),
			})
		}
		if len(unsetNames) > 0 {
			commands = append(commands, vpnTunCommand{
				Name: writeCommand,
				Args: append([]string{"--user", "unset-environment"}, unsetNames...),
			})
		}
	}
	if strings.TrimSpace(notifyCommand) != "" && len(dbusAssignments) > 0 {
		commands = append(commands, vpnTunCommand{
			Name: notifyCommand,
			Args: append([]string{"--systemd"}, dbusAssignments...),
		})
	}
	return commands
}

func buildLinuxEnvProxyAssignments(httpAddr string, socksAddr string) ([]string, error) {
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
	if hasHTTP {
		httpProxy = "http://" + httpHost + ":" + httpPort
	}
	socksProxy := ""
	if hasSOCKS {
		socksProxy = "socks5://" + socksHost + ":" + socksPort
	}
	return []string{
		"http_proxy=" + httpProxy,
		"https_proxy=" + httpProxy,
		"HTTP_PROXY=" + httpProxy,
		"HTTPS_PROXY=" + httpProxy,
		"all_proxy=" + socksProxy,
		"ALL_PROXY=" + socksProxy,
	}, nil
}

func collectLinuxEnvProxyStates(readCommand string) ([]linuxEnvProxyState, error) {
	values := map[string]string{}
	if strings.TrimSpace(readCommand) != "" {
		raw, err := runVPNTunCommandOutput(readCommand, "--user", "show-environment")
		if err != nil {
			return nil, err
		}
		values = parseLinuxEnvProxyEnvironment(raw)
	}

	states := make([]linuxEnvProxyState, 0, len(linuxEnvProxyKeys))
	for _, key := range linuxEnvProxyKeys {
		value, ok := values[key]
		if strings.TrimSpace(readCommand) == "" {
			value, ok = os.LookupEnv(key)
		}
		states = append(states, linuxEnvProxyState{
			Name:  key,
			Value: value,
			Set:   ok,
		})
	}
	return states, nil
}

func parseLinuxEnvProxyEnvironment(raw string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(name) == "" {
			continue
		}
		values[name] = value
	}
	return values
}
