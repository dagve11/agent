//go:build linux

package main

import (
	"errors"
	"os/exec"
	"strings"
	"sync"
)

type linuxVPNSystemProxyManager struct {
	mu               sync.Mutex
	applied          bool
	backend          string
	gsettingsStates  []linuxGSettingsProxyState
	kdeStates        []linuxKDEProxyState
	envStates        []linuxEnvProxyState
	kdeWriteCommand  string
	kdeNotifyCommand string
	envReadCommand   string
	envWriteCommand  string
	envNotifyCommand string
}

func newPlatformVPNSystemProxyManager() vpnSystemProxyManager {
	return &linuxVPNSystemProxyManager{}
}

func (m *linuxVPNSystemProxyManager) Apply(httpAddr string, socksAddr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	backend, err := detectLinuxSystemProxyBackend()
	if err != nil {
		return err
	}
	if !m.applied {
		m.backend = backend.Name
		switch backend.Name {
		case "gsettings":
			states, err := collectLinuxGSettingsProxyStates()
			if err != nil {
				return err
			}
			m.gsettingsStates = states
		case "kde":
			states, err := collectLinuxKDEProxyStates(backend.ReadCommand)
			if err != nil {
				return err
			}
			m.kdeStates = states
			m.kdeWriteCommand = backend.WriteCommand
			m.kdeNotifyCommand = backend.NotifyCommand
		case "environment":
			states, err := collectLinuxEnvProxyStates(backend.ReadCommand)
			if err != nil {
				return err
			}
			m.envStates = states
			m.envReadCommand = backend.ReadCommand
			m.envWriteCommand = backend.WriteCommand
			m.envNotifyCommand = backend.NotifyCommand
		}
	}
	commands, err := buildLinuxSystemProxyApplyCommands(backend, httpAddr, socksAddr)
	if err != nil {
		return err
	}
	for _, command := range commands {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	if backend.Name == "kde" && strings.TrimSpace(backend.NotifyCommand) != "" {
		if err := runVPNTunCommand(linuxKDEProxyNotifyCommand(backend.NotifyCommand)); err != nil {
			return err
		}
	}
	m.applied = true
	return nil
}

func (m *linuxVPNSystemProxyManager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.applied {
		return nil
	}
	for _, command := range m.restoreCommands() {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	if m.backend == "kde" && strings.TrimSpace(m.kdeNotifyCommand) != "" {
		if err := runVPNTunCommand(linuxKDEProxyNotifyCommand(m.kdeNotifyCommand)); err != nil {
			return err
		}
	}
	m.applied = false
	m.backend = ""
	m.gsettingsStates = nil
	m.kdeStates = nil
	m.envStates = nil
	m.kdeWriteCommand = ""
	m.kdeNotifyCommand = ""
	m.envReadCommand = ""
	m.envWriteCommand = ""
	m.envNotifyCommand = ""
	return nil
}

func (m *linuxVPNSystemProxyManager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	backend, err := m.clearBackend()
	if err != nil {
		return err
	}
	for _, command := range buildLinuxSystemProxyClearCommands(backend) {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	if backend.Name == "kde" && strings.TrimSpace(backend.NotifyCommand) != "" {
		if err := runVPNTunCommand(linuxKDEProxyNotifyCommand(backend.NotifyCommand)); err != nil {
			return err
		}
	}
	return nil
}

func (m *linuxVPNSystemProxyManager) Inspect(httpAddr string, socksAddr string) (vpnSystemProxyInspection, error) {
	return platformVPNSystemProxyStatus(httpAddr, socksAddr)
}

func (m *linuxVPNSystemProxyManager) clearBackend() (linuxSystemProxyBackend, error) {
	if m.applied {
		return linuxSystemProxyBackend{
			Name:          m.backend,
			WriteCommand:  firstNonEmptyString(m.kdeWriteCommand, m.envWriteCommand),
			NotifyCommand: firstNonEmptyString(m.kdeNotifyCommand, m.envNotifyCommand),
		}, nil
	}
	return detectLinuxSystemProxyBackend()
}

func detectLinuxSystemProxyBackend() (linuxSystemProxyBackend, error) {
	if _, err := exec.LookPath("gsettings"); err == nil {
		return linuxSystemProxyBackend{Name: "gsettings"}, nil
	}
	if writeCommand := firstExecutable("kwriteconfig6", "kwriteconfig5", "kwriteconfig"); writeCommand != "" {
		if readCommand := firstExecutable("kreadconfig6", "kreadconfig5", "kreadconfig"); readCommand != "" {
			return linuxSystemProxyBackend{
				Name:          "kde",
				ReadCommand:   readCommand,
				WriteCommand:  writeCommand,
				NotifyCommand: firstExecutable("dbus-send"),
			}, nil
		}
	}
	if writeCommand := firstExecutable("systemctl"); writeCommand != "" {
		return linuxSystemProxyBackend{
			Name:          "environment",
			ReadCommand:   writeCommand,
			WriteCommand:  writeCommand,
			NotifyCommand: firstExecutable("dbus-update-activation-environment"),
		}, nil
	}
	if notifyCommand := firstExecutable("dbus-update-activation-environment"); notifyCommand != "" {
		return linuxSystemProxyBackend{
			Name:          "environment",
			NotifyCommand: notifyCommand,
		}, nil
	}
	return linuxSystemProxyBackend{}, errors.New("VPN system proxy setup requires GNOME gsettings, KDE kreadconfig/kwriteconfig, or systemd/dbus user environment support on linux")
}

func firstExecutable(names ...string) string {
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil && strings.TrimSpace(path) != "" {
			return name
		}
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func buildLinuxSystemProxyApplyCommands(backend linuxSystemProxyBackend, httpAddr string, socksAddr string) ([]vpnTunCommand, error) {
	switch backend.Name {
	case "gsettings":
		return buildLinuxGSettingsProxyApplyCommands(httpAddr, socksAddr)
	case "kde":
		return buildLinuxKDEProxyApplyCommands(backend.WriteCommand, httpAddr, socksAddr)
	case "environment":
		return buildLinuxEnvProxyApplyCommands(backend, httpAddr, socksAddr)
	default:
		return nil, errors.New("unsupported linux system proxy backend")
	}
}

func buildLinuxSystemProxyClearCommands(backend linuxSystemProxyBackend) []vpnTunCommand {
	switch backend.Name {
	case "gsettings":
		return buildLinuxGSettingsProxyClearCommands()
	case "kde":
		return buildLinuxKDEProxyClearCommands(backend.WriteCommand)
	case "environment":
		return buildLinuxEnvProxyClearCommands(backend.WriteCommand, backend.NotifyCommand)
	default:
		return nil
	}
}

func (m *linuxVPNSystemProxyManager) restoreCommands() []vpnTunCommand {
	switch m.backend {
	case "gsettings":
		return buildLinuxGSettingsProxyRestoreCommands(m.gsettingsStates)
	case "kde":
		return buildLinuxKDEProxyRestoreCommands(m.kdeWriteCommand, m.kdeStates)
	case "environment":
		return buildLinuxEnvProxyRestoreCommands(m.envWriteCommand, m.envNotifyCommand, m.envStates)
	default:
		return nil
	}
}

func collectLinuxGSettingsProxyStates() ([]linuxGSettingsProxyState, error) {
	states := make([]linuxGSettingsProxyState, 0, len(linuxGSettingsProxyKeys))
	for _, key := range linuxGSettingsProxyKeys {
		raw, err := runVPNTunCommandOutput("gsettings", "get", key.Schema, key.Key)
		if err != nil {
			return nil, err
		}
		key.Raw = strings.TrimSpace(raw)
		states = append(states, key)
	}
	return states, nil
}

func collectLinuxKDEProxyStates(readCommand string) ([]linuxKDEProxyState, error) {
	commands := buildLinuxKDEProxyReadCommands(readCommand)
	states := make([]linuxKDEProxyState, 0, len(commands))
	for _, command := range commands {
		raw, err := runVPNTunCommandOutput(command.Name, command.Args...)
		if err != nil {
			return nil, err
		}
		states = append(states, linuxKDEProxyState{
			Key: command.Args[len(command.Args)-1],
			Raw: strings.TrimSpace(raw),
		})
	}
	return states, nil
}

func platformVPNSystemProxyStatus(httpAddr string, socksAddr string) (vpnSystemProxyInspection, error) {
	backend, err := detectLinuxSystemProxyBackend()
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	switch backend.Name {
	case "gsettings":
		return inspectLinuxGSettingsProxyStatus(httpAddr, socksAddr)
	case "kde":
		return inspectLinuxKDEProxyStatus(backend, httpAddr, socksAddr)
	case "environment":
		return inspectLinuxEnvProxyStatus(backend, httpAddr, socksAddr)
	default:
		return vpnSystemProxyInspection{}, errors.New("unsupported linux system proxy backend")
	}
}

func inspectLinuxGSettingsProxyStatus(httpAddr string, socksAddr string) (vpnSystemProxyInspection, error) {
	states, err := collectLinuxGSettingsProxyStates()
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	values := linuxGSettingsProxyStateMap(states)
	mode := linuxProxyUnquote(values["org.gnome.system.proxy/mode"])
	httpExpected, socksExpected, hasHTTP, hasSOCKS, err := linuxExpectedProxyAddresses(httpAddr, socksAddr)
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	httpCurrent := linuxHostPort(values["org.gnome.system.proxy.http/host"], values["org.gnome.system.proxy.http/port"])
	httpsCurrent := linuxHostPort(values["org.gnome.system.proxy.https/host"], values["org.gnome.system.proxy.https/port"])
	socksCurrent := linuxHostPort(values["org.gnome.system.proxy.socks/host"], values["org.gnome.system.proxy.socks/port"])
	current := "backend=gsettings mode=" + emptyVPNStatusValue(mode) + " http=" + emptyVPNStatusValue(httpCurrent) + " https=" + emptyVPNStatusValue(httpsCurrent) + " socks=" + emptyVPNStatusValue(socksCurrent)
	if mode != "manual" {
		return vpnSystemProxyInspection{Status: "disabled", Current: current, Expected: formatVPNSystemProxyExpected(httpAddr, socksAddr)}, nil
	}
	matched := true
	if hasHTTP {
		matched = linuxProxyAddressEqual(httpCurrent, httpExpected) && linuxProxyAddressEqual(httpsCurrent, httpExpected)
	}
	if hasSOCKS {
		matched = matched && linuxProxyAddressEqual(socksCurrent, socksExpected)
	}
	status := "overridden"
	if matched {
		status = "applied"
	}
	return vpnSystemProxyInspection{Applied: status == "applied", Status: status, Current: current, Expected: formatVPNSystemProxyExpected(httpAddr, socksAddr)}, nil
}

func inspectLinuxKDEProxyStatus(backend linuxSystemProxyBackend, httpAddr string, socksAddr string) (vpnSystemProxyInspection, error) {
	states, err := collectLinuxKDEProxyStates(backend.ReadCommand)
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	values := linuxKDEProxyStateMap(states)
	httpExpected, socksExpected, hasSOCKS, err := linuxExpectedProxyURLs(httpAddr, socksAddr, "socks")
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	hasHTTP := strings.TrimSpace(httpExpected) != ""
	current := "backend=kde type=" + emptyVPNStatusValue(values["ProxyType"]) + " http=" + emptyVPNStatusValue(values["httpProxy"]) + " https=" + emptyVPNStatusValue(values["httpsProxy"]) + " socks=" + emptyVPNStatusValue(values["socksProxy"])
	if strings.TrimSpace(values["ProxyType"]) != "1" {
		return vpnSystemProxyInspection{Status: "disabled", Current: current, Expected: formatVPNSystemProxyExpected(httpAddr, socksAddr)}, nil
	}
	matched := true
	if hasHTTP {
		matched = linuxProxyAddressEqual(values["httpProxy"], httpExpected) && linuxProxyAddressEqual(values["httpsProxy"], httpExpected)
	}
	if hasSOCKS {
		matched = matched && linuxProxyAddressEqual(values["socksProxy"], socksExpected)
	}
	status := "overridden"
	if matched {
		status = "applied"
	}
	return vpnSystemProxyInspection{Applied: status == "applied", Status: status, Current: current, Expected: formatVPNSystemProxyExpected(httpAddr, socksAddr)}, nil
}

func inspectLinuxEnvProxyStatus(backend linuxSystemProxyBackend, httpAddr string, socksAddr string) (vpnSystemProxyInspection, error) {
	states, err := collectLinuxEnvProxyStates(backend.ReadCommand)
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	currentValues := make(map[string]string, len(states))
	enabled := 0
	for _, state := range states {
		currentValues[state.Name] = state.Value
		if state.Set && strings.TrimSpace(state.Value) != "" {
			enabled++
		}
	}
	expectedAssignments, err := buildLinuxEnvProxyAssignments(httpAddr, socksAddr)
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	expectedValues := parseLinuxEnvProxyEnvironment(strings.Join(expectedAssignments, "\n"))
	matched := true
	for name, expected := range expectedValues {
		if strings.TrimSpace(expected) == "" {
			continue
		}
		if !linuxProxyAddressEqual(currentValues[name], expected) {
			matched = false
			break
		}
	}
	current := "backend=environment http=" + emptyVPNStatusValue(currentValues["http_proxy"]) + " https=" + emptyVPNStatusValue(currentValues["https_proxy"]) + " all=" + emptyVPNStatusValue(currentValues["all_proxy"])
	status := "overridden"
	if matched {
		status = "applied"
	} else if enabled == 0 {
		status = "disabled"
	}
	return vpnSystemProxyInspection{Applied: status == "applied", Status: status, Current: current, Expected: formatVPNSystemProxyExpected(httpAddr, socksAddr)}, nil
}

func linuxGSettingsProxyStateMap(states []linuxGSettingsProxyState) map[string]string {
	values := make(map[string]string, len(states))
	for _, state := range states {
		values[state.Schema+"/"+state.Key] = strings.TrimSpace(state.Raw)
	}
	return values
}

func linuxKDEProxyStateMap(states []linuxKDEProxyState) map[string]string {
	values := make(map[string]string, len(states))
	for _, state := range states {
		values[strings.TrimSpace(state.Key)] = strings.TrimSpace(state.Raw)
	}
	return values
}

func linuxExpectedProxyAddresses(httpAddr string, socksAddr string) (string, string, bool, bool, error) {
	httpHost, httpPort, hasHTTP, err := linuxSplitProxyListen(httpAddr)
	if err != nil {
		return "", "", false, false, err
	}
	socksHost, socksPort, hasSOCKS, err := linuxSplitProxyListen(socksAddr)
	if err != nil {
		return "", "", false, false, err
	}
	if !hasHTTP && !hasSOCKS {
		return "", "", false, false, errors.New("system proxy requires http or socks listen address")
	}
	httpExpected := ""
	if hasHTTP {
		httpExpected = httpHost + ":" + httpPort
	}
	socksExpected := ""
	if hasSOCKS {
		socksExpected = socksHost + ":" + socksPort
	}
	return httpExpected, socksExpected, hasHTTP, hasSOCKS, nil
}

func linuxExpectedProxyURLs(httpAddr string, socksAddr string, socksScheme string) (string, string, bool, error) {
	httpExpected, socksExpected, _, hasSOCKS, err := linuxExpectedProxyAddresses(httpAddr, socksAddr)
	if err != nil {
		return "", "", false, err
	}
	if httpExpected != "" {
		httpExpected = "http://" + httpExpected
	}
	if socksExpected != "" {
		socksExpected = socksScheme + "://" + socksExpected
	}
	return httpExpected, socksExpected, hasSOCKS, nil
}

func linuxHostPort(hostRaw string, portRaw string) string {
	host := linuxProxyUnquote(hostRaw)
	port := linuxProxyUnquote(portRaw)
	if host == "" || port == "" || port == "0" {
		return ""
	}
	return host + ":" + port
}

func linuxProxyUnquote(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "'\"")
	return strings.TrimSpace(value)
}

func linuxProxyAddressEqual(actual string, expected string) bool {
	actual = strings.TrimSpace(actual)
	expected = strings.TrimSpace(expected)
	if strings.EqualFold(actual, expected) {
		return true
	}
	actual = strings.TrimPrefix(strings.TrimPrefix(actual, "http://"), "socks://")
	actual = strings.TrimPrefix(actual, "socks5://")
	expected = strings.TrimPrefix(strings.TrimPrefix(expected, "http://"), "socks://")
	expected = strings.TrimPrefix(expected, "socks5://")
	return strings.EqualFold(actual, expected)
}
