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
