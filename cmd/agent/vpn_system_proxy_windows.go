//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

const winINetSettingsKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type windowsVPNSystemProxyManager struct {
	mu            sync.Mutex
	applied       bool
	proxyEnable   *string
	proxyServer   *string
	proxyOverride *string
}

func newPlatformVPNSystemProxyManager() vpnSystemProxyManager {
	return &windowsVPNSystemProxyManager{}
}

func (m *windowsVPNSystemProxyManager) Apply(httpAddr string, socksAddr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.applied {
		m.proxyEnable = readWindowsRegistryValue("ProxyEnable")
		m.proxyServer = readWindowsRegistryValue("ProxyServer")
		m.proxyOverride = readWindowsRegistryValue("ProxyOverride")
	}

	proxyServer := buildWindowsProxyServer(httpAddr, socksAddr)
	if proxyServer == "" {
		return fmt.Errorf("system proxy requires http or socks listen address")
	}
	if err := setWindowsRegistryDWORD("ProxyEnable", "1"); err != nil {
		return err
	}
	if err := setWindowsRegistryString("ProxyServer", proxyServer); err != nil {
		return err
	}
	if err := setWindowsRegistryString("ProxyOverride", "<local>"); err != nil {
		return err
	}
	m.applied = true
	return nil
}

func (m *windowsVPNSystemProxyManager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.applied {
		return nil
	}
	if err := restoreWindowsRegistryValue("ProxyEnable", "REG_DWORD", m.proxyEnable); err != nil {
		return err
	}
	if err := restoreWindowsRegistryValue("ProxyServer", "REG_SZ", m.proxyServer); err != nil {
		return err
	}
	if err := restoreWindowsRegistryValue("ProxyOverride", "REG_SZ", m.proxyOverride); err != nil {
		return err
	}
	m.applied = false
	return nil
}

func buildWindowsProxyServer(httpAddr string, socksAddr string) string {
	httpAddr = strings.TrimSpace(httpAddr)
	socksAddr = strings.TrimSpace(socksAddr)
	parts := make([]string, 0, 2)
	if httpAddr != "" {
		parts = append(parts, "http="+httpAddr, "https="+httpAddr)
	}
	if socksAddr != "" {
		parts = append(parts, "socks="+socksAddr)
	}
	return strings.Join(parts, ";")
}

func readWindowsRegistryValue(name string) *string {
	out, err := exec.Command("reg", "query", winINetSettingsKey, "/v", name).CombinedOutput()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.EqualFold(fields[0], name) {
			value := strings.Join(fields[2:], " ")
			return &value
		}
	}
	return nil
}

func restoreWindowsRegistryValue(name string, kind string, value *string) error {
	if value == nil {
		return deleteWindowsRegistryValue(name)
	}
	if kind == "REG_DWORD" {
		return setWindowsRegistryDWORD(name, *value)
	}
	return setWindowsRegistryString(name, *value)
}

func setWindowsRegistryDWORD(name string, value string) error {
	return runWindowsRegistry("add", winINetSettingsKey, "/v", name, "/t", "REG_DWORD", "/d", value, "/f")
}

func setWindowsRegistryString(name string, value string) error {
	return runWindowsRegistry("add", winINetSettingsKey, "/v", name, "/t", "REG_SZ", "/d", value, "/f")
}

func deleteWindowsRegistryValue(name string) error {
	err := runWindowsRegistry("delete", winINetSettingsKey, "/v", name, "/f")
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unable to find") {
		return nil
	}
	return err
}

func runWindowsRegistry(args ...string) error {
	out, err := exec.Command("reg", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("reg %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
