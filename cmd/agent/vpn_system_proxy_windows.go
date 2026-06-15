//go:build windows

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

const (
	winCurrentUserRoot     = `HKCU`
	winUsersRoot           = `HKEY_USERS`
	winINetSettingsSubKey  = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	winProxyEnableValue    = "ProxyEnable"
	winProxyServerValue    = "ProxyServer"
	winProxyOverrideValue  = "ProxyOverride"
	winProxyOverrideLocal  = "<local>"
	winRegTypeDWORD        = "REG_DWORD"
	winRegTypeString       = "REG_SZ"
	winSettingsChangedFlag = 39
	winSettingsRefreshFlag = 37
)

type windowsProxySnapshot struct {
	key           string
	proxyEnable   *string
	proxyServer   *string
	proxyOverride *string
}

type windowsVPNSystemProxyManager struct {
	mu        sync.Mutex
	applied   bool
	snapshots []windowsProxySnapshot
}

func newPlatformVPNSystemProxyManager() vpnSystemProxyManager {
	return &windowsVPNSystemProxyManager{}
}

func (m *windowsVPNSystemProxyManager) Apply(httpAddr string, socksAddr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	proxyServer := buildWindowsProxyServer(httpAddr, socksAddr)
	if proxyServer == "" {
		return fmt.Errorf("system proxy requires http or socks listen address")
	}

	targets, err := windowsProxyTargetKeys()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("no Windows user registry hive found for system proxy")
	}

	snapshots := m.snapshots
	if !m.applied {
		snapshots = windowsProxySnapshots(targets)
		m.snapshots = snapshots
	}

	changed := make([]windowsProxySnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if err := applyWindowsProxyToKey(snapshot.key, proxyServer); err != nil {
			_ = restoreWindowsProxySnapshots(changed)
			notifyWindowsProxySettingsChanged()
			return err
		}
		changed = append(changed, snapshot)
	}
	if len(changed) == 0 {
		return errors.New("no Windows proxy registry target was changed")
	}
	notifyWindowsProxySettingsChanged()
	m.applied = true
	return nil
}

func (m *windowsVPNSystemProxyManager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.applied {
		return nil
	}
	err := restoreWindowsProxySnapshots(m.snapshots)
	notifyWindowsProxySettingsChanged()
	if err != nil {
		return err
	}
	m.applied = false
	m.snapshots = nil
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

func windowsProxyTargetKeys() ([]string, error) {
	userRoots, err := queryWindowsLoadedUserRoots()
	if err != nil {
		return nil, err
	}
	targets := make([]string, 0, len(userRoots)+1)
	for _, root := range userRoots {
		targets = append(targets, windowsRegistryKey(root, winINetSettingsSubKey))
	}
	if len(targets) == 0 {
		targets = append(targets, windowsRegistryKey(winCurrentUserRoot, winINetSettingsSubKey))
	}
	return cleanStrings(targets), nil
}

func queryWindowsLoadedUserRoots() ([]string, error) {
	out, err := exec.Command("reg", "query", winUsersRoot).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("reg query %s failed: %w: %s", winUsersRoot, err, strings.TrimSpace(string(out)))
	}
	roots := make([]string, 0)
	for _, line := range strings.Split(string(out), "\n") {
		root := strings.TrimSpace(line)
		if isWindowsUserRegistryRoot(root) {
			roots = append(roots, root)
		}
	}
	return roots, nil
}

func isWindowsUserRegistryRoot(root string) bool {
	sid := strings.TrimSpace(root)
	sid = strings.TrimPrefix(sid, winUsersRoot+`\`)
	if sid == root || sid == "" || strings.HasSuffix(strings.ToLower(sid), `_classes`) {
		return false
	}
	switch strings.ToUpper(sid) {
	case ".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return false
	}
	return strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")
}

func windowsProxySnapshots(keys []string) []windowsProxySnapshot {
	snapshots := make([]windowsProxySnapshot, 0, len(keys))
	for _, key := range keys {
		snapshots = append(snapshots, windowsProxySnapshot{
			key:           key,
			proxyEnable:   readWindowsRegistryValue(key, winProxyEnableValue),
			proxyServer:   readWindowsRegistryValue(key, winProxyServerValue),
			proxyOverride: readWindowsRegistryValue(key, winProxyOverrideValue),
		})
	}
	return snapshots
}

func applyWindowsProxyToKey(key string, proxyServer string) error {
	if err := setWindowsRegistryDWORD(key, winProxyEnableValue, "1"); err != nil {
		return err
	}
	if err := setWindowsRegistryString(key, winProxyServerValue, proxyServer); err != nil {
		return err
	}
	return setWindowsRegistryString(key, winProxyOverrideValue, winProxyOverrideLocal)
}

func platformVPNSystemProxyStatus(httpAddr string, socksAddr string) (vpnSystemProxyInspection, error) {
	proxyServer := buildWindowsProxyServer(httpAddr, socksAddr)
	if proxyServer == "" {
		return vpnSystemProxyInspection{}, fmt.Errorf("system proxy requires http or socks listen address")
	}
	targets, err := windowsProxyTargetKeys()
	if err != nil {
		return vpnSystemProxyInspection{}, err
	}
	if len(targets) == 0 {
		return vpnSystemProxyInspection{}, errors.New("no Windows user registry hive found for system proxy")
	}
	matched := 0
	enabled := 0
	servers := make([]string, 0, len(targets))
	for _, key := range targets {
		proxyEnabled := windowsRegistryDWORDEnabled(readWindowsRegistryValue(key, winProxyEnableValue))
		proxyServerValue := readWindowsRegistryValue(key, winProxyServerValue)
		if proxyEnabled {
			enabled++
		}
		if proxyServerValue != nil && strings.TrimSpace(*proxyServerValue) != "" {
			servers = append(servers, strings.TrimSpace(*proxyServerValue))
		}
		if proxyEnabled && windowsProxyServerApplied(proxyServerValue, proxyServer, httpAddr, socksAddr) {
			matched++
		}
	}
	status := "overridden"
	if matched == len(targets) {
		status = "applied"
	} else if enabled == 0 {
		status = "disabled"
	}
	return vpnSystemProxyInspection{
		Applied:  status == "applied",
		Status:   status,
		Current:  fmt.Sprintf("targets=%d matched=%d enabled=%d server=%s", len(targets), matched, enabled, emptyVPNStatusValue(strings.Join(cleanStrings(servers), "|"))),
		Expected: proxyServer,
	}, nil
}

func windowsRegistryDWORDEnabled(value *string) bool {
	if value == nil {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(*value))
	return normalized == "1" || normalized == "0x1"
}

func windowsProxyServerApplied(value *string, proxyServer string, httpAddr string, socksAddr string) bool {
	if value == nil {
		return false
	}
	actual := strings.TrimSpace(*value)
	if strings.EqualFold(actual, strings.TrimSpace(proxyServer)) {
		return true
	}
	for _, addr := range []string{strings.TrimSpace(httpAddr), strings.TrimSpace(socksAddr)} {
		if addr == "" {
			continue
		}
		if strings.EqualFold(actual, addr) || strings.EqualFold(actual, "http://"+addr) {
			return true
		}
	}
	return false
}

func restoreWindowsProxySnapshots(snapshots []windowsProxySnapshot) error {
	errs := make([]error, 0)
	for _, snapshot := range snapshots {
		if err := restoreWindowsRegistryValue(snapshot.key, winProxyEnableValue, winRegTypeDWORD, snapshot.proxyEnable); err != nil {
			errs = append(errs, err)
		}
		if err := restoreWindowsRegistryValue(snapshot.key, winProxyServerValue, winRegTypeString, snapshot.proxyServer); err != nil {
			errs = append(errs, err)
		}
		if err := restoreWindowsRegistryValue(snapshot.key, winProxyOverrideValue, winRegTypeString, snapshot.proxyOverride); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func readWindowsRegistryValue(key string, name string) *string {
	out, err := exec.Command("reg", "query", key, "/v", name).CombinedOutput()
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

func restoreWindowsRegistryValue(key string, name string, kind string, value *string) error {
	if value == nil {
		return deleteWindowsRegistryValue(key, name)
	}
	if kind == winRegTypeDWORD {
		return setWindowsRegistryDWORD(key, name, *value)
	}
	return setWindowsRegistryString(key, name, *value)
}

func setWindowsRegistryDWORD(key string, name string, value string) error {
	return runWindowsRegistry("add", key, "/v", name, "/t", winRegTypeDWORD, "/d", value, "/f")
}

func setWindowsRegistryString(key string, name string, value string) error {
	return runWindowsRegistry("add", key, "/v", name, "/t", winRegTypeString, "/d", value, "/f")
}

func deleteWindowsRegistryValue(key string, name string) error {
	err := runWindowsRegistry("delete", key, "/v", name, "/f")
	if err != nil && isWindowsRegistryMissingValueError(err) {
		return nil
	}
	return err
}

func isWindowsRegistryMissingValueError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unable to find") ||
		strings.Contains(message, "not found") ||
		strings.Contains(message, "找不到")
}

func windowsRegistryKey(root string, subKey string) string {
	return strings.TrimRight(root, `\`) + `\` + strings.TrimLeft(subKey, `\`)
}

func notifyWindowsProxySettingsChanged() {
	wininet := syscall.NewLazyDLL("wininet.dll")
	internetSetOption := wininet.NewProc("InternetSetOptionW")
	_, _, _ = internetSetOption.Call(0, uintptr(winSettingsChangedFlag), 0, 0)
	_, _, _ = internetSetOption.Call(0, uintptr(winSettingsRefreshFlag), 0, 0)
}

func runWindowsRegistry(args ...string) error {
	out, err := exec.Command("reg", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("reg %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
