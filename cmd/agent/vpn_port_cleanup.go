package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/nezhahq/agent/model"
)

func (m *AgentVPNManager) cleanupVPNPortSidecars(req model.VPNControlRequest) []string {
	return cleanupVPNPortSidecarsWithActive(req, m.activeVPNSidecarPIDs())
}

func (m *AgentVPNManager) activeVPNSidecarPIDs() map[int]struct{} {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	active := make(map[int]struct{}, len(m.sessions)+len(m.sharedExitRuntimes))
	for _, session := range m.sessions {
		if pid := vpnTrackedSessionSidecarPID(session); pid > 0 {
			active[pid] = struct{}{}
		}
	}
	for _, runtime := range m.sharedExitRuntimes {
		if runtime != nil && runtime.sidecarPID > 0 {
			active[runtime.sidecarPID] = struct{}{}
		}
	}
	if len(active) == 0 {
		return nil
	}
	return active
}

func cleanupVPNPortSidecars(req model.VPNControlRequest) []string {
	return cleanupVPNPortSidecarsWithActive(req, nil)
}

func cleanupVPNPortSidecarsWithActive(req model.VPNControlRequest, activePIDs map[int]struct{}) []string {
	ports := vpnSidecarCleanupPorts(req)
	if len(ports) == 0 {
		return nil
	}
	logs := make([]string, 0, len(ports))
	seen := map[int]struct{}{}
	for _, port := range ports {
		pids, err := vpnListeningPIDs(port)
		if err != nil {
			logs = append(logs, fmt.Sprintf("[cleanup] port=%d scan=failed: %s", port, err.Error()))
			continue
		}
		for _, pid := range pids {
			if pid <= 0 || pid == os.Getpid() {
				continue
			}
			if _, ok := seen[pid]; ok {
				continue
			}
			if _, ok := activePIDs[pid]; ok {
				logs = append(logs, fmt.Sprintf("[cleanup] port=%d pid=%d skip=active-session", port, pid))
				continue
			}
			cmdline := vpnProcessCommandLine(pid)
			if !isNezhaVPNSidecarCommand(cmdline, req.SessionID) {
				continue
			}
			seen[pid] = struct{}{}
			if err := killStaleVPNSidecarProcess(pid); err != nil {
				if isStaleSidecarAlreadyGone(err) {
					logs = append(logs, fmt.Sprintf("[cleanup] port=%d pid=%d already-gone", port, pid))
					continue
				}
				logs = append(logs, fmt.Sprintf("[cleanup] port=%d pid=%d kill=failed: %s", port, pid, err.Error()))
				continue
			}
			logs = append(logs, fmt.Sprintf("[cleanup] port=%d pid=%d kill=ok", port, pid))
		}
	}
	return logs
}

func vpnSidecarCleanupPorts(req model.VPNControlRequest) []int {
	ports := make([]int, 0, 2)
	switch req.Role {
	case model.VPNRoleExit:
		if port, ok := vpnListenPort(firstNonEmpty(req.Extra["bridge_listen"], defaultVPNExitBridge)); ok {
			ports = append(ports, port)
		}
	case model.VPNRoleEntry:
		if req.Mode != "" && req.Mode != model.VPNModeSystemProxy {
			return nil
		}
		httpAddr := strings.TrimSpace(req.ListenHTTP)
		socksAddr := strings.TrimSpace(req.ListenSOCKS)
		if httpAddr == "" && socksAddr == "" {
			socksAddr = defaultVPNLocalSOCKS
		}
		if port, ok := vpnListenPort(httpAddr); ok {
			ports = append(ports, port)
		}
		if port, ok := vpnListenPort(socksAddr); ok {
			ports = append(ports, port)
		}
	}
	return ports
}

func vpnListenPort(address string) (int, bool) {
	if strings.TrimSpace(address) == "" {
		return 0, false
	}
	_, port, err := splitListenAddress(address)
	if err != nil {
		return 0, false
	}
	return port, true
}

func vpnListeningPIDs(port int) ([]int, error) {
	if port <= 0 {
		return nil, nil
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("netstat", "-ano", "-p", "tcp").Output()
		if err != nil {
			return nil, err
		}
		return parseWindowsNetstatListeningPIDs(string(out), port), nil
	}
	if pids, err := vpnListeningPIDsLsof(port); err == nil {
		return pids, nil
	}
	return vpnListeningPIDsSS(port)
}

func vpnListeningPIDsLsof(port int) ([]int, error) {
	out, err := exec.Command("lsof", "-nP", fmt.Sprintf("-iTCP:%d", port), "-sTCP:LISTEN", "-t").Output()
	if err != nil {
		return nil, err
	}
	return parsePIDLines(string(out)), nil
}

func vpnListeningPIDsSS(port int) ([]int, error) {
	out, err := exec.Command("ss", "-ltnp").Output()
	if err != nil {
		return nil, err
	}
	return parseSSListeningPIDs(string(out), port), nil
}

func parseWindowsNetstatListeningPIDs(output string, port int) []int {
	wantSuffix := ":" + strconv.Itoa(port)
	pids := make([]int, 0, 1)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.EqualFold(fields[0], "TCP") || !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}
		if !strings.HasSuffix(fields[1], wantSuffix) {
			continue
		}
		if pid, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

func parseSSListeningPIDs(output string, port int) []int {
	wantSuffix := ":" + strconv.Itoa(port)
	pids := make([]int, 0, 1)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if !strings.HasSuffix(fields[3], wantSuffix) {
			continue
		}
		for _, part := range fields {
			for {
				idx := strings.Index(part, "pid=")
				if idx < 0 {
					break
				}
				part = part[idx+4:]
				end := 0
				for end < len(part) && part[end] >= '0' && part[end] <= '9' {
					end++
				}
				if end == 0 {
					break
				}
				if pid, err := strconv.Atoi(part[:end]); err == nil {
					pids = append(pids, pid)
				}
				part = part[end:]
			}
		}
	}
	return pids
}

func parsePIDLines(output string) []int {
	pids := make([]int, 0, 1)
	for _, line := range strings.Split(output, "\n") {
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

func vpnProcessCommandLine(pid int) string {
	if pid <= 0 {
		return ""
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell.exe", "-NoProfile", "-Command", fmt.Sprintf("(Get-CimInstance Win32_Process -Filter 'ProcessId = %d').CommandLine", pid)).Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return strings.TrimSpace(string(out))
		}
		out, err = exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine", "/value").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
		return ""
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err == nil && len(raw) > 0 {
		return strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "args=").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func isNezhaVPNSidecarCommand(cmdline string, sessionID string) bool {
	cmdline = strings.ToLower(strings.TrimSpace(cmdline))
	if cmdline == "" || !strings.Contains(cmdline, "sing-box") || !strings.Contains(cmdline, " run ") {
		return false
	}
	if session := strings.ToLower(safeVPNPathName(sessionID)); session != "" && session != "session" && strings.Contains(cmdline, session) {
		return true
	}
	for _, marker := range []string{
		"/vpn/sessions/",
		"\\vpn\\sessions\\",
		"/nezha-agent-vpn/sessions/",
		"\\nezha-agent-vpn\\sessions\\",
	} {
		if strings.Contains(cmdline, marker) {
			return true
		}
	}
	return false
}
