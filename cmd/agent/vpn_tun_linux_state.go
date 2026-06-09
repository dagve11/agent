package main

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/nezhahq/agent/model"
)

const linuxResolvConfPath = "/etc/resolv.conf"

type linuxVPNTunRoute struct {
	Prefix string `json:"prefix"`
	Dev    string `json:"dev"`
	Raw    string `json:"raw"`
}

func parseLinuxRouteLines(raw string) []linuxVPNTunRoute {
	var routes []linuxVPNTunRoute
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		route := linuxVPNTunRoute{
			Prefix: fields[0],
			Raw:    line,
		}
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				route.Dev = fields[i+1]
				break
			}
		}
		routes = append(routes, route)
	}
	return routes
}

func buildLinuxRouteCleanupCommands(tunName string, before string, after string) []vpnTunCommand {
	beforeRoutes := make(map[string]struct{})
	for _, route := range parseLinuxRouteLines(before) {
		beforeRoutes[route.Raw] = struct{}{}
	}
	var commands []vpnTunCommand
	for _, route := range parseLinuxRouteLines(after) {
		if route.Dev != tunName {
			continue
		}
		if _, existed := beforeRoutes[route.Raw]; existed {
			continue
		}
		commands = append(commands, vpnTunCommand{
			Name: "ip",
			Args: []string{"route", "del", route.Prefix, "dev", tunName},
		})
	}
	return commands
}

func parseLinuxResolvConfState(path string, raw string) vpnTunDNSState {
	state := vpnTunDNSState{
		Path: path,
		Raw:  raw,
	}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "nameserver" {
			state.Servers = append(state.Servers, fields[1])
		}
	}
	return state
}

func parseLinuxResolvedLinkDNSState(raw string) []vpnTunDNSState {
	var states []vpnTunDNSState
	var current *vpnTunDNSState
	flush := func() {
		if current != nil && current.Interface != "" {
			states = append(states, *current)
		}
		current = nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Link ") {
			flush()
			if start := strings.Index(trimmed, "("); start >= 0 {
				if end := strings.LastIndex(trimmed, ")"); end > start {
					current = &vpnTunDNSState{
						Source:    "systemd-resolved",
						Interface: strings.TrimSpace(trimmed[start+1 : end]),
						Raw:       "default_route=unknown",
					}
				}
			}
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(trimmed, "Protocols:") {
			if strings.Contains(trimmed, "+DefaultRoute") {
				current.Raw = "default_route=true"
			} else if strings.Contains(trimmed, "-DefaultRoute") {
				current.Raw = "default_route=false"
			}
			continue
		}
		if strings.HasPrefix(trimmed, "DNS Servers:") {
			current.Servers = append(current.Servers, strings.Fields(strings.TrimSpace(strings.TrimPrefix(trimmed, "DNS Servers:")))...)
			continue
		}
		if strings.HasPrefix(trimmed, "DNS Domain:") {
			current.Domains = append(current.Domains, strings.Fields(strings.TrimSpace(strings.TrimPrefix(trimmed, "DNS Domain:")))...)
			continue
		}
	}
	flush()
	return states
}

func buildLinuxResolvedDNSRestoreCommands(before []vpnTunDNSState, afterRaw string, tunName string) []vpnTunCommand {
	afterByInterface := make(map[string]vpnTunDNSState)
	for _, state := range parseLinuxResolvedLinkDNSState(afterRaw) {
		afterByInterface[state.Interface] = state
	}
	beforeByInterface := make(map[string]vpnTunDNSState)
	for _, state := range before {
		if state.Source == "systemd-resolved" && state.Interface != "" {
			beforeByInterface[state.Interface] = state
		}
	}

	var commands []vpnTunCommand
	if strings.TrimSpace(tunName) != "" {
		if _, ok := afterByInterface[tunName]; ok {
			commands = append(commands, vpnTunCommand{Name: "resolvectl", Args: []string{"revert", tunName}})
		}
	}
	for _, state := range before {
		if state.Source != "systemd-resolved" || state.Interface == "" {
			continue
		}
		after, existedAfter := afterByInterface[state.Interface]
		if !existedAfter || resolvedDNSStateEqual(state, after) {
			continue
		}
		commands = append(commands, vpnTunCommand{Name: "resolvectl", Args: []string{"revert", state.Interface}})
		if len(state.Servers) > 0 {
			args := append([]string{"dns", state.Interface}, state.Servers...)
			commands = append(commands, vpnTunCommand{Name: "resolvectl", Args: args})
		}
		if len(state.Domains) > 0 {
			args := append([]string{"domain", state.Interface}, state.Domains...)
			commands = append(commands, vpnTunCommand{Name: "resolvectl", Args: args})
		}
		switch state.Raw {
		case "default_route=true":
			commands = append(commands, vpnTunCommand{Name: "resolvectl", Args: []string{"default-route", state.Interface, "yes"}})
		case "default_route=false":
			commands = append(commands, vpnTunCommand{Name: "resolvectl", Args: []string{"default-route", state.Interface, "no"}})
		}
	}
	for interfaceName := range afterByInterface {
		if interfaceName == tunName {
			continue
		}
		if _, ok := beforeByInterface[interfaceName]; ok {
			continue
		}
		commands = append(commands, vpnTunCommand{Name: "resolvectl", Args: []string{"revert", interfaceName}})
	}
	return commands
}

func resolvedDNSStateEqual(left vpnTunDNSState, right vpnTunDNSState) bool {
	if left.Interface != right.Interface || left.Raw != right.Raw {
		return false
	}
	return strings.Join(left.Servers, "\x00") == strings.Join(right.Servers, "\x00") &&
		strings.Join(left.Domains, "\x00") == strings.Join(right.Domains, "\x00")
}

func fillLinuxVPNTunSnapshot(snapshot *vpnTunSystemSnapshot) error {
	if snapshot == nil {
		return nil
	}
	routes, err := runVPNTunCommandOutput("ip", "route", "show", "table", "main")
	if err != nil {
		return err
	}
	resolv, err := os.ReadFile(linuxResolvConfPath)
	if err != nil {
		return err
	}
	snapshot.RoutePrint = routes
	snapshot.DNS = []vpnTunDNSState{parseLinuxResolvConfState(linuxResolvConfPath, string(resolv))}
	if resolved, err := runVPNTunCommandOutput("resolvectl", "status"); err == nil {
		snapshot.DNS = append(snapshot.DNS, parseLinuxResolvedLinkDNSState(resolved)...)
	}
	return nil
}

func restoreLinuxVPNTunSnapshot(req model.VPNControlRequest, snapshotPath string) error {
	raw, err := os.ReadFile(snapshotPath)
	if err != nil {
		return err
	}
	var snapshot vpnTunSystemSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	for _, state := range snapshot.DNS {
		if state.Path == "" || state.Raw == "" {
			continue
		}
		if err := os.WriteFile(state.Path, []byte(state.Raw), 0600); err != nil {
			return err
		}
	}
	after, err := runVPNTunCommandOutput("ip", "route", "show", "table", "main")
	if err != nil {
		return err
	}
	tunName := firstNonEmpty(snapshot.TunName, req.TunName, "nezha-vpn")
	if resolvedAfter, err := runVPNTunCommandOutput("resolvectl", "status"); err == nil {
		for _, command := range buildLinuxResolvedDNSRestoreCommands(snapshot.DNS, resolvedAfter, tunName) {
			if err := runVPNTunCommand(command); err != nil {
				return err
			}
		}
	}
	for _, command := range buildLinuxRouteCleanupCommands(tunName, snapshot.RoutePrint, after) {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	return nil
}
