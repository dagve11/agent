package main

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/nezhahq/agent/model"
)

type vpnTunCommand struct {
	Name string
	Args []string
}

func parseWindowsDNSState(family string, raw string) []vpnTunDNSState {
	var states []vpnTunDNSState
	var current *vpnTunDNSState
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, `Configuration for interface "`) && strings.HasSuffix(trimmed, `"`) {
			name := strings.TrimSuffix(strings.TrimPrefix(trimmed, `Configuration for interface "`), `"`)
			states = append(states, vpnTunDNSState{
				Family:    family,
				Interface: name,
			})
			current = &states[len(states)-1]
			continue
		}
		if current == nil {
			continue
		}
		lower := strings.ToLower(trimmed)
		switch {
		case strings.Contains(lower, "dns servers configured through dhcp"):
			current.Source = "dhcp"
			if server := valueAfterColon(trimmed); server != "" {
				current.Servers = append(current.Servers, server)
			}
		case strings.Contains(lower, "statically configured dns servers"):
			current.Source = "static"
			if server := valueAfterColon(trimmed); server != "" {
				current.Servers = append(current.Servers, server)
			}
		case current.Source != "" && net.ParseIP(strings.Fields(trimmed)[0]) != nil:
			current.Servers = append(current.Servers, strings.Fields(trimmed)[0])
		}
	}
	return states
}

func buildWindowsDNSRestoreCommands(states []vpnTunDNSState) []vpnTunCommand {
	commands := make([]vpnTunCommand, 0, len(states))
	for _, state := range states {
		family := strings.TrimSpace(state.Family)
		if family == "" {
			family = "ipv4"
		}
		name := "name=" + state.Interface
		if strings.EqualFold(state.Source, "dhcp") || len(state.Servers) == 0 {
			commands = append(commands, vpnTunCommand{
				Name: "netsh",
				Args: []string{"interface", family, "set", "dnsservers", name, "source=dhcp"},
			})
			continue
		}
		commands = append(commands, vpnTunCommand{
			Name: "netsh",
			Args: []string{"interface", family, "set", "dnsservers", name, "static", state.Servers[0], "primary", "validate=no"},
		})
		for i, server := range state.Servers[1:] {
			commands = append(commands, vpnTunCommand{
				Name: "netsh",
				Args: []string{"interface", family, "add", "dnsservers", name, "address=" + server, "index=" + intString(i+2), "validate=no"},
			})
		}
	}
	return commands
}

func buildWindowsRouteCleanupCommands(tunName string, before string, after string, tunInterfaceIP string) []vpnTunCommand {
	beforeRoutes := parseWindowsRouteLineSet(before, tunInterfaceIP)
	afterRoutes := parseWindowsRouteLines(after, tunInterfaceIP)
	commands := make([]vpnTunCommand, 0, len(afterRoutes))
	for _, route := range afterRoutes {
		if _, existed := beforeRoutes[route]; existed {
			continue
		}
		prefix := windowsRoutePrefix(route.destination, route.netmask)
		if prefix == "" {
			continue
		}
		commands = append(commands, vpnTunCommand{
			Name: "netsh",
			Args: []string{"interface", "ipv4", "delete", "route", "prefix=" + prefix, "interface=" + tunName},
		})
	}
	return commands
}

func fillWindowsVPNTunSnapshot(snapshot *vpnTunSystemSnapshot) error {
	if snapshot == nil {
		return nil
	}
	routePrint, err := runVPNTunCommandOutput("route", "print")
	if err != nil {
		return err
	}
	ipv4DNS, err := runVPNTunCommandOutput("netsh", "interface", "ipv4", "show", "dnsservers")
	if err != nil {
		return err
	}
	ipv6DNS, err := runVPNTunCommandOutput("netsh", "interface", "ipv6", "show", "dnsservers")
	if err != nil {
		return err
	}
	snapshot.RoutePrint = routePrint
	snapshot.DNS = append(parseWindowsDNSState("ipv4", ipv4DNS), parseWindowsDNSState("ipv6", ipv6DNS)...)
	return nil
}

func restoreWindowsVPNTunSnapshot(req model.VPNControlRequest, snapshotPath string) error {
	raw, err := os.ReadFile(snapshotPath)
	if err != nil {
		return err
	}
	var snapshot vpnTunSystemSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	for _, command := range buildWindowsDNSRestoreCommands(snapshot.DNS) {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	after, err := runVPNTunCommandOutput("route", "print")
	if err != nil {
		return err
	}
	tunName := firstNonEmpty(snapshot.TunName, req.TunName, "nezha-vpn")
	tunIP := firstNonEmpty(snapshot.TunInterface, "172.19.0.1")
	for _, command := range buildWindowsRouteCleanupCommands(tunName, snapshot.RoutePrint, after, tunIP) {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	return nil
}

type windowsRouteLine struct {
	destination string
	netmask     string
}

func parseWindowsRouteLineSet(raw string, interfaceIP string) map[windowsRouteLine]struct{} {
	routes := make(map[windowsRouteLine]struct{})
	for _, route := range parseWindowsRouteLines(raw, interfaceIP) {
		routes[route] = struct{}{}
	}
	return routes
}

func parseWindowsRouteLines(raw string, interfaceIP string) []windowsRouteLine {
	var routes []windowsRouteLine
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		destination := fields[0]
		netmask := fields[1]
		if net.ParseIP(destination) == nil || net.ParseIP(netmask) == nil {
			continue
		}
		if fields[len(fields)-2] != interfaceIP {
			continue
		}
		routes = append(routes, windowsRouteLine{destination: destination, netmask: netmask})
	}
	return routes
}

func windowsRoutePrefix(destination string, mask string) string {
	ip := net.ParseIP(destination).To4()
	maskIP := net.ParseIP(mask).To4()
	if ip == nil || maskIP == nil {
		return ""
	}
	ones, bits := net.IPMask(maskIP).Size()
	if bits != 32 || ones < 0 {
		return ""
	}
	return destination + "/" + intString(ones)
}

func valueAfterColon(value string) string {
	_, after, ok := strings.Cut(value, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(after)
}

func intString(value int) string {
	return strconv.Itoa(value)
}
