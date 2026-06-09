package main

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/nezhahq/agent/model"
)

type darwinVPNTunRoute struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Flags       string `json:"flags"`
	Netif       string `json:"netif"`
	Raw         string `json:"raw"`
}

func parseDarwinRouteLines(raw string) []darwinVPNTunRoute {
	var routes []darwinVPNTunRoute
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" ||
			strings.EqualFold(trimmed, "Routing tables") ||
			strings.HasSuffix(trimmed, ":") ||
			strings.HasPrefix(trimmed, "Destination ") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 4 {
			continue
		}
		routes = append(routes, darwinVPNTunRoute{
			Destination: fields[0],
			Gateway:     fields[1],
			Flags:       fields[2],
			Netif:       fields[3],
			Raw:         strings.TrimRight(line, " \t"),
		})
	}
	return routes
}

func buildDarwinRouteCleanupCommands(tunName string, before string, after string) []vpnTunCommand {
	beforeRoutes := make(map[string]struct{})
	for _, route := range parseDarwinRouteLines(before) {
		beforeRoutes[route.Raw] = struct{}{}
	}

	var commands []vpnTunCommand
	for _, route := range parseDarwinRouteLines(after) {
		if !darwinRouteBelongsToTun(route, tunName) {
			continue
		}
		if _, existed := beforeRoutes[route.Raw]; existed {
			continue
		}
		commands = append(commands, vpnTunCommand{
			Name: "route",
			Args: []string{"-n", "delete", "-net", route.Destination, "-interface", route.Netif},
		})
	}
	return commands
}

func darwinRouteBelongsToTun(route darwinVPNTunRoute, tunName string) bool {
	netif := strings.TrimSpace(route.Netif)
	if netif == "" {
		return false
	}
	if strings.TrimSpace(tunName) != "" && netif == tunName {
		return true
	}
	return strings.HasPrefix(netif, "utun")
}

func parseDarwinNetworkServices(raw string) []string {
	var services []string
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		service := strings.TrimSpace(line)
		if service == "" || strings.HasPrefix(service, "An asterisk ") {
			continue
		}
		service = strings.TrimSpace(strings.TrimPrefix(service, "*"))
		if service != "" {
			services = append(services, service)
		}
	}
	return services
}

func parseDarwinDNSState(service string, dnsRaw string, searchRaw string) vpnTunDNSState {
	return vpnTunDNSState{
		Interface: service,
		Source:    "networksetup",
		Servers:   parseDarwinNetworkSetupValues(dnsRaw, "there aren't any dns servers set"),
		Domains:   parseDarwinNetworkSetupValues(searchRaw, "there aren't any search domains set"),
	}
}

func parseDarwinNetworkSetupValues(raw string, emptyMarker string) []string {
	if strings.Contains(strings.ToLower(raw), emptyMarker) {
		return nil
	}
	var values []string
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		value := strings.TrimSpace(line)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func buildDarwinDNSRestoreCommands(states []vpnTunDNSState) []vpnTunCommand {
	var commands []vpnTunCommand
	for _, state := range states {
		if state.Source != "networksetup" || strings.TrimSpace(state.Interface) == "" {
			continue
		}
		dnsArgs := []string{"-setdnsservers", state.Interface}
		if len(state.Servers) == 0 {
			dnsArgs = append(dnsArgs, "Empty")
		} else {
			dnsArgs = append(dnsArgs, state.Servers...)
		}
		commands = append(commands, vpnTunCommand{Name: "networksetup", Args: dnsArgs})

		searchArgs := []string{"-setsearchdomains", state.Interface}
		if len(state.Domains) == 0 {
			searchArgs = append(searchArgs, "Empty")
		} else {
			searchArgs = append(searchArgs, state.Domains...)
		}
		commands = append(commands, vpnTunCommand{Name: "networksetup", Args: searchArgs})
	}
	return commands
}

func fillDarwinVPNTunSnapshot(snapshot *vpnTunSystemSnapshot) error {
	if snapshot == nil {
		return nil
	}
	routes, err := runVPNTunCommandOutput("netstat", "-rn", "-f", "inet")
	if err != nil {
		return err
	}
	servicesRaw, err := runVPNTunCommandOutput("networksetup", "-listallnetworkservices")
	if err != nil {
		return err
	}
	snapshot.RoutePrint = routes
	for _, service := range parseDarwinNetworkServices(servicesRaw) {
		dnsRaw, err := runVPNTunCommandOutput("networksetup", "-getdnsservers", service)
		if err != nil {
			return err
		}
		searchRaw, err := runVPNTunCommandOutput("networksetup", "-getsearchdomains", service)
		if err != nil {
			return err
		}
		snapshot.DNS = append(snapshot.DNS, parseDarwinDNSState(service, dnsRaw, searchRaw))
	}
	return nil
}

func restoreDarwinVPNTunSnapshot(req model.VPNControlRequest, snapshotPath string) error {
	raw, err := os.ReadFile(snapshotPath)
	if err != nil {
		return err
	}
	var snapshot vpnTunSystemSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	for _, command := range buildDarwinDNSRestoreCommands(snapshot.DNS) {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	after, err := runVPNTunCommandOutput("netstat", "-rn", "-f", "inet")
	if err != nil {
		return err
	}
	tunName := firstNonEmpty(snapshot.TunName, req.TunName, "nezha-vpn")
	for _, command := range buildDarwinRouteCleanupCommands(tunName, snapshot.RoutePrint, after) {
		if err := runVPNTunCommand(command); err != nil {
			return err
		}
	}
	return nil
}
