package main

import (
	"reflect"
	"testing"
)

func TestParseWindowsDNSStateFromNetshOutput(t *testing.T) {
	raw := `Configuration for interface "Ethernet"
    DNS servers configured through DHCP:  192.168.1.1
    Register with which suffix:           Primary only

Configuration for interface "Wi-Fi"
    Statically Configured DNS Servers:    1.1.1.1
                                          8.8.8.8
    Register with which suffix:           Primary only`

	got := parseWindowsDNSState("ipv4", raw)
	want := []vpnTunDNSState{
		{Family: "ipv4", Interface: "Ethernet", Source: "dhcp", Servers: []string{"192.168.1.1"}},
		{Family: "ipv4", Interface: "Wi-Fi", Source: "static", Servers: []string{"1.1.1.1", "8.8.8.8"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed DNS state mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildWindowsDNSRestoreCommands(t *testing.T) {
	states := []vpnTunDNSState{
		{Family: "ipv4", Interface: "Ethernet", Source: "dhcp", Servers: []string{"192.168.1.1"}},
		{Family: "ipv4", Interface: "Wi-Fi", Source: "static", Servers: []string{"1.1.1.1", "8.8.8.8"}},
	}

	got := buildWindowsDNSRestoreCommands(states)
	want := []vpnTunCommand{
		{Name: "netsh", Args: []string{"interface", "ipv4", "set", "dnsservers", "name=Ethernet", "source=dhcp"}},
		{Name: "netsh", Args: []string{"interface", "ipv4", "set", "dnsservers", "name=Wi-Fi", "static", "1.1.1.1", "primary", "validate=no"}},
		{Name: "netsh", Args: []string{"interface", "ipv4", "add", "dnsservers", "name=Wi-Fi", "address=8.8.8.8", "index=2", "validate=no"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DNS restore commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildWindowsRouteCleanupCommandsForTunInterface(t *testing.T) {
	before := `===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0    192.168.1.1  192.168.1.10     25
===========================================================================
Persistent Routes:
  None`
	after := `===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         On-link       172.19.0.1      5
        10.0.0.0        255.0.0.0         On-link       172.19.0.1      5
          0.0.0.0          0.0.0.0    192.168.1.1  192.168.1.10     25
===========================================================================
Persistent Routes:
  None`

	got := buildWindowsRouteCleanupCommands("nezha-vpn", before, after, "172.19.0.1")
	want := []vpnTunCommand{
		{Name: "netsh", Args: []string{"interface", "ipv4", "delete", "route", "prefix=0.0.0.0/0", "interface=nezha-vpn"}},
		{Name: "netsh", Args: []string{"interface", "ipv4", "delete", "route", "prefix=10.0.0.0/8", "interface=nezha-vpn"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("route cleanup commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}
