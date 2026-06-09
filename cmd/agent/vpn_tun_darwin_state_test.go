package main

import (
	"reflect"
	"testing"
)

func TestParseDarwinRouteLines(t *testing.T) {
	raw := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
10/8               utun9              USc                 utun9
172.19.0/30        link#24            UCS                 utun9
192.168.1          link#4             UCS                   en0      !
`

	got := parseDarwinRouteLines(raw)
	want := []darwinVPNTunRoute{
		{Destination: "default", Gateway: "192.168.1.1", Flags: "UGScg", Netif: "en0", Raw: "default            192.168.1.1        UGScg                 en0"},
		{Destination: "10/8", Gateway: "utun9", Flags: "USc", Netif: "utun9", Raw: "10/8               utun9              USc                 utun9"},
		{Destination: "172.19.0/30", Gateway: "link#24", Flags: "UCS", Netif: "utun9", Raw: "172.19.0/30        link#24            UCS                 utun9"},
		{Destination: "192.168.1", Gateway: "link#4", Flags: "UCS", Netif: "en0", Raw: "192.168.1          link#4             UCS                   en0      !"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin routes mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDarwinRouteCleanupCommandsForTunInterface(t *testing.T) {
	before := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
192.168.1          link#4             UCS                   en0
`
	after := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            utun9              UGSc                utun9
10/8               utun9              USc                 utun9
172.19.0/30        link#24            UCS                 utun9
default            192.168.1.1        UGScg                 en0
192.168.1          link#4             UCS                   en0
`

	got := buildDarwinRouteCleanupCommands("utun9", before, after)
	want := []vpnTunCommand{
		{Name: "route", Args: []string{"-n", "delete", "-net", "default", "-interface", "utun9"}},
		{Name: "route", Args: []string{"-n", "delete", "-net", "10/8", "-interface", "utun9"}},
		{Name: "route", Args: []string{"-n", "delete", "-net", "172.19.0/30", "-interface", "utun9"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin route cleanup commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDarwinRouteCleanupCommandsInfersUtunInterface(t *testing.T) {
	before := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
`
	after := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            utun9              UGSc                utun9
10/8               utun9              USc                 utun9
172.19.0/30        link#24            UCS                 utun9
default            192.168.1.1        UGScg                 en0
`

	got := buildDarwinRouteCleanupCommands("nezha-vpn", before, after)
	want := []vpnTunCommand{
		{Name: "route", Args: []string{"-n", "delete", "-net", "default", "-interface", "utun9"}},
		{Name: "route", Args: []string{"-n", "delete", "-net", "10/8", "-interface", "utun9"}},
		{Name: "route", Args: []string{"-n", "delete", "-net", "172.19.0/30", "-interface", "utun9"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin inferred route cleanup commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestParseDarwinNetworkServices(t *testing.T) {
	raw := `An asterisk (*) denotes that a network service is disabled.
Wi-Fi
*Thunderbolt Bridge
USB 10/100/1000 LAN
`

	got := parseDarwinNetworkServices(raw)
	want := []string{"Wi-Fi", "Thunderbolt Bridge", "USB 10/100/1000 LAN"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin network services mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestParseDarwinDNSState(t *testing.T) {
	got := parseDarwinDNSState(
		"Wi-Fi",
		"192.168.1.1\n1.1.1.1\n",
		"lan\ncorp.example\n",
	)
	want := vpnTunDNSState{
		Interface: "Wi-Fi",
		Source:    "networksetup",
		Servers:   []string{"192.168.1.1", "1.1.1.1"},
		Domains:   []string{"lan", "corp.example"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin DNS state mismatch:\nwant %#v\ngot  %#v", want, got)
	}

	empty := parseDarwinDNSState(
		"Ethernet",
		"There aren't any DNS Servers set on Ethernet.\n",
		"There aren't any Search Domains set on Ethernet.\n",
	)
	wantEmpty := vpnTunDNSState{
		Interface: "Ethernet",
		Source:    "networksetup",
	}
	if !reflect.DeepEqual(empty, wantEmpty) {
		t.Fatalf("empty darwin DNS state mismatch:\nwant %#v\ngot  %#v", wantEmpty, empty)
	}
}

func TestBuildDarwinDNSRestoreCommands(t *testing.T) {
	states := []vpnTunDNSState{
		{
			Interface: "Wi-Fi",
			Source:    "networksetup",
			Servers:   []string{"192.168.1.1", "1.1.1.1"},
			Domains:   []string{"lan", "corp.example"},
		},
		{
			Interface: "Ethernet",
			Source:    "networksetup",
		},
	}

	got := buildDarwinDNSRestoreCommands(states)
	want := []vpnTunCommand{
		{Name: "networksetup", Args: []string{"-setdnsservers", "Wi-Fi", "192.168.1.1", "1.1.1.1"}},
		{Name: "networksetup", Args: []string{"-setsearchdomains", "Wi-Fi", "lan", "corp.example"}},
		{Name: "networksetup", Args: []string{"-setdnsservers", "Ethernet", "Empty"}},
		{Name: "networksetup", Args: []string{"-setsearchdomains", "Ethernet", "Empty"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin DNS restore commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}
