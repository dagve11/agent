package main

import (
	"reflect"
	"testing"
)

func TestParseDarwinProxyState(t *testing.T) {
	raw := `Enabled: Yes
Server: 127.0.0.1
Port: 8080
Authenticated Proxy Enabled: 0
`

	got := parseDarwinProxyState("Wi-Fi", "web", raw)
	want := darwinVPNProxyState{
		Service: "Wi-Fi",
		Kind:    "web",
		Enabled: true,
		Server:  "127.0.0.1",
		Port:    "8080",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin proxy state mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDarwinSystemProxyApplyCommands(t *testing.T) {
	got, err := buildDarwinSystemProxyApplyCommands(
		[]string{"Wi-Fi", "Ethernet"},
		"127.0.0.1:8088",
		"127.0.0.1:1080",
	)
	if err != nil {
		t.Fatalf("build apply commands: %v", err)
	}
	want := []vpnTunCommand{
		{Name: "networksetup", Args: []string{"-setwebproxy", "Wi-Fi", "127.0.0.1", "8088"}},
		{Name: "networksetup", Args: []string{"-setwebproxystate", "Wi-Fi", "on"}},
		{Name: "networksetup", Args: []string{"-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "8088"}},
		{Name: "networksetup", Args: []string{"-setsecurewebproxystate", "Wi-Fi", "on"}},
		{Name: "networksetup", Args: []string{"-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "1080"}},
		{Name: "networksetup", Args: []string{"-setsocksfirewallproxystate", "Wi-Fi", "on"}},
		{Name: "networksetup", Args: []string{"-setwebproxy", "Ethernet", "127.0.0.1", "8088"}},
		{Name: "networksetup", Args: []string{"-setwebproxystate", "Ethernet", "on"}},
		{Name: "networksetup", Args: []string{"-setsecurewebproxy", "Ethernet", "127.0.0.1", "8088"}},
		{Name: "networksetup", Args: []string{"-setsecurewebproxystate", "Ethernet", "on"}},
		{Name: "networksetup", Args: []string{"-setsocksfirewallproxy", "Ethernet", "127.0.0.1", "1080"}},
		{Name: "networksetup", Args: []string{"-setsocksfirewallproxystate", "Ethernet", "on"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin proxy apply commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDarwinSystemProxyRestoreCommands(t *testing.T) {
	states := []darwinVPNProxyState{
		{Service: "Wi-Fi", Kind: "web", Enabled: true, Server: "192.168.1.2", Port: "8888"},
		{Service: "Wi-Fi", Kind: "secureweb", Enabled: false, Server: "192.168.1.3", Port: "8443"},
		{Service: "Wi-Fi", Kind: "socks", Enabled: false},
	}

	got := buildDarwinSystemProxyRestoreCommands(states)
	want := []vpnTunCommand{
		{Name: "networksetup", Args: []string{"-setwebproxy", "Wi-Fi", "192.168.1.2", "8888"}},
		{Name: "networksetup", Args: []string{"-setwebproxystate", "Wi-Fi", "on"}},
		{Name: "networksetup", Args: []string{"-setsecurewebproxy", "Wi-Fi", "192.168.1.3", "8443"}},
		{Name: "networksetup", Args: []string{"-setsecurewebproxystate", "Wi-Fi", "off"}},
		{Name: "networksetup", Args: []string{"-setsocksfirewallproxystate", "Wi-Fi", "off"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin proxy restore commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDarwinSystemProxyClearCommands(t *testing.T) {
	got := buildDarwinSystemProxyClearCommands([]string{"Wi-Fi", "Ethernet"})
	want := []vpnTunCommand{
		{Name: "networksetup", Args: []string{"-setwebproxystate", "Wi-Fi", "off"}},
		{Name: "networksetup", Args: []string{"-setsecurewebproxystate", "Wi-Fi", "off"}},
		{Name: "networksetup", Args: []string{"-setsocksfirewallproxystate", "Wi-Fi", "off"}},
		{Name: "networksetup", Args: []string{"-setwebproxystate", "Ethernet", "off"}},
		{Name: "networksetup", Args: []string{"-setsecurewebproxystate", "Ethernet", "off"}},
		{Name: "networksetup", Args: []string{"-setsocksfirewallproxystate", "Ethernet", "off"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin proxy clear commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}
