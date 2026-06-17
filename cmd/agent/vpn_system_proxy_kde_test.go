package main

import (
	"reflect"
	"testing"
)

func TestBuildLinuxKDEProxyApplyCommands(t *testing.T) {
	got, err := buildLinuxKDEProxyApplyCommands("kwriteconfig6", "127.0.0.1:8088", "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("build KDE proxy apply commands: %v", err)
	}
	want := []vpnTunCommand{
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1"}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Authmode", "0"}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", "http://127.0.0.1:8088"}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", "http://127.0.0.1:8088"}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", "socks://127.0.0.1:1080"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("KDE proxy apply commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildLinuxKDEProxyApplyCommandsClearsMissingProxyKinds(t *testing.T) {
	got, err := buildLinuxKDEProxyApplyCommands("kwriteconfig5", "", "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("build KDE socks-only proxy apply commands: %v", err)
	}
	want := []vpnTunCommand{
		{Name: "kwriteconfig5", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1"}},
		{Name: "kwriteconfig5", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Authmode", "0"}},
		{Name: "kwriteconfig5", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", ""}},
		{Name: "kwriteconfig5", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", ""}},
		{Name: "kwriteconfig5", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", "socks://127.0.0.1:1080"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("KDE socks-only proxy apply commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildLinuxKDEProxyRestoreCommands(t *testing.T) {
	states := []linuxKDEProxyState{
		{Key: "ProxyType", Raw: "4"},
		{Key: "Authmode", Raw: "1"},
		{Key: "httpProxy", Raw: "http://proxy.local:3128"},
		{Key: "httpsProxy", Raw: "http://proxy.local:3129"},
		{Key: "socksProxy", Raw: ""},
		{Key: "NoProxyFor", Raw: "localhost,127.0.0.1"},
	}

	got := buildLinuxKDEProxyRestoreCommands("kwriteconfig6", states)
	want := []vpnTunCommand{
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "4"}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Authmode", "1"}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", "http://proxy.local:3128"}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", "http://proxy.local:3129"}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", ""}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "NoProxyFor", "localhost,127.0.0.1"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("KDE proxy restore commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildLinuxKDEProxyClearCommands(t *testing.T) {
	got := buildLinuxKDEProxyClearCommands("kwriteconfig6")
	want := []vpnTunCommand{
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Authmode", "0"}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", ""}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", ""}},
		{Name: "kwriteconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", ""}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("KDE proxy clear commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildLinuxKDEProxyReadCommands(t *testing.T) {
	got := buildLinuxKDEProxyReadCommands("kreadconfig6")
	want := []vpnTunCommand{
		{Name: "kreadconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType"}},
		{Name: "kreadconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Authmode"}},
		{Name: "kreadconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy"}},
		{Name: "kreadconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy"}},
		{Name: "kreadconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy"}},
		{Name: "kreadconfig6", Args: []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "NoProxyFor"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("KDE proxy read commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestLinuxKDEProxyNotifyCommand(t *testing.T) {
	got := linuxKDEProxyNotifyCommand("dbus-send")
	want := vpnTunCommand{
		Name: "dbus-send",
		Args: []string{"--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("KDE proxy notify command mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildLinuxEnvProxyApplyCommandsUpdatesSystemdAndDBus(t *testing.T) {
	backend := linuxSystemProxyBackend{
		Name:          "environment",
		WriteCommand:  "systemctl",
		NotifyCommand: "dbus-update-activation-environment",
	}
	got, err := buildLinuxEnvProxyApplyCommands(backend, "127.0.0.1:8088", "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("build linux env proxy apply commands: %v", err)
	}
	wantAssignments := []string{
		"http_proxy=http://127.0.0.1:8088",
		"https_proxy=http://127.0.0.1:8088",
		"HTTP_PROXY=http://127.0.0.1:8088",
		"HTTPS_PROXY=http://127.0.0.1:8088",
		"all_proxy=socks5://127.0.0.1:1080",
		"ALL_PROXY=socks5://127.0.0.1:1080",
	}
	want := []vpnTunCommand{
		{Name: "systemctl", Args: append([]string{"--user", "set-environment"}, wantAssignments...)},
		{Name: "dbus-update-activation-environment", Args: append([]string{"--systemd"}, wantAssignments...)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linux env apply commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildLinuxEnvProxyRestoreCommandsRestoresSetAndUnsetVariables(t *testing.T) {
	states := []linuxEnvProxyState{
		{Name: "http_proxy", Value: "http://proxy.local:3128", Set: true},
		{Name: "all_proxy", Set: false},
	}
	got := buildLinuxEnvProxyRestoreCommands("systemctl", "dbus-update-activation-environment", states)
	want := []vpnTunCommand{
		{Name: "systemctl", Args: []string{"--user", "set-environment", "http_proxy=http://proxy.local:3128"}},
		{Name: "systemctl", Args: []string{"--user", "unset-environment", "all_proxy"}},
		{Name: "dbus-update-activation-environment", Args: []string{"--systemd", "http_proxy=http://proxy.local:3128", "all_proxy="}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linux env restore commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildLinuxEnvProxyClearCommands(t *testing.T) {
	got := buildLinuxEnvProxyClearCommands("systemctl", "dbus-update-activation-environment")
	want := []vpnTunCommand{
		{Name: "systemctl", Args: []string{"--user", "unset-environment", "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"}},
		{Name: "dbus-update-activation-environment", Args: []string{"--systemd", "http_proxy=", "https_proxy=", "HTTP_PROXY=", "HTTPS_PROXY=", "all_proxy=", "ALL_PROXY="}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linux env clear commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestParseLinuxEnvProxyEnvironmentKeepsValuesWithEquals(t *testing.T) {
	got := parseLinuxEnvProxyEnvironment("http_proxy=http://proxy.local:3128\nIGNORED\nHTTPS_PROXY=http://user=a@proxy.local:8443\n")
	want := map[string]string{
		"http_proxy":  "http://proxy.local:3128",
		"HTTPS_PROXY": "http://user=a@proxy.local:8443",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linux env parser mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}
