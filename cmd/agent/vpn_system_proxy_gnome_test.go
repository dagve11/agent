package main

import (
	"reflect"
	"testing"
)

func TestBuildLinuxGSettingsProxyApplyCommands(t *testing.T) {
	got, err := buildLinuxGSettingsProxyApplyCommands("127.0.0.1:8088", "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("build gsettings proxy apply commands: %v", err)
	}
	want := []vpnTunCommand{
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "host", "'127.0.0.1'"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "port", "8088"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "enabled", "true"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.https", "host", "'127.0.0.1'"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.https", "port", "8088"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.socks", "host", "'127.0.0.1'"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.socks", "port", "1080"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy", "mode", "'manual'"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linux gsettings apply commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildLinuxGSettingsProxyApplyCommandsClearsMissingProxyKinds(t *testing.T) {
	got, err := buildLinuxGSettingsProxyApplyCommands("", "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("build socks-only gsettings proxy apply commands: %v", err)
	}
	want := []vpnTunCommand{
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "host", "''"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "port", "0"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "enabled", "false"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.https", "host", "''"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.https", "port", "0"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.socks", "host", "'127.0.0.1'"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.socks", "port", "1080"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy", "mode", "'manual'"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linux socks-only gsettings apply commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildLinuxGSettingsProxyRestoreCommands(t *testing.T) {
	states := []linuxGSettingsProxyState{
		{Schema: "org.gnome.system.proxy.http", Key: "host", Raw: "'proxy.local'"},
		{Schema: "org.gnome.system.proxy.http", Key: "port", Raw: "3128"},
		{Schema: "org.gnome.system.proxy.http", Key: "enabled", Raw: "true"},
		{Schema: "org.gnome.system.proxy.https", Key: "host", Raw: "''"},
		{Schema: "org.gnome.system.proxy.https", Key: "port", Raw: "0"},
		{Schema: "org.gnome.system.proxy.socks", Key: "host", Raw: "'127.0.0.1'"},
		{Schema: "org.gnome.system.proxy.socks", Key: "port", Raw: "1080"},
		{Schema: "org.gnome.system.proxy", Key: "mode", Raw: "'auto'"},
	}

	got := buildLinuxGSettingsProxyRestoreCommands(states)
	want := []vpnTunCommand{
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "host", "'proxy.local'"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "port", "3128"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "enabled", "true"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.https", "host", "''"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.https", "port", "0"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.socks", "host", "'127.0.0.1'"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.socks", "port", "1080"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy", "mode", "'auto'"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linux gsettings restore commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildLinuxGSettingsProxyClearCommands(t *testing.T) {
	got := buildLinuxGSettingsProxyClearCommands()
	want := []vpnTunCommand{
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "host", "''"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "port", "0"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.http", "enabled", "false"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.https", "host", "''"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.https", "port", "0"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.socks", "host", "''"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy.socks", "port", "0"}},
		{Name: "gsettings", Args: []string{"set", "org.gnome.system.proxy", "mode", "'none'"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linux gsettings clear commands mismatch:\nwant %#v\ngot  %#v", want, got)
	}
}
