package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nezhahq/agent/model"
)

func TestBuildVPNSingBoxConfigEntrySystemProxyUsesLocalBridgeAndRules(t *testing.T) {
	req := model.VPNControlRequest{
		SessionID:   "vpn-session-1",
		Role:        model.VPNRoleEntry,
		Mode:        model.VPNModeSystemProxy,
		ListenHTTP:  "127.0.0.1:8088",
		ListenSOCKS: "127.0.0.1:1080",
		Rules: model.VPNRules{
			Mode:        model.VPNRuleModeDomain,
			Domains:     []string{"github.com", "api.github.com"},
			DirectCIDRs: []string{"198.51.100.0/24"},
		},
		DashboardBypass: []string{"dashboard.example.com", "203.0.113.10"},
		Extra: map[string]string{
			"bridge_addr": "127.0.0.1:19090",
		},
	}

	raw, err := buildVPNSingBoxConfig(req)
	if err != nil {
		t.Fatalf("build entry config: %v", err)
	}
	cfg := decodeSingBoxConfigForTest(t, raw)

	inbounds := cfg.array("inbounds")
	if len(inbounds) != 2 {
		t.Fatalf("entry system proxy must expose HTTP and SOCKS mixed inbounds, got %#v", inbounds)
	}
	assertObjectWithFieldsForTest(t, inbounds, map[string]any{
		"type":        "mixed",
		"tag":         "local-socks",
		"listen":      "127.0.0.1",
		"listen_port": float64(1080),
	})
	assertObjectWithFieldsForTest(t, inbounds, map[string]any{
		"type":        "mixed",
		"tag":         "local-http",
		"listen":      "127.0.0.1",
		"listen_port": float64(8088),
	})

	outbounds := cfg.array("outbounds")
	assertObjectWithFieldsForTest(t, outbounds, map[string]any{
		"type":        "socks",
		"tag":         "vpn-exit",
		"server":      "127.0.0.1",
		"server_port": float64(19090),
	})
	assertObjectWithFieldsForTest(t, outbounds, map[string]any{"type": "direct", "tag": "direct"})
	assertObjectWithFieldsForTest(t, outbounds, map[string]any{"type": "block", "tag": "block"})

	route := cfg.object("route")
	if route["final"] != "direct" {
		t.Fatalf("domain rule mode must default unmatched traffic to direct, got %#v", route["final"])
	}
	if route["auto_detect_interface"] != true {
		t.Fatalf("route must auto-detect interface to reduce TUN loop risk, got %#v", route)
	}
	rules := configObject(route).array("rules")
	assertObjectWithFieldsForTest(t, rules, map[string]any{
		"outbound": "direct",
		"domain":   []any{"dashboard.example.com"},
	})
	assertObjectWithFieldsForTest(t, rules, map[string]any{
		"outbound": "direct",
		"ip_cidr":  []any{"203.0.113.10/32", "198.51.100.0/24"},
	})
	assertObjectWithFieldsForTest(t, rules, map[string]any{
		"outbound": "vpn-exit",
		"domain":   []any{"github.com", "api.github.com"},
	})
	assertObjectWithFieldsForTest(t, rules, map[string]any{
		"outbound": "block",
		"ip_cidr":  defaultSensitiveCIDRsForTest(),
	})
}

func TestBuildVPNSingBoxConfigEntryUsesLocalRuleSetsWhenPresent(t *testing.T) {
	rulesDir := t.TempDir()
	for _, name := range []string{vpnRuleSetGeositeCN + ".srs", vpnRuleSetGeoIPCN + ".srs"} {
		if err := os.WriteFile(filepath.Join(rulesDir, name), []byte("rule-set"), 0600); err != nil {
			t.Fatalf("write rule-set file %s: %v", name, err)
		}
	}

	req := model.VPNControlRequest{
		SessionID:   "vpn-session-rules",
		Role:        model.VPNRoleEntry,
		Mode:        model.VPNModeSystemProxy,
		ListenSOCKS: "127.0.0.1:1080",
		Rules: model.VPNRules{
			Mode:    model.VPNRuleModeDomain,
			Domains: []string{"github.com"},
		},
		Extra: map[string]string{
			"bridge_addr": "127.0.0.1:19090",
			"rules_dir":   rulesDir,
		},
	}

	raw, err := buildVPNSingBoxConfig(req)
	if err != nil {
		t.Fatalf("build entry config: %v", err)
	}
	cfg := decodeSingBoxConfigForTest(t, raw)

	route := cfg.object("route")
	if route["final"] != "vpn-exit" {
		t.Fatalf("rule-set routing must default unmatched traffic to vpn-exit, got %#v", route["final"])
	}
	ruleSets := route.array("rule_set")
	assertObjectWithFieldsForTest(t, ruleSets, map[string]any{
		"type":   "local",
		"tag":    "geosite-cn",
		"format": "binary",
		"path":   filepath.Join(rulesDir, "geosite-cn.srs"),
	})
	assertObjectWithFieldsForTest(t, ruleSets, map[string]any{
		"type":   "local",
		"tag":    "geoip-cn",
		"format": "binary",
		"path":   filepath.Join(rulesDir, "geoip-cn.srs"),
	})

	rules := route.array("rules")
	assertObjectWithFieldsForTest(t, rules, map[string]any{
		"outbound": "vpn-exit",
		"domain":   []any{"github.com"},
	})
	assertObjectWithFieldsForTest(t, rules, map[string]any{
		"outbound": "direct",
		"rule_set": "geosite-cn",
	})
	assertObjectWithFieldsForTest(t, rules, map[string]any{
		"outbound": "direct",
		"rule_set": "geoip-cn",
	})
}

func TestBuildVPNSingBoxConfigExitProvidesLoopbackInbound(t *testing.T) {
	req := model.VPNControlRequest{
		SessionID: "vpn-session-1",
		Role:      model.VPNRoleExit,
		Mode:      model.VPNModeSystemProxy,
		Extra: map[string]string{
			"bridge_listen": "127.0.0.1:19091",
		},
	}

	raw, err := buildVPNSingBoxConfig(req)
	if err != nil {
		t.Fatalf("build exit config: %v", err)
	}
	cfg := decodeSingBoxConfigForTest(t, raw)

	inbounds := cfg.array("inbounds")
	if len(inbounds) != 1 {
		t.Fatalf("exit side must expose exactly one loopback inbound for Agent bridge, got %#v", inbounds)
	}
	assertObjectWithFieldsForTest(t, inbounds, map[string]any{
		"type":        "socks",
		"tag":         "relay-in",
		"listen":      "127.0.0.1",
		"listen_port": float64(19091),
	})

	outbounds := cfg.array("outbounds")
	assertObjectWithFieldsForTest(t, outbounds, map[string]any{"type": "direct", "tag": "direct"})
	assertObjectWithFieldsForTest(t, outbounds, map[string]any{"type": "block", "tag": "block"})

	route := cfg.object("route")
	if route["final"] != "direct" {
		t.Fatalf("exit side must send accepted bridge traffic directly, got %#v", route["final"])
	}
	rules := configObject(route).array("rules")
	assertObjectWithFieldsForTest(t, rules, map[string]any{
		"outbound": "block",
		"ip_cidr":  defaultSensitiveCIDRsForTest(),
	})
}

func TestBuildVPNSingBoxConfigEntryTunIncludesDNSAndHijackRule(t *testing.T) {
	req := model.VPNControlRequest{
		SessionID: "vpn-session-tun",
		Role:      model.VPNRoleEntry,
		Mode:      model.VPNModeTunSplit,
		TunName:   "nezha-vpn",
		DNSServer: "https://1.1.1.1/dns-query",
		Rules: model.VPNRules{
			Mode:    model.VPNRuleModeDomain,
			Domains: []string{"github.com"},
		},
		DashboardBypass: []string{"dashboard.example.com", "203.0.113.10"},
		Extra: map[string]string{
			"bridge_addr": "127.0.0.1:19090",
		},
	}

	raw, err := buildVPNSingBoxConfig(req)
	if err != nil {
		t.Fatalf("build TUN entry config: %v", err)
	}
	cfg := decodeSingBoxConfigForTest(t, raw)

	inbounds := cfg.array("inbounds")
	assertObjectWithFieldsForTest(t, inbounds, map[string]any{
		"type":           "tun",
		"tag":            "tun-in",
		"interface_name": "nezha-vpn",
		"auto_route":     true,
		"strict_route":   true,
	})
	dns := cfg.object("dns")
	servers := dns.array("servers")
	assertObjectWithFieldsForTest(t, servers, map[string]any{
		"tag":     "remote",
		"address": "https://1.1.1.1/dns-query",
	})
	rules := dns.array("rules")
	assertObjectWithFieldsForTest(t, rules, map[string]any{
		"domain": []any{"dashboard.example.com"},
		"server": "direct",
	})

	routeRules := cfg.object("route").array("rules")
	assertObjectWithFieldsForTest(t, routeRules, map[string]any{
		"protocol": "dns",
		"action":   "hijack-dns",
	})
}

func TestBuildVPNSingBoxConfigPlacesDashboardBypassBeforeSensitiveBlock(t *testing.T) {
	req := model.VPNControlRequest{
		SessionID: "vpn-session-private-dashboard",
		Role:      model.VPNRoleEntry,
		Mode:      model.VPNModeTunGlobal,
		Rules: model.VPNRules{
			Mode:        model.VPNRuleModeGlobal,
			DirectCIDRs: []string{"192.168.50.0/24"},
		},
		DashboardBypass: []string{"10.1.2.3"},
		Extra: map[string]string{
			"bridge_addr": "127.0.0.1:19090",
		},
	}

	raw, err := buildVPNSingBoxConfig(req)
	if err != nil {
		t.Fatalf("build TUN entry config: %v", err)
	}
	cfg := decodeSingBoxConfigForTest(t, raw)
	routeRules := cfg.object("route").array("rules")

	directIndex := indexObjectWithFieldsForTest(t, routeRules, map[string]any{
		"outbound": "direct",
		"ip_cidr":  []any{"10.1.2.3/32", "192.168.50.0/24"},
	})
	blockIndex := indexObjectWithFieldsForTest(t, routeRules, map[string]any{
		"outbound": "block",
		"ip_cidr":  defaultSensitiveCIDRsForTest(),
	})
	if directIndex > blockIndex {
		t.Fatalf("dashboard bypass/direct CIDR rule must be evaluated before sensitive block rule, direct=%d block=%d rules=%#v", directIndex, blockIndex, routeRules)
	}
}

func defaultSensitiveCIDRsForTest() []any {
	return []any{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "169.254.169.254/32", "::1/128", "fc00::/7", "fe80::/10"}
}

type configObject map[string]any

func decodeSingBoxConfigForTest(t *testing.T, raw []byte) configObject {
	t.Helper()

	var cfg configObject
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config must be valid JSON: %v\n%s", err, string(raw))
	}
	return cfg
}

func (o configObject) object(key string) configObject {
	value, ok := o[key].(map[string]any)
	if !ok {
		return nil
	}
	return configObject(value)
}

func (o configObject) array(key string) []any {
	value, ok := o[key].([]any)
	if !ok {
		return nil
	}
	return value
}

func assertObjectWithFieldsForTest(t *testing.T, objects []any, fields map[string]any) {
	t.Helper()

	_ = indexObjectWithFieldsForTest(t, objects, fields)
}

func indexObjectWithFieldsForTest(t *testing.T, objects []any, fields map[string]any) int {
	t.Helper()

	for index, item := range objects {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if objectContainsFieldsForTest(object, fields) {
			return index
		}
	}
	t.Fatalf("missing object with fields %#v in %#v", fields, objects)
	return -1
}

func objectContainsFieldsForTest(object map[string]any, fields map[string]any) bool {
	for key, want := range fields {
		got, ok := object[key]
		if !ok {
			return false
		}
		if !jsonValuesEqualForTest(got, want) {
			return false
		}
	}
	return true
}

func jsonValuesEqualForTest(got any, want any) bool {
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	return string(gotJSON) == string(wantJSON)
}
