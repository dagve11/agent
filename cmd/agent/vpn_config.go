package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nezhahq/agent/model"
)

const (
	defaultVPNLocalHTTP      = "127.0.0.1:8088"
	defaultVPNLocalSOCKS     = "127.0.0.1:1080"
	defaultVPNTunDNSServer   = "https://1.1.1.1/dns-query"
	defaultVPNEntryBridge    = "127.0.0.1:19090"
	defaultVPNExitBridge     = "127.0.0.1:19091"
	defaultVPNPolicyCoreID   = "core_policy"
	vpnOutboundExit          = "vpn-exit"
	vpnOutboundDirect        = "direct"
	vpnOutboundBlock         = "block"
	vpnOutboundModeSelector  = "vpn-mode"
	vpnOutboundRuleMatch     = "vpn-rule-match"
	vpnOutboundRuleDirect    = "vpn-rule-direct"
	vpnInboundLocalHTTP      = "local-http"
	vpnInboundLocalSOCKS     = "local-socks"
	vpnInboundRelay          = "relay-in"
	vpnSingBoxConfigLogLevel = "warn"
	vpnRuleSetGeositeCN      = "geosite-cn"
	vpnRuleSetGeoIPCN        = "geoip-cn"
)

var defaultVPNSensitiveCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"169.254.169.254/32",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

func buildVPNSingBoxConfig(req model.VPNControlRequest) ([]byte, error) {
	if req.Role != model.VPNRoleEntry && req.Role != model.VPNRoleExit {
		return nil, fmt.Errorf("unsupported VPN role %q", req.Role)
	}
	if req.Mode == "" {
		req.Mode = model.VPNModeSystemProxy
	}

	var cfg map[string]any
	var err error
	switch req.Role {
	case model.VPNRoleEntry:
		cfg, err = buildVPNEntrySingBoxConfig(req)
	case model.VPNRoleExit:
		cfg, err = buildVPNExitSingBoxConfig(req)
	}
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func buildVPNEntrySingBoxConfig(req model.VPNControlRequest) (map[string]any, error) {
	inbounds, err := buildVPNEntryInbounds(req)
	if err != nil {
		return nil, err
	}
	bridgeHost, bridgePort, err := splitListenAddress(firstNonEmpty(req.Extra["bridge_addr"], defaultVPNEntryBridge))
	if err != nil {
		return nil, fmt.Errorf("invalid entry bridge address: %w", err)
	}

	cfg := map[string]any{
		"log": map[string]any{
			"level": vpnSingBoxConfigLogLevel,
		},
		"inbounds":  inbounds,
		"outbounds": buildVPNEntryOutbounds(req, bridgeHost, bridgePort),
		"route":     buildVPNEntryRoute(req),
	}
	if runtimeAPI := vpnRuntimeControlAddress(req); runtimeAPI != "" {
		cfg["experimental"] = map[string]any{
			"clash_api": map[string]any{
				"external_controller": runtimeAPI,
			},
		}
	}
	if isVPNTunMode(req.Mode) {
		cfg["dns"] = buildVPNTunDNS(req)
	}
	return cfg, nil
}

func buildVPNEntryOutbounds(req model.VPNControlRequest, bridgeHost string, bridgePort int) []map[string]any {
	finalOutbound, ruleMatchOutbound, ruleDirectOutbound := vpnSelectorOutboundsForRuleMode(req)
	return []map[string]any{
		{
			"type":        "socks",
			"tag":         vpnOutboundExit,
			"server":      bridgeHost,
			"server_port": bridgePort,
		},
		{
			"type": "direct",
			"tag":  vpnOutboundDirect,
		},
		{
			"type": "block",
			"tag":  vpnOutboundBlock,
		},
		buildVPNSelectorOutbound(vpnOutboundModeSelector, finalOutbound),
		buildVPNSelectorOutbound(vpnOutboundRuleMatch, ruleMatchOutbound),
		buildVPNSelectorOutbound(vpnOutboundRuleDirect, ruleDirectOutbound),
	}
}

func buildVPNSelectorOutbound(tag string, selected string) map[string]any {
	return map[string]any{
		"type":      "selector",
		"tag":       tag,
		"outbounds": []string{vpnOutboundExit, vpnOutboundDirect},
		"default":   selected,
	}
}

func buildVPNEntryInbounds(req model.VPNControlRequest) ([]map[string]any, error) {
	if req.Mode == "" || req.Mode == model.VPNModeSystemProxy {
		return buildVPNSystemProxyInbounds(req)
	}
	if req.Mode == model.VPNModeTunSplit || req.Mode == model.VPNModeTunGlobal {
		tunName := strings.TrimSpace(req.TunName)
		if tunName == "" {
			tunName = "nezha-vpn"
		}
		return []map[string]any{
			{
				"type":           "tun",
				"tag":            "tun-in",
				"interface_name": tunName,
				"address":        []string{"172.19.0.1/30"},
				"auto_route":     true,
				"strict_route":   true,
				"stack":          "system",
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported VPN mode %q", req.Mode)
}

func buildVPNSystemProxyInbounds(req model.VPNControlRequest) ([]map[string]any, error) {
	listenHTTP := strings.TrimSpace(req.ListenHTTP)
	listenSOCKS := strings.TrimSpace(req.ListenSOCKS)
	if listenHTTP == "" && listenSOCKS == "" {
		listenSOCKS = defaultVPNLocalSOCKS
	}

	var inbounds []map[string]any
	if listenSOCKS != "" {
		host, port, err := splitListenAddress(listenSOCKS)
		if err != nil {
			return nil, fmt.Errorf("invalid SOCKS listen address: %w", err)
		}
		inbounds = append(inbounds, map[string]any{
			"type":        "mixed",
			"tag":         vpnInboundLocalSOCKS,
			"listen":      host,
			"listen_port": port,
		})
	}
	if listenHTTP != "" {
		host, port, err := splitListenAddress(listenHTTP)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTP listen address: %w", err)
		}
		inbounds = append(inbounds, map[string]any{
			"type":        "mixed",
			"tag":         vpnInboundLocalHTTP,
			"listen":      host,
			"listen_port": port,
		})
	}
	return inbounds, nil
}

func buildVPNEntryRoute(req model.VPNControlRequest) map[string]any {
	rules := []map[string]any{}
	if isVPNTunMode(req.Mode) {
		rules = append(rules, map[string]any{
			"protocol": "dns",
			"action":   "hijack-dns",
		})
	}
	if directDomain, directCIDRs := splitDashboardBypass(req.DashboardBypass); len(directDomain) > 0 || len(directCIDRs) > 0 || len(req.Rules.DirectCIDRs) > 0 {
		if len(directDomain) > 0 {
			rules = append(rules, map[string]any{
				"domain":   directDomain,
				"outbound": vpnOutboundDirect,
			})
		}
		allDirectCIDRs := append([]string{}, directCIDRs...)
		allDirectCIDRs = append(allDirectCIDRs, cleanStrings(req.Rules.DirectCIDRs)...)
		if len(allDirectCIDRs) > 0 {
			rules = append(rules, map[string]any{
				"ip_cidr":  allDirectCIDRs,
				"outbound": vpnOutboundDirect,
			})
		}
	}
	if blockRule := buildVPNSensitiveBlockRule(); len(blockRule) > 0 {
		rules = append(rules, blockRule)
	}

	if domains := cleanStrings(req.Rules.Domains); len(domains) > 0 {
		rules = append(rules, map[string]any{
			"domain":   domains,
			"outbound": vpnOutboundRuleMatch,
		})
	}
	if cidrs := cleanStrings(req.Rules.CIDRs); len(cidrs) > 0 {
		rules = append(rules, map[string]any{
			"ip_cidr":  cidrs,
			"outbound": vpnOutboundRuleMatch,
		})
	}

	if ruleSets, ok := activeVPNRuleSetRouteItems(req); ok {
		rules = append(rules,
			map[string]any{
				"rule_set": vpnRuleSetGeositeCN,
				"outbound": vpnOutboundRuleDirect,
			},
			map[string]any{
				"rule_set": vpnRuleSetGeoIPCN,
				"outbound": vpnOutboundRuleDirect,
			},
		)
		return buildVPNRoute(rules, vpnOutboundModeSelector, ruleSets)
	}

	return buildVPNRoute(rules, vpnOutboundModeSelector, nil)
}

func buildVPNRoute(rules []map[string]any, final string, ruleSets []map[string]any) map[string]any {
	route := map[string]any{
		"auto_detect_interface": true,
		"rules":                 rules,
		"final":                 final,
	}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	return route
}

func activeVPNRuleSetRouteItems(req model.VPNControlRequest) ([]map[string]any, bool) {
	rulesDir := vpnRuleSetDirFromRequest(req)
	if strings.TrimSpace(rulesDir) == "" {
		return nil, false
	}
	geositePath := filepath.Join(rulesDir, vpnRuleSetGeositeCN+".srs")
	geoipPath := filepath.Join(rulesDir, vpnRuleSetGeoIPCN+".srs")
	if !vpnRuleSetFileReady(geositePath) || !vpnRuleSetFileReady(geoipPath) {
		return nil, false
	}
	return []map[string]any{
		{
			"type":   "local",
			"tag":    vpnRuleSetGeositeCN,
			"format": "binary",
			"path":   geositePath,
		},
		{
			"type":   "local",
			"tag":    vpnRuleSetGeoIPCN,
			"format": "binary",
			"path":   geoipPath,
		},
	}, true
}

func vpnRuleSetFileReady(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func vpnRuleSetDirFromRequest(req model.VPNControlRequest) string {
	if dir := strings.TrimSpace(req.Extra["rules_dir"]); dir != "" {
		return dir
	}
	return filepath.Join(defaultVPNSessionCoreCleanupDir(vpnCoreSessionIDFromRequest(req)), "rules")
}

func buildVPNTunDNS(req model.VPNControlRequest) map[string]any {
	if req.Rules.Mode == model.VPNRuleModeDirect {
		return map[string]any{
			"servers": []map[string]any{
				{
					"tag":     "direct",
					"address": "local",
					"detour":  vpnOutboundDirect,
				},
			},
			"final": "direct",
		}
	}

	server := strings.TrimSpace(req.DNSServer)
	if server == "" {
		server = defaultVPNTunDNSServer
	}
	directDomains, _ := splitDashboardBypass(req.DashboardBypass)
	rules := []map[string]any{}
	if len(directDomains) > 0 {
		rules = append(rules, map[string]any{
			"domain": directDomains,
			"server": "direct",
		})
	}
	return map[string]any{
		"servers": []map[string]any{
			{
				"tag":     "remote",
				"address": server,
				"detour":  vpnOutboundExit,
			},
			{
				"tag":     "direct",
				"address": "local",
				"detour":  vpnOutboundDirect,
			},
		},
		"rules": rules,
		"final": "remote",
	}
}

func buildVPNExitSingBoxConfig(req model.VPNControlRequest) (map[string]any, error) {
	bridgeHost, bridgePort, err := splitListenAddress(firstNonEmpty(req.Extra["bridge_listen"], defaultVPNExitBridge))
	if err != nil {
		return nil, fmt.Errorf("invalid exit bridge listen address: %w", err)
	}
	return map[string]any{
		"log": map[string]any{
			"level": vpnSingBoxConfigLogLevel,
		},
		"inbounds": []map[string]any{
			{
				"type":        "socks",
				"tag":         vpnInboundRelay,
				"listen":      bridgeHost,
				"listen_port": bridgePort,
			},
		},
		"outbounds": []map[string]any{
			{
				"type": "direct",
				"tag":  vpnOutboundDirect,
			},
			{
				"type": "block",
				"tag":  vpnOutboundBlock,
			},
		},
		"route": map[string]any{
			"auto_detect_interface": true,
			"rules": []map[string]any{
				buildVPNSensitiveBlockRule(),
			},
			"final": vpnOutboundDirect,
		},
	}, nil
}

func buildVPNSensitiveBlockRule() map[string]any {
	return map[string]any{
		"ip_cidr":  append([]string(nil), defaultVPNSensitiveCIDRs...),
		"outbound": vpnOutboundBlock,
	}
}

func splitDashboardBypass(values []string) ([]string, []string) {
	var domains []string
	var cidrs []string
	for _, raw := range cleanStrings(values) {
		if _, _, err := net.ParseCIDR(raw); err == nil {
			cidrs = append(cidrs, raw)
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			if ip.To4() != nil {
				cidrs = append(cidrs, ip.String()+"/32")
			} else {
				cidrs = append(cidrs, ip.String()+"/128")
			}
			continue
		}
		domains = append(domains, raw)
	}
	return domains, cidrs
}

func splitListenAddress(address string) (string, int, error) {
	host, portRaw, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", 0, err
	}
	if strings.TrimSpace(host) == "" {
		return "", 0, errors.New("host is required")
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portRaw)
	}
	return host, port, nil
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
