package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nezhahq/agent/model"
	"golang.org/x/net/proxy"
)

const defaultVPNEgressProbeTimeout = 10 * time.Second
const maxVPNEgressProbeBodyBytes = 512
const vpnEgressProbeRetryInterval = 100 * time.Millisecond

func defaultVPNEgressProbe(ctx context.Context, req model.VPNControlRequest) ([]string, error) {
	probeURL := strings.TrimSpace(req.Extra["egress_probe_url"])
	if probeURL == "" {
		return nil, nil
	}
	client, proxyLabel, err := vpnEgressProbeHTTPClient(req)
	if err != nil {
		return []string{fmt.Sprintf("[egress] probe failed: %v", err)}, err
	}
	expectedIPs := parseVPNEgressExpectedIPs(req)

	var lastErr error
	var lastLogs []string
	for {
		logs, err := runVPNEgressProbeOnce(ctx, client, probeURL, proxyLabel, expectedIPs)
		if err == nil {
			return logs, nil
		}
		lastErr = err
		lastLogs = logs
		timer := time.NewTimer(vpnEgressProbeRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			if lastErr != nil {
				if len(lastLogs) > 0 {
					return lastLogs, lastErr
				}
				return []string{lastErr.Error()}, lastErr
			}
			err := fmt.Errorf("[egress] probe failed via %s: %v", proxyLabel, ctx.Err())
			return []string{err.Error()}, err
		case <-timer.C:
		}
	}
}

func runVPNEgressProbeOnce(ctx context.Context, client *http.Client, probeURL string, proxyLabel string, expectedIPs []string) ([]string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("[egress] probe request invalid: %v", err)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("[egress] probe failed via %s: %v", proxyLabel, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVPNEgressProbeBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("[egress] probe read failed via %s: %v", proxyLabel, err)
	}
	observed := strings.TrimSpace(string(body))
	if observed == "" {
		observed = resp.Status
	}
	matchPart := ""
	if len(expectedIPs) > 0 {
		matched := vpnEgressProbeMatchesExpected(observed, expectedIPs)
		expected := strings.Join(expectedIPs, ",")
		matchPart = fmt.Sprintf(" expected=%s match=%t", expected, matched)
		line := fmt.Sprintf("[egress] probe url=%s via=%s status=%s observed=%s%s", probeURL, proxyLabel, resp.Status, observed, matchPart)
		if !matched {
			return []string{line}, fmt.Errorf("[egress] observed exit %q does not match expected %s", observed, expected)
		}
		return []string{line}, nil
	}
	return []string{fmt.Sprintf("[egress] probe url=%s via=%s status=%s observed=%s%s", probeURL, proxyLabel, resp.Status, observed, matchPart)}, nil
}

func parseVPNEgressExpectedIPs(req model.VPNControlRequest) []string {
	raw := strings.TrimSpace(req.Extra["egress_expected_ips"])
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func vpnEgressProbeMatchesExpected(observed string, expectedIPs []string) bool {
	observed = strings.TrimSpace(observed)
	if observed == "" {
		return false
	}
	for _, expected := range expectedIPs {
		expected = strings.TrimSpace(expected)
		if expected != "" && strings.Contains(observed, expected) {
			return true
		}
	}
	return false
}

func vpnEgressProbeHTTPClient(req model.VPNControlRequest) (*http.Client, string, error) {
	if listenHTTP := strings.TrimSpace(req.ListenHTTP); listenHTTP != "" {
		proxyURL, err := url.Parse("http://" + listenHTTP)
		if err != nil {
			return nil, "", err
		}
		return &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		}, "http://" + listenHTTP, nil
	}
	if listenSOCKS := strings.TrimSpace(req.ListenSOCKS); listenSOCKS != "" {
		dialer, err := proxy.SOCKS5("tcp", listenSOCKS, nil, proxy.Direct)
		if err != nil {
			return nil, "", err
		}
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					type result struct {
						conn net.Conn
						err  error
					}
					ch := make(chan result, 1)
					go func() {
						conn, err := dialer.Dial(network, address)
						ch <- result{conn: conn, err: err}
					}()
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case res := <-ch:
						return res.conn, res.err
					}
				},
			},
		}, "socks5://" + listenSOCKS, nil
	}
	return nil, "", fmt.Errorf("egress probe requires local HTTP or SOCKS listen address")
}

func vpnEgressProbeTimeout(req model.VPNControlRequest) time.Duration {
	raw := strings.TrimSpace(req.Extra["egress_probe_timeout_seconds"])
	if raw == "" {
		return defaultVPNEgressProbeTimeout
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return defaultVPNEgressProbeTimeout
	}
	if seconds > 60 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}
