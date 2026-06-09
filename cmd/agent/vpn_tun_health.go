package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nezhahq/agent/model"
)

const defaultVPNTunHealthTimeout = 10 * time.Second

func defaultVPNTunHealthProbe(ctx context.Context, req model.VPNControlRequest) error {
	probeURL := strings.TrimSpace(req.Extra["tun_health_url"])
	if probeURL == "" {
		return nil
	}
	httpClient := httpClientDefault()
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 399 {
		return fmt.Errorf("unexpected TUN health status %s", resp.Status)
	}
	return nil
}

func vpnTunHealthProbeTimeout(req model.VPNControlRequest) time.Duration {
	raw := strings.TrimSpace(req.Extra["tun_health_timeout_seconds"])
	if raw == "" {
		return defaultVPNTunHealthTimeout
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return defaultVPNTunHealthTimeout
	}
	if seconds > 60 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}

func validateVPNTunHealthURL(req model.VPNControlRequest) error {
	rawURL := strings.TrimSpace(req.Extra["tun_health_url"])
	if rawURL == "" {
		return nil
	}
	if !isVPNTunMode(req.Mode) || req.Role != model.VPNRoleEntry {
		return errors.New("tun_health_url is only supported for entry TUN sessions")
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("invalid tun_health_url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("tun_health_url must use http or https")
	}
	return nil
}
