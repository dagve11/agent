package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
)

func TestDefaultVPNTunHealthProbeChecksConfiguredURL(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := defaultVPNTunHealthProbe(context.Background(), model.VPNControlRequest{
		Role: model.VPNRoleEntry,
		Mode: model.VPNModeTunSplit,
		Extra: map[string]string{
			"tun_health_url": server.URL,
		},
	})
	if err != nil {
		t.Fatalf("health probe must pass for successful URL: %v", err)
	}
	if calls != 1 {
		t.Fatalf("health probe must call configured URL once, got %d", calls)
	}
}

func TestDefaultVPNTunHealthProbeFailsOnBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	err := defaultVPNTunHealthProbe(context.Background(), model.VPNControlRequest{
		Role: model.VPNRoleEntry,
		Mode: model.VPNModeTunSplit,
		Extra: map[string]string{
			"tun_health_url": server.URL,
		},
	})
	if err == nil {
		t.Fatal("health probe must fail on bad status")
	}
}

func TestVPNTunHealthProbeTimeoutClampsInvalidValues(t *testing.T) {
	got := vpnTunHealthProbeTimeout(model.VPNControlRequest{Extra: map[string]string{
		"tun_health_timeout_seconds": "90",
	}})
	if got != 60*time.Second {
		t.Fatalf("timeout must clamp to 60 seconds, got %s", got)
	}
}

func TestValidateVPNTunHealthURLRejectsNonHTTPURL(t *testing.T) {
	err := validateVPNTunHealthURL(model.VPNControlRequest{
		Role: model.VPNRoleEntry,
		Mode: model.VPNModeTunSplit,
		Extra: map[string]string{
			"tun_health_url": "file:///etc/passwd",
		},
	})
	if err == nil {
		t.Fatal("TUN health URL must reject non-http schemes")
	}
	if !strings.Contains(err.Error(), "tun_health_url must use http or https") {
		t.Fatalf("error = %q, want scheme validation reason", err.Error())
	}
}
