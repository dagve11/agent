package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/nezhahq/agent/model"
)

type vpnHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

var vpnCoreSHA256HexPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func validateVPNCoreSpec(spec model.VPNCoreSpec) error {
	downloadURL := strings.TrimSpace(spec.DownloadURL)
	if downloadURL != "" {
		parsed, err := url.ParseRequestURI(downloadURL)
		if err != nil {
			return fmt.Errorf("invalid core download url: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("core download url must use http or https")
		}
	}
	expectedSHA256 := strings.TrimSpace(spec.SHA256)
	if expectedSHA256 == "" {
		return nil
	}
	if !vpnCoreSHA256HexPattern.MatchString(expectedSHA256) {
		return errors.New("core sha256 must be a 64-character hex digest without prefix")
	}
	return nil
}

func validateVPNWintunSpec(req model.VPNControlRequest) error {
	if req.Role != model.VPNRoleEntry || !isVPNTunMode(req.Mode) {
		return nil
	}
	downloadURL := strings.TrimSpace(req.Extra["wintun_url"])
	if downloadURL != "" {
		parsed, err := url.ParseRequestURI(downloadURL)
		if err != nil {
			return fmt.Errorf("invalid wintun_url: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("wintun_url must use http or https")
		}
	}
	expectedSHA256 := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(req.Extra["wintun_sha256"]), "sha256:"))
	if expectedSHA256 == "" {
		return nil
	}
	if !vpnCoreSHA256HexPattern.MatchString(expectedSHA256) {
		return errors.New("wintun_sha256 must be a 64-character hex digest")
	}
	return nil
}

func prepareVPNCore(ctx context.Context, spec model.VPNCoreSpec, corePath string, httpClient vpnHTTPClient) (string, error) {
	if err := validateVPNCoreSpec(spec); err != nil {
		return "", err
	}
	if strings.TrimSpace(corePath) == "" {
		corePath = defaultVPNCorePath()
	}
	if strings.TrimSpace(spec.Name) != "" && spec.Name != "sing-box" {
		return "", fmt.Errorf("unsupported VPN core %q", spec.Name)
	}

	if _, err := os.Stat(corePath); err == nil {
		return corePath, verifyVPNCoreSHA256(corePath, spec.SHA256)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	if strings.TrimSpace(spec.DownloadURL) == "" {
		return "", fmt.Errorf("VPN core not found at %s", corePath)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if err := downloadVPNCore(ctx, spec.DownloadURL, corePath, httpClient); err != nil {
		return "", err
	}
	if err := verifyVPNCoreSHA256(corePath, spec.SHA256); err != nil {
		_ = os.Remove(corePath)
		return "", err
	}
	return corePath, nil
}

func downloadVPNCore(ctx context.Context, url string, corePath string, httpClient vpnHTTPClient) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("download VPN core failed: %s", resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(corePath), 0750); err != nil {
		return err
	}
	tmpPath := corePath + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, resp.Body)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0700); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
	}
	return os.Rename(tmpPath, corePath)
}

func verifyVPNCoreSHA256(path string, expected string) error {
	expected = strings.TrimSpace(strings.TrimPrefix(expected, "sha256:"))
	if expected == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("VPN core sha256 mismatch: want %s got %s", expected, actual)
	}
	return nil
}

func resolveVPNCorePath(defaultCorePath string, spec model.VPNCoreSpec) string {
	if strings.TrimSpace(spec.Name) != "" && filepath.IsAbs(spec.Name) {
		return spec.Name
	}
	return defaultCorePath
}

func vpnDisabledByConfig() error {
	if agentConfig.DisableVPN {
		return errors.New("Agent VPN rejected by DisableVPN")
	}
	return nil
}

func vpnModeAllowedByConfig(mode string) error {
	if strings.TrimSpace(mode) == "" {
		mode = model.VPNModeSystemProxy
	}
	switch mode {
	case model.VPNModeSystemProxy:
		if !agentConfig.VPNAllowSystemProxy {
			return errors.New("Agent VPN system_proxy mode is disabled by vpn_allow_system_proxy=false")
		}
	case model.VPNModeTunSplit, model.VPNModeTunGlobal:
		if !agentConfig.VPNAllowTun {
			return errors.New("Agent VPN tun mode is disabled by vpn_allow_tun=false")
		}
	default:
		return fmt.Errorf("unsupported VPN mode %q", mode)
	}
	return nil
}

func isVPNTunMode(mode string) bool {
	return mode == model.VPNModeTunSplit || mode == model.VPNModeTunGlobal
}

func isWindowsRuntime() bool {
	return runtime.GOOS == "windows"
}
