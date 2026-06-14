package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"time"

	"github.com/nezhahq/agent/model"
)

type vpnHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

var vpnCoreSHA256HexPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

const (
	defaultVPNCoreDownloadBaseURL   = "https://github.com/dagve11/sb-core/releases/latest/download"
	defaultVPNCoreCNDownloadBaseURL = "https://gitee.com/AGZZY11/sb-core/releases/download/V1.0.1"
	maxVPNCoreDownloadRedirects     = 5
	maxVPNCoreManifestBytes         = 1 << 20
	vpnCoreGeoCheckTimeout          = 3 * time.Second
)

var vpnCoreCNTraceURLs = []string{
	"https://blog.cloudflare.com/cdn-cgi/trace",
	"https://developers.cloudflare.com/cdn-cgi/trace",
	"https://1.0.0.1/cdn-cgi/trace",
}

type vpnCoreDownloadCandidate struct {
	URL    string
	SHA256 string
}

type vpnCoreManifest struct {
	Assets []vpnCoreManifestAsset `json:"assets"`
}

type vpnCoreManifestAsset struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Asset  string `json:"asset"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
	CNURL  string `json:"cn_url"`
}

func validateVPNCoreSpec(spec model.VPNCoreSpec) error {
	for _, item := range []struct {
		label string
		value string
	}{
		{label: "core download url", value: spec.DownloadURL},
		{label: "core download base url", value: spec.DownloadBaseURL},
		{label: "core cn download base url", value: spec.CNDownloadBaseURL},
		{label: "core manifest url", value: spec.ManifestURL},
		{label: "core cn manifest url", value: spec.CNManifestURL},
	} {
		if err := validateVPNHTTPURL(item.label, item.value); err != nil {
			return err
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

func validateVPNHTTPURL(label string, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", label, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s must use http or https", label)
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

	candidates, err := vpnCoreDownloadCandidates(ctx, spec, httpClient)
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("VPN core not found at %s", corePath)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	var lastErr error
	for _, candidate := range candidates {
		if err := downloadVPNCore(ctx, candidate.URL, corePath, httpClient); err != nil {
			lastErr = fmt.Errorf("%s: %w", candidate.URL, err)
			continue
		}
		if err := verifyVPNCoreSHA256(corePath, candidate.SHA256); err != nil {
			_ = os.Remove(corePath)
			lastErr = fmt.Errorf("%s: %w", candidate.URL, err)
			continue
		}
		return corePath, nil
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("VPN core not found at %s", corePath)
}

func vpnCoreDownloadCandidates(ctx context.Context, spec model.VPNCoreSpec, httpClient vpnHTTPClient) ([]vpnCoreDownloadCandidate, error) {
	manualURL := strings.TrimSpace(spec.DownloadURL)
	if manualURL != "" {
		return []vpnCoreDownloadCandidate{{
			URL:    manualURL,
			SHA256: strings.TrimSpace(spec.SHA256),
		}}, nil
	}

	assetName := vpnCoreAssetName(runtime.GOOS, runtime.GOARCH)
	if assetName == "" {
		return nil, fmt.Errorf("unsupported VPN core platform %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	preferCN := false
	if shouldDetectVPNCoreCNNetwork(spec) {
		preferCN = detectVPNCoreCNNetwork(ctx, httpClient)
	}
	baseURLs := orderedVPNCoreBaseURLs(spec, preferCN)
	manifestURLs := orderedVPNCoreManifestURLs(spec, baseURLs, preferCN)

	manifestAsset, _ := loadVPNCoreManifestAsset(ctx, manifestURLs, assetName, httpClient)
	downloadAsset := assetName
	if manifestAsset.Asset != "" {
		downloadAsset = manifestAsset.Asset
	}
	sha256Value := strings.TrimSpace(spec.SHA256)
	if sha256Value == "" {
		sha256Value = strings.TrimSpace(manifestAsset.SHA256)
	}

	candidates := make([]vpnCoreDownloadCandidate, 0, len(baseURLs)+2)
	if preferCN {
		candidates = appendVPNCoreCandidate(candidates, manifestAsset.CNURL, sha256Value)
		candidates = appendVPNCoreCandidate(candidates, manifestAsset.URL, sha256Value)
	} else {
		candidates = appendVPNCoreCandidate(candidates, manifestAsset.URL, sha256Value)
		candidates = appendVPNCoreCandidate(candidates, manifestAsset.CNURL, sha256Value)
	}
	for _, baseURL := range baseURLs {
		assetURL, err := joinVPNCoreAssetURL(baseURL, downloadAsset)
		if err != nil {
			return nil, err
		}
		candidates = appendVPNCoreCandidate(candidates, assetURL, sha256Value)
	}
	return candidates, nil
}

func shouldDetectVPNCoreCNNetwork(spec model.VPNCoreSpec) bool {
	globalURL := strings.TrimSpace(spec.DownloadBaseURL)
	cnURL := strings.TrimSpace(spec.CNDownloadBaseURL)
	return (globalURL == "" && cnURL == "") || (globalURL != "" && cnURL != "")
}

func detectVPNCoreCNNetwork(ctx context.Context, httpClient vpnHTTPClient) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NZ_VPN_CORE_CN"))) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	for _, traceURL := range vpnCoreCNTraceURLs {
		traceCtx, cancel := context.WithTimeout(ctx, vpnCoreGeoCheckTimeout)
		req, err := http.NewRequestWithContext(traceCtx, http.MethodGet, traceURL, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "nezha-agent-vpn-core")
		resp, err := httpClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		cancel()
		if readErr != nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(line) == "loc=CN" {
				return true
			}
		}
	}
	return false
}

func vpnCoreAssetName(goos string, goarch string) string {
	if strings.TrimSpace(goos) == "" || strings.TrimSpace(goarch) == "" {
		return ""
	}
	name := "sing-box-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

func orderedVPNCoreBaseURLs(spec model.VPNCoreSpec, preferCN bool) []string {
	globalURL := strings.TrimSpace(spec.DownloadBaseURL)
	cnURL := strings.TrimSpace(spec.CNDownloadBaseURL)
	if globalURL == "" && cnURL == "" {
		globalURL = defaultVPNCoreDownloadBaseURL
		cnURL = defaultVPNCoreCNDownloadBaseURL
	}
	if preferCN {
		return compactVPNCoreURLs(cnURL, globalURL)
	}
	return compactVPNCoreURLs(globalURL, cnURL)
}

func orderedVPNCoreManifestURLs(spec model.VPNCoreSpec, baseURLs []string, preferCN bool) []string {
	globalURL := strings.TrimSpace(spec.ManifestURL)
	cnURL := strings.TrimSpace(spec.CNManifestURL)
	if globalURL != "" || cnURL != "" {
		if preferCN {
			return compactVPNCoreURLs(cnURL, globalURL)
		}
		return compactVPNCoreURLs(globalURL, cnURL)
	}

	manifestURLs := make([]string, 0, len(baseURLs))
	for _, baseURL := range baseURLs {
		manifestURL, err := joinVPNCoreAssetURL(baseURL, "manifest.json")
		if err == nil {
			manifestURLs = appendVPNCoreURL(manifestURLs, manifestURL)
		}
	}
	return manifestURLs
}

func compactVPNCoreURLs(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = appendVPNCoreURL(out, value)
	}
	return out
}

func appendVPNCoreURL(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendVPNCoreCandidate(candidates []vpnCoreDownloadCandidate, rawURL string, sha256Value string) []vpnCoreDownloadCandidate {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return candidates
	}
	for _, candidate := range candidates {
		if candidate.URL == rawURL {
			return candidates
		}
	}
	return append(candidates, vpnCoreDownloadCandidate{
		URL:    rawURL,
		SHA256: strings.TrimSpace(sha256Value),
	})
}

func joinVPNCoreAssetURL(baseURL string, asset string) (string, error) {
	baseURL = strings.TrimSpace(baseURL)
	asset = strings.TrimLeft(strings.TrimSpace(asset), "/")
	if baseURL == "" || asset == "" {
		return "", nil
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid core download base url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("core download base url must use http or https")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/" + asset
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func loadVPNCoreManifestAsset(ctx context.Context, manifestURLs []string, assetName string, httpClient vpnHTTPClient) (vpnCoreManifestAsset, error) {
	var lastErr error
	for _, manifestURL := range manifestURLs {
		asset, err := loadVPNCoreManifestAssetFromURL(ctx, manifestURL, assetName, httpClient)
		if err != nil {
			lastErr = err
			continue
		}
		return asset, nil
	}
	if lastErr != nil {
		return vpnCoreManifestAsset{}, lastErr
	}
	return vpnCoreManifestAsset{}, errors.New("no VPN core manifest URLs")
}

func loadVPNCoreManifestAssetFromURL(ctx context.Context, manifestURL string, assetName string, httpClient vpnHTTPClient) (vpnCoreManifestAsset, error) {
	resp, err := openVPNCoreDownload(ctx, manifestURL, httpClient)
	if err != nil {
		return vpnCoreManifestAsset{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return vpnCoreManifestAsset{}, fmt.Errorf("download VPN core manifest failed: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxVPNCoreManifestBytes))
	if err != nil {
		return vpnCoreManifestAsset{}, err
	}
	var manifest vpnCoreManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return vpnCoreManifestAsset{}, err
	}
	for _, asset := range manifest.Assets {
		if strings.EqualFold(strings.TrimSpace(asset.Asset), assetName) ||
			(strings.EqualFold(strings.TrimSpace(asset.OS), runtime.GOOS) && strings.EqualFold(strings.TrimSpace(asset.Arch), runtime.GOARCH)) {
			return asset, nil
		}
	}
	return vpnCoreManifestAsset{}, fmt.Errorf("VPN core manifest does not contain %s", assetName)
}

func downloadVPNCore(ctx context.Context, rawURL string, corePath string, httpClient vpnHTTPClient) error {
	resp, err := openVPNCoreDownload(ctx, rawURL, httpClient)
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

func openVPNCoreDownload(ctx context.Context, rawURL string, httpClient vpnHTTPClient) (*http.Response, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	currentURL := strings.TrimSpace(rawURL)
	for redirects := 0; ; redirects++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		if !isVPNCoreRedirect(resp.StatusCode) {
			return resp, nil
		}
		if redirects >= maxVPNCoreDownloadRedirects {
			_ = resp.Body.Close()
			return nil, errors.New("download VPN core exceeded redirect limit")
		}
		nextURL, err := resolveVPNCoreRedirectURL(currentURL, resp.Header.Get("Location"))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		currentURL = nextURL
	}
}

func isVPNCoreRedirect(statusCode int) bool {
	switch statusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func resolveVPNCoreRedirectURL(currentURL string, location string) (string, error) {
	location = strings.TrimSpace(location)
	if location == "" {
		return "", errors.New("download VPN core redirect missing location")
	}
	base, err := url.Parse(currentURL)
	if err != nil {
		return "", err
	}
	next, err := base.Parse(location)
	if err != nil {
		return "", err
	}
	if next.Scheme != "http" && next.Scheme != "https" {
		return "", errors.New("download VPN core redirect must use http or https")
	}
	return next.String(), nil
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
