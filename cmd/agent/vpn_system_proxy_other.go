//go:build !windows && !darwin && !linux

package main

func newPlatformVPNSystemProxyManager() vpnSystemProxyManager {
	return unsupportedVPNSystemProxyManager{}
}
