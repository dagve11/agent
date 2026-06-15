//go:build !windows && !darwin && !linux

package main

import "errors"

func platformVPNSystemProxyStatus(string, string) (vpnSystemProxyInspection, error) {
	return vpnSystemProxyInspection{}, errors.New("system proxy status inspection is not supported on this platform")
}
