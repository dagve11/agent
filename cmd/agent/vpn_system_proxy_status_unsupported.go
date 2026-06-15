//go:build !windows

package main

import "errors"

func platformVPNSystemProxyApplied(string, string) (bool, string, error) {
	return false, "", errors.New("system proxy status inspection is not supported on this platform")
}
