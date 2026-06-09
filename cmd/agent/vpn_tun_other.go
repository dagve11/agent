//go:build !windows

package main

func isElevatedRuntime() bool {
	return false
}
