package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func runVPNTunCommandOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func runVPNTunCommand(command vpnTunCommand) error {
	if strings.TrimSpace(command.Name) == "" {
		return nil
	}
	_, err := runVPNTunCommandOutput(command.Name, command.Args...)
	return err
}
