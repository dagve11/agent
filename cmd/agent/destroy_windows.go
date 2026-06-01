//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

func detachAgentDestroyCommand(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008,
	}
	return cmd.Start()
}
