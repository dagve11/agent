package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nezhahq/agent/pkg/util"
	pb "github.com/nezhahq/agent/proto"
)

type destroyAgentPlan struct {
	Command    string
	Args       []string
	InstallDir string
}

var scheduleAgentDestroyFunc = scheduleAgentDestroy

func agentServiceName(configPath string) string {
	name := filepath.Base(executablePath)
	if configPath != defaultConfigPath && configPath != "" {
		hex := util.MD5Sum(configPath)[:7]
		name = fmt.Sprintf("%s-%s", name, hex)
	}
	return name
}

func buildDestroyAgentPlan(execPath, configPath, defaultPath string) destroyAgentPlan {
	installDir := filepath.Dir(execPath)
	name := filepath.Base(execPath)
	if configPath != defaultPath && configPath != "" {
		hex := util.MD5Sum(configPath)[:7]
		name = fmt.Sprintf("%s-%s", name, hex)
	}

	if runtime.GOOS == "windows" {
		script := strings.Join([]string{
			"$ErrorActionPreference = 'SilentlyContinue'",
			"Start-Sleep -Seconds 2",
			fmt.Sprintf("sc.exe stop %s | Out-Null", powerShellSingleQuote(name)),
			"Start-Sleep -Seconds 2",
			fmt.Sprintf("sc.exe delete %s | Out-Null", powerShellSingleQuote(name)),
			"Start-Sleep -Seconds 1",
			fmt.Sprintf("Remove-Item -LiteralPath %s -Recurse -Force", powerShellSingleQuote(installDir)),
			"Remove-Item -LiteralPath 'C:/install.ps1' -Force",
		}, "; ")
		return destroyAgentPlan{
			Command:    "powershell.exe",
			Args:       []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", script},
			InstallDir: installDir,
		}
	}

	script := strings.Join([]string{
		"sleep 2",
		fmt.Sprintf("%s service -c %s stop >/dev/null 2>&1 || true", shellSingleQuote(execPath), shellSingleQuote(configPath)),
		fmt.Sprintf("%s service -c %s uninstall >/dev/null 2>&1 || true", shellSingleQuote(execPath), shellSingleQuote(configPath)),
		fmt.Sprintf("rm -rf %s", shellSingleQuote(installDir)),
		fmt.Sprintf("rmdir %s >/dev/null 2>&1 || true", shellSingleQuote(filepath.Dir(installDir))),
	}, "; ")
	return destroyAgentPlan{
		Command:    "/bin/sh",
		Args:       []string{"-c", script},
		InstallDir: installDir,
	}
}

func handleDestroyAgentTask(result *pb.TaskResult) {
	if err := scheduleAgentDestroyFunc(); err != nil {
		result.Data = err.Error()
		return
	}
	result.Successful = true
	result.Data = "agent self-removal scheduled"
}

func scheduleAgentDestroy() error {
	configPath := agentConfig.ConfigPath()
	if configPath == "" {
		configPath = defaultConfigPath
	}
	plan := buildDestroyAgentPlan(executablePath, configPath, defaultConfigPath)
	cmd := exec.Command(plan.Command, plan.Args...)
	if err := detachAgentDestroyCommand(cmd); err != nil {
		return err
	}
	go func() {
		time.Sleep(time.Second)
		os.Exit(0)
	}()
	return nil
}

func powerShellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(filepath.ToSlash(s), "'", "''") + "'"
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
