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
	WorkDir    string
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
		workDir := os.TempDir()
		script := strings.Join([]string{
			"$ErrorActionPreference = 'SilentlyContinue'",
			fmt.Sprintf("$serviceName = %s", powerShellSingleQuote(name)),
			fmt.Sprintf("$installDir = %s", powerShellSingleQuote(installDir)),
			fmt.Sprintf("$agentPid = %d", os.Getpid()),
			fmt.Sprintf("Set-Location %s", powerShellSingleQuote(workDir)),
			"$svc = Get-CimInstance Win32_Service -Filter \"Name='$serviceName'\"",
			"if ($svc) { sc.exe failure $serviceName reset= 0 actions= \"\" | Out-Null; sc.exe failureflag $serviceName 0 | Out-Null }",
			"if ($svc -and $svc.State -ne 'Stopped') { sc.exe stop $serviceName | Out-Null }",
			"for ($i = 0; $i -lt 20; $i++) { $svc = Get-CimInstance Win32_Service -Filter \"Name='$serviceName'\"; if (-not $svc -or $svc.State -eq 'Stopped') { break }; Start-Sleep -Milliseconds 500 }",
			"$svc = Get-CimInstance Win32_Service -Filter \"Name='$serviceName'\"",
			"if ($svc -and $svc.ProcessId -gt 0) { Stop-Process -Id $svc.ProcessId -Force; taskkill.exe /PID $svc.ProcessId /F | Out-Null }",
			"if ($agentPid -gt 0 -and (Get-Process -Id $agentPid -ErrorAction SilentlyContinue)) { Stop-Process -Id $agentPid -Force; taskkill.exe /PID $agentPid /F | Out-Null }",
			"Start-Sleep -Seconds 1",
			"sc.exe delete $serviceName | Out-Null",
			"for ($i = 0; $i -lt 40; $i++) { Remove-Item -LiteralPath $installDir -Recurse -Force; if (-not (Test-Path -LiteralPath $installDir)) { break }; Start-Sleep -Milliseconds 500 }",
			"Remove-Item -LiteralPath 'C:/install.ps1' -Force",
		}, "; ")
		return destroyAgentPlan{
			Command:    "powershell.exe",
			Args:       []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", script},
			InstallDir: installDir,
			WorkDir:    workDir,
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
	if plan.WorkDir != "" {
		cmd.Dir = plan.WorkDir
	}
	if err := detachAgentDestroyCommand(cmd); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		go func() {
			time.Sleep(time.Second)
			os.Exit(0)
		}()
	}
	return nil
}

func powerShellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(filepath.ToSlash(s), "'", "''") + "'"
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
