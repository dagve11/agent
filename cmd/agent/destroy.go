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
	Command       string
	Args          []string
	InstallDir    string
	WorkDir       string
	ScriptPath    string
	ScriptContent string
	LogPath       string
}

var scheduleAgentDestroyFunc = scheduleAgentDestroy

func shouldSelfDestroyAfterReportError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "server UUID has been deleted")
}

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
		pid := os.Getpid()
		scriptPath := filepath.Join(workDir, fmt.Sprintf("agent-destroy-%d.ps1", pid))
		logPath := filepath.Join(workDir, fmt.Sprintf("agent-destroy-%d.log", pid))
		script := strings.Join([]string{
			"$ErrorActionPreference = 'Continue'",
			fmt.Sprintf("$serviceName = %s", powerShellSingleQuote(name)),
			fmt.Sprintf("$installDir = %s", powerShellSingleQuote(installDir)),
			fmt.Sprintf("$agentPid = %d", pid),
			fmt.Sprintf("$logPath = %s", powerShellSingleQuote(logPath)),
			"function Write-Log { param([string]$Message) Add-Content -LiteralPath $logPath -Value \"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message\" }",
			"function Run-Step { param([string]$Name, [scriptblock]$Block) Write-Log $Name; try { & $Block 2>&1 | ForEach-Object { Write-Log $_.ToString() } } catch { Write-Log $_.Exception.Message } }",
			fmt.Sprintf("Set-Location %s", powerShellSingleQuote(workDir)),
			"Write-Log 'destroy start'",
			"$svc = Get-CimInstance Win32_Service -Filter \"Name='$serviceName'\"",
			"if ($svc) { Run-Step 'clear service restart action' { sc.exe failure $serviceName reset= 0 actions= \"\"; sc.exe failureflag $serviceName 0 } }",
			"Start-Sleep -Seconds 2",
			"$svc = Get-CimInstance Win32_Service -Filter \"Name='$serviceName'\"",
			"if ($svc -and $svc.State -ne 'Stopped') { Run-Step 'stop service' { sc.exe stop $serviceName } }",
			"for ($i = 0; $i -lt 30; $i++) { $svc = Get-CimInstance Win32_Service -Filter \"Name='$serviceName'\"; if (-not $svc -or $svc.State -eq 'Stopped') { break }; Start-Sleep -Milliseconds 500 }",
			"$svc = Get-CimInstance Win32_Service -Filter \"Name='$serviceName'\"",
			"if ($svc -and $svc.ProcessId -gt 0) { Run-Step 'kill service process' { Stop-Process -Id $svc.ProcessId -Force; taskkill.exe /PID $svc.ProcessId /F } }",
			"if ($agentPid -gt 0 -and (Get-Process -Id $agentPid -ErrorAction SilentlyContinue)) { Run-Step 'kill agent process' { Stop-Process -Id $agentPid -Force; taskkill.exe /PID $agentPid /F } }",
			"Start-Sleep -Milliseconds 500",
			"Run-Step 'delete service' { sc.exe delete $serviceName }",
			"for ($i = 0; $i -lt 60; $i++) { try { Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction Stop } catch { Write-Log \"remove install dir failed: $($_.Exception.Message)\" }; if (-not (Test-Path -LiteralPath $installDir)) { break }; Start-Sleep -Milliseconds 500 }",
			"Run-Step 'remove installer' { Remove-Item -LiteralPath 'C:/install.ps1' -Force }",
			"Write-Log \"destroy finished; install dir exists=$(Test-Path -LiteralPath $installDir)\"",
		}, "\r\n")
		return destroyAgentPlan{
			Command:       "powershell.exe",
			Args:          []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", scriptPath},
			InstallDir:    installDir,
			WorkDir:       workDir,
			ScriptPath:    scriptPath,
			ScriptContent: script,
			LogPath:       logPath,
		}
	}

	script := strings.Join([]string{
		"#!/bin/sh",
		"set +e",
		fmt.Sprintf("log=%s", shellSingleQuote(filepath.Join(os.TempDir(), fmt.Sprintf("agent-destroy-%d.log", os.Getpid())))),
		`run_step() { name="$1"; shift; printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$name" >> "$log"; "$@" >> "$log" 2>&1; }`,
		fmt.Sprintf("printf 'destroy start %s pid=%d\\n' \"$(date '+%%Y-%%m-%%d %%H:%%M:%%S')\" >> \"$log\"", runtime.GOOS, os.Getpid()),
		"sleep 2",
		fmt.Sprintf("run_step 'stop service' %s service -c %s stop || true", shellSingleQuote(execPath), shellSingleQuote(configPath)),
		fmt.Sprintf("run_step 'uninstall service' %s service -c %s uninstall || true", shellSingleQuote(execPath), shellSingleQuote(configPath)),
		fmt.Sprintf("run_step 'remove install dir' rm -rf %s", shellSingleQuote(installDir)),
		fmt.Sprintf("run_step 'remove base dir if empty' rmdir %s || true", shellSingleQuote(filepath.Dir(installDir))),
		fmt.Sprintf("printf 'destroy finished install_dir_exists=%%s\\n' \"$(test -e %s && echo true || echo false)\" >> \"$log\"", shellSingleQuote(installDir)),
	}, "\n")
	workDir := os.TempDir()
	scriptPath := filepath.Join(workDir, fmt.Sprintf("agent-destroy-%d.sh", os.Getpid()))
	logPath := filepath.Join(workDir, fmt.Sprintf("agent-destroy-%d.log", os.Getpid()))
	launcher := strings.Join([]string{
		"if command -v systemd-run >/dev/null 2>&1; then",
		fmt.Sprintf("  systemd-run --unit=agent-destroy-%d --property=KillMode=process /bin/sh %s", os.Getpid(), shellSingleQuote(scriptPath)),
		"  status=$?",
		"else",
		"  status=127",
		"fi",
		"if [ \"$status\" -ne 0 ]; then",
		fmt.Sprintf("  nohup /bin/sh %s >/dev/null 2>&1 &", shellSingleQuote(scriptPath)),
		"fi",
	}, "\n")
	return destroyAgentPlan{
		Command:       "/bin/sh",
		Args:          []string{"-c", launcher},
		InstallDir:    installDir,
		WorkDir:       workDir,
		ScriptPath:    scriptPath,
		ScriptContent: script,
		LogPath:       logPath,
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
	if plan.ScriptPath != "" {
		if err := os.WriteFile(plan.ScriptPath, []byte(plan.ScriptContent), 0600); err != nil {
			return err
		}
	}
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
