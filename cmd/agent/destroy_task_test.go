package main

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestDestroyAgentTaskTypeStaysInSyncWithDashboard(t *testing.T) {
	if model.TaskTypeDestroyAgent != 21 {
		t.Fatalf("TaskTypeDestroyAgent must stay 21 so dashboard and agent agree, got %d", model.TaskTypeDestroyAgent)
	}
}

func TestBuildDestroyAgentPlanRemovesServiceAndInstallDirectory(t *testing.T) {
	plan := buildDestroyAgentPlan(
		"C:/Program Files/agent/agent.exe",
		"C:/Program Files/agent/config.yml",
		"C:/Program Files/agent/config.yml",
	)

	if plan.Command == "" {
		t.Fatal("destroy plan must have a command")
	}
	if plan.InstallDir == "" {
		t.Fatal("destroy plan must identify the install directory")
	}

	commandLine := strings.Join(append([]string{plan.Command}, plan.Args...), " ")
	if runtime.GOOS == "windows" {
		if plan.ScriptPath == "" || !strings.HasSuffix(strings.ToLower(plan.ScriptPath), ".ps1") {
			t.Fatalf("windows destroy plan must write a ps1 helper, got: %s", plan.ScriptPath)
		}
		if plan.LogPath == "" || !strings.HasSuffix(strings.ToLower(plan.LogPath), ".log") {
			t.Fatalf("windows destroy plan must write a log file, got: %s", plan.LogPath)
		}
		if !strings.Contains(commandLine, "-File "+plan.ScriptPath) {
			t.Fatalf("windows destroy plan must execute the ps1 helper via -File, got: %s", commandLine)
		}
		if !strings.Contains(plan.ScriptContent, "$serviceName = 'agent.exe'") {
			t.Fatalf("windows destroy script must store the service name, got: %s", plan.ScriptContent)
		}
		if plan.WorkDir == "" {
			t.Fatal("windows destroy plan must run the helper outside the install directory")
		}
		if strings.EqualFold(filepath.Clean(plan.WorkDir), filepath.Clean(plan.InstallDir)) {
			t.Fatalf("windows destroy helper must not inherit the install directory as its working directory: %s", plan.WorkDir)
		}
		setLocation := "Set-Location " + powerShellSingleQuote(plan.WorkDir)
		if !strings.Contains(plan.ScriptContent, setLocation) {
			t.Fatalf("windows destroy script must leave the install directory before removal, got: %s", plan.ScriptContent)
		}
		if strings.Index(plan.ScriptContent, setLocation) > strings.Index(plan.ScriptContent, "Remove-Item -LiteralPath $installDir -Recurse -Force") {
			t.Fatalf("windows destroy script must change directory before removing the install directory, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "sc.exe failure $serviceName reset= 0 actions= \"\"") {
			t.Fatalf("windows destroy plan must disable service failure restart before killing the process, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "Write-Log") {
			t.Fatalf("windows destroy script must log each step for debugging, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "$agentPid = ") {
			t.Fatalf("windows destroy script must know the current agent pid so the helper owns process shutdown, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "Stop-Process -Id $agentPid -Force") {
			t.Fatalf("windows destroy script must stop the current agent process itself instead of relying on a racing os.Exit, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "sc.exe stop $serviceName") {
			t.Fatalf("windows destroy plan must stop the installed service, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "Stop-Process -Id $svc.ProcessId -Force") {
			t.Fatalf("windows destroy plan must force-kill a service process that ignores stop, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "taskkill.exe /PID $svc.ProcessId /F") {
			t.Fatalf("windows destroy plan must have taskkill fallback for stubborn service processes, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "sc.exe delete $serviceName") {
			t.Fatalf("windows destroy plan must delete the installed service, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "Remove-Item -LiteralPath $installDir -Recurse -Force") {
			t.Fatalf("windows destroy plan must remove the install directory, got: %s", plan.ScriptContent)
		}
	} else {
		if plan.ScriptPath == "" || !strings.HasSuffix(strings.ToLower(plan.ScriptPath), ".sh") {
			t.Fatalf("unix destroy plan must write a shell helper, got: %s", plan.ScriptPath)
		}
		if plan.LogPath == "" || !strings.HasSuffix(strings.ToLower(plan.LogPath), ".log") {
			t.Fatalf("unix destroy plan must write a log file, got: %s", plan.LogPath)
		}
		if plan.WorkDir == "" {
			t.Fatal("unix destroy plan must run the helper outside the install directory")
		}
		if strings.EqualFold(filepath.Clean(plan.WorkDir), filepath.Clean(plan.InstallDir)) {
			t.Fatalf("unix destroy helper must not inherit the install directory as its working directory: %s", plan.WorkDir)
		}
		if !strings.Contains(commandLine, "systemd-run") {
			t.Fatalf("unix destroy plan must prefer systemd-run so cleanup survives service stop, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "KillMode=process") {
			t.Fatalf("unix destroy plan must keep the cleanup process outside the original service cgroup cleanup, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "nohup") {
			t.Fatalf("unix destroy plan must keep a nohup fallback for non-systemd hosts, got: %s", commandLine)
		}
		if !strings.Contains(plan.ScriptContent, "service -c 'C:/Program Files/agent/config.yml' stop") {
			t.Fatalf("unix destroy plan must stop the installed service via the agent binary, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "service -c 'C:/Program Files/agent/config.yml' uninstall") {
			t.Fatalf("unix destroy plan must uninstall the installed service via the agent binary, got: %s", plan.ScriptContent)
		}
		if !strings.Contains(plan.ScriptContent, "rm -rf 'C:/Program Files/agent'") {
			t.Fatalf("unix destroy plan must remove the install directory, got: %s", plan.ScriptContent)
		}
	}
}

func TestDoTaskHandlesDestroyAgentTask(t *testing.T) {
	previous := scheduleAgentDestroyFunc
	defer func() {
		scheduleAgentDestroyFunc = previous
	}()
	called := false
	scheduleAgentDestroyFunc = func() error {
		called = true
		return nil
	}

	result := doTask(&pb.Task{Id: 77, Type: model.TaskTypeDestroyAgent})
	if result == nil {
		t.Fatal("destroy task must return a result before the agent exits")
	}
	if result.Id != 77 || result.Type != model.TaskTypeDestroyAgent {
		t.Fatalf("destroy task result must echo id/type, got id=%d type=%d", result.Id, result.Type)
	}
	if !result.Successful {
		t.Fatalf("destroy task must report successful scheduling, got data=%q", result.Data)
	}
	if !called {
		t.Fatal("destroy task must schedule self-removal")
	}
}

func TestDeletedUUIDReportErrorTriggersSelfDestroy(t *testing.T) {
	if !shouldSelfDestroyAfterReportError(errors.New("rpc error: code = Unauthenticated desc = server UUID has been deleted")) {
		t.Fatal("deleted UUID report error must trigger local self-removal fallback")
	}
	if shouldSelfDestroyAfterReportError(errors.New("rpc error: code = Unavailable desc = connection refused")) {
		t.Fatal("ordinary connection errors must not trigger local self-removal")
	}
	if shouldSelfDestroyAfterReportError(nil) {
		t.Fatal("nil error must not trigger local self-removal")
	}
}
