package main

import (
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
		if !strings.Contains(commandLine, "$serviceName = 'agent.exe'") {
			t.Fatalf("windows destroy plan must store the service name, got: %s", commandLine)
		}
		if plan.WorkDir == "" {
			t.Fatal("windows destroy plan must run the helper outside the install directory")
		}
		if strings.EqualFold(filepath.Clean(plan.WorkDir), filepath.Clean(plan.InstallDir)) {
			t.Fatalf("windows destroy helper must not inherit the install directory as its working directory: %s", plan.WorkDir)
		}
		setLocation := "Set-Location " + powerShellSingleQuote(plan.WorkDir)
		if !strings.Contains(commandLine, setLocation) {
			t.Fatalf("windows destroy script must leave the install directory before removal, got: %s", commandLine)
		}
		if strings.Index(commandLine, setLocation) > strings.Index(commandLine, "Remove-Item -LiteralPath $installDir -Recurse -Force") {
			t.Fatalf("windows destroy script must change directory before removing the install directory, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "sc.exe failure $serviceName reset= 0 actions= \"\"") {
			t.Fatalf("windows destroy plan must disable service failure restart before killing the process, got: %s", commandLine)
		}
		if strings.Contains(commandLine, "Start-Sleep -Seconds 2") {
			t.Fatalf("windows destroy plan must not rely on a fixed wait before stopping the service, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "$agentPid = ") {
			t.Fatalf("windows destroy script must know the current agent pid so the helper owns process shutdown, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "Stop-Process -Id $agentPid -Force") {
			t.Fatalf("windows destroy script must stop the current agent process itself instead of relying on a racing os.Exit, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "sc.exe stop $serviceName") {
			t.Fatalf("windows destroy plan must stop the installed service, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "Stop-Process -Id $svc.ProcessId -Force") {
			t.Fatalf("windows destroy plan must force-kill a service process that ignores stop, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "taskkill.exe /PID $svc.ProcessId /F") {
			t.Fatalf("windows destroy plan must have taskkill fallback for stubborn service processes, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "sc.exe delete $serviceName") {
			t.Fatalf("windows destroy plan must delete the installed service, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "Remove-Item -LiteralPath $installDir -Recurse -Force") {
			t.Fatalf("windows destroy plan must remove the install directory, got: %s", commandLine)
		}
	} else {
		if !strings.Contains(commandLine, "service -c 'C:/Program Files/agent/config.yml' stop") {
			t.Fatalf("unix destroy plan must stop the installed service via the agent binary, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "service -c 'C:/Program Files/agent/config.yml' uninstall") {
			t.Fatalf("unix destroy plan must uninstall the installed service via the agent binary, got: %s", commandLine)
		}
		if !strings.Contains(commandLine, "rm -rf 'C:/Program Files/agent'") {
			t.Fatalf("unix destroy plan must remove the install directory, got: %s", commandLine)
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
