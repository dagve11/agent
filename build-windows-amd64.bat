@echo off
setlocal

set "VERSION=1.0.4"
set "REPO_DIR=%~dp0"
set "REPO_DIR=%REPO_DIR:~0,-1%"

docker run --rm -v "%REPO_DIR%:/build" -w /build golang:1.26 sh -c "apt-get update -qq && apt-get install -y -qq zip gcc-mingw-w64-x86-64 > /dev/null 2>&1 && rm -rf dist/agent_windows_amd64 && mkdir -p dist/agent_windows_amd64 && CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -trimpath -ldflags '-s -w -X github.com/nezhahq/agent/pkg/monitor.Version=%VERSION% -X main.arch=amd64' -o dist/agent_windows_amd64/agent.exe ./cmd/agent && cd dist/agent_windows_amd64 && zip -q -9 -r ../agent_windows_amd64.zip agent.exe"

if errorlevel 1 exit /b %errorlevel%

echo Built dist\agent_windows_amd64.zip
