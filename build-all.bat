@echo off
setlocal EnableExtensions

set "REPO_DIR=%~dp0"
set "REPO_DIR=%REPO_DIR:~0,-1%"

set /p VERSION=Enter VERSION:
if "%VERSION%"=="" (
    echo VERSION is required.
    exit /b 1
)

docker run --rm -v "%REPO_DIR%:/build" -w /build golang:1.26 sh -c "apt-get update -qq && apt-get install -y -qq zip gcc > /dev/null 2>&1 && VERSION=%VERSION% ./build.sh"

exit /b %errorlevel%
