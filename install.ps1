$ErrorActionPreference = "Stop"

$Repo = if ($env:NZ_AGENT_REPO) { $env:NZ_AGENT_REPO } else { "dagve11/agent" }
$InstallDir = if ($env:NZ_INSTALL_DIR) { $env:NZ_INSTALL_DIR } else { "C:\Program Files\agent" }
$AgentPath = Join-Path $InstallDir "agent.exe"
$ConfigPath = Join-Path $InstallDir "config.yml"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AgentArch {
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }

    switch ($arch.ToUpperInvariant()) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        "X86" { return "386" }
        default { throw "Unsupported Windows architecture: $arch" }
    }
}

function Quote-YamlString([string]$Value) {
    return "'" + ($Value -replace "'", "''") + "'"
}

function Get-RequiredEnv([string]$Name) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$Name is required."
    }
    return $value
}

function Get-ExistingAgentUuid {
    if (-not (Test-Path $ConfigPath)) {
        return $null
    }

    $match = Get-Content -Path $ConfigPath -ErrorAction SilentlyContinue |
        Select-String -Pattern "^\s*uuid:\s*['""]?([^'""]+)['""]?\s*$" |
        Select-Object -First 1

    if ($match) {
        return $match.Matches[0].Groups[1].Value
    }

    return $null
}

function Invoke-AgentService([string]$Action) {
    if (Test-Path $AgentPath) {
        try {
            & $AgentPath service $Action -c $ConfigPath | Out-Host
        } catch {
            Write-Host "Ignore service $Action failure: $($_.Exception.Message)"
        }
    }
}

function Start-AgentServiceIfNeeded {
    $serviceName = Split-Path -Leaf $AgentPath
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($service -and $service.State -eq "Running") {
        Write-Host "agent service already running."
        return
    }

    Invoke-AgentService "start"
}

if (-not (Test-Administrator)) {
    throw "Please run PowerShell as Administrator."
}

$server = Get-RequiredEnv "NZ_SERVER"
$clientSecret = Get-RequiredEnv "NZ_CLIENT_SECRET"
$tls = if ($env:NZ_TLS) { $env:NZ_TLS.ToLowerInvariant() } else { "false" }
if ($tls -ne "true" -and $tls -ne "false") {
    throw "NZ_TLS must be true or false."
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

$arch = Get-AgentArch
$assetUrl = "https://github.com/$Repo/releases/latest/download/agent_windows_$arch.zip"
$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("agent-install-" + [Guid]::NewGuid().ToString("N"))
$zipPath = Join-Path $tempDir "agent.zip"
$extractDir = Join-Path $tempDir "extract"

Write-Host "Downloading $assetUrl"
New-Item -ItemType Directory -Force -Path $tempDir, $extractDir | Out-Null
Invoke-WebRequest -Uri $assetUrl -OutFile $zipPath -UseBasicParsing
Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

$downloadedAgent = Get-ChildItem -Path $extractDir -Recurse -File -Filter "agent.exe" | Select-Object -First 1
if (-not $downloadedAgent) {
    throw "agent.exe was not found in release asset."
}

$existingUuid = Get-ExistingAgentUuid
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Invoke-AgentService "stop"
Invoke-AgentService "uninstall"
Copy-Item -Path $downloadedAgent.FullName -Destination $AgentPath -Force

$configLines = @(
    "server: $(Quote-YamlString $server)",
    "client_secret: $(Quote-YamlString $clientSecret)",
    "tls: $tls"
)

if ($env:NZ_UUID) {
    $configLines += "uuid: $(Quote-YamlString $env:NZ_UUID)"
} elseif ($existingUuid) {
    $configLines += "uuid: $(Quote-YamlString $existingUuid)"
}

Set-Content -Path $ConfigPath -Value $configLines -Encoding UTF8

& $AgentPath service install -c $ConfigPath
Start-AgentServiceIfNeeded

Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "agent installed and started."
