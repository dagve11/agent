$ErrorActionPreference = "Stop"

$Repo = if ($env:NZ_AGENT_REPO) { $env:NZ_AGENT_REPO } else { "dagve11/agent" }
$GiteeRepo = if ($env:NZ_GITEE_REPO) { $env:NZ_GITEE_REPO } else { "AGZZY11/agent" }
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

function Test-ChinaNetwork {
    if ($env:CN) {
        return $env:CN.ToLowerInvariant() -eq "true"
    }

    $traceUrls = @(
        "https://blog.cloudflare.com/cdn-cgi/trace",
        "https://developers.cloudflare.com/cdn-cgi/trace",
        "https://1.0.0.1/cdn-cgi/trace"
    )

    foreach ($traceUrl in $traceUrls) {
        try {
            $resp = Invoke-WebRequest -Uri $traceUrl -UseBasicParsing -TimeoutSec 5
            if ($resp.Content -match "(?m)^loc=CN$") {
                return $true
            }
        } catch {
            continue
        }
    }

    return $false
}

function Add-DownloadUrl([System.Collections.Generic.List[string]]$Urls, [string]$Url) {
    if ([string]::IsNullOrWhiteSpace($Url)) {
        return
    }
    if (-not $Urls.Contains($Url)) {
        [void]$Urls.Add($Url)
    }
}

function Get-GiteeAssetUrl([string]$Asset) {
    if ([string]::IsNullOrWhiteSpace($GiteeRepo)) {
        return $null
    }

    try {
        $apiUrl = "https://gitee.com/api/v5/repos/$GiteeRepo/releases/latest"
        $release = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 10
        if ($release.tag_name) {
            return "https://gitee.com/$GiteeRepo/releases/download/$($release.tag_name)/$Asset"
        }
    } catch {
        return $null
    }

    return $null
}

function Get-AgentDownloadUrls([string]$Asset) {
    $urls = [System.Collections.Generic.List[string]]::new()
    $directUrl = "https://github.com/$Repo/releases/latest/download/$Asset"

    if (-not [string]::IsNullOrWhiteSpace($env:NZ_DOWNLOAD_BASE)) {
        Add-DownloadUrl $urls (($env:NZ_DOWNLOAD_BASE.TrimEnd("/")) + "/" + $Asset)
    }

    if (Test-ChinaNetwork) {
        Add-DownloadUrl $urls (Get-GiteeAssetUrl $Asset)
    }

    if (-not [string]::IsNullOrWhiteSpace($env:NZ_GITHUB_PROXY)) {
        Add-DownloadUrl $urls (($env:NZ_GITHUB_PROXY.TrimEnd("/")) + "/" + $directUrl)
    }

    Add-DownloadUrl $urls $directUrl
    return $urls
}

function Invoke-DownloadWithFallback([string]$Asset, [string]$OutFile) {
    $urls = Get-AgentDownloadUrls $Asset
    foreach ($url in $urls) {
        try {
            Write-Host "Downloading $url"
            Invoke-WebRequest -Uri $url -OutFile $OutFile -UseBasicParsing -TimeoutSec 60
            return
        } catch {
            Remove-Item -Path $OutFile -Force -ErrorAction SilentlyContinue
            Write-Host "Download failed: $($_.Exception.Message)"
        }
    }

    throw "Download agent release failed. You can set NZ_DOWNLOAD_BASE, NZ_GITHUB_PROXY, or NZ_GITEE_REPO to use a mirror."
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
$assetName = "agent_windows_$arch.zip"
$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("agent-install-" + [Guid]::NewGuid().ToString("N"))
$zipPath = Join-Path $tempDir "agent.zip"
$extractDir = Join-Path $tempDir "extract"

New-Item -ItemType Directory -Force -Path $tempDir, $extractDir | Out-Null
Invoke-DownloadWithFallback $assetName $zipPath
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
