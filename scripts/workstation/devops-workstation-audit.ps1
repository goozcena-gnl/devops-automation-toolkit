# SPDX-License-Identifier: MIT
<#+
.SYNOPSIS
Audits a Windows 11 / PowerShell / WSL DevOps workstation without modifying it.
.DESCRIPTION
Discovers required tools, executable conflicts, PATH defects, Git and SSH hygiene,
WSL integration, Docker connectivity, Kubernetes contexts, and optional CLI
authentication status. Sensitive command output is never included in the report.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "workstation-doctor-report.json",

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 10,

    [Parameter()]
    [string[]]$RequiredTools = @(
        "git", "ssh", "docker", "wsl", "kubectl", "terraform", "tofu",
        "helm", "gh", "az", "aws"
    ),

    [Parameter()]
    [switch]$CheckAuthentication,

    [Parameter()]
    [ValidateSet("info", "low", "medium", "high", "critical")]
    [string]$SeverityThreshold = "high",

    [Parameter()]
    [switch]$FailOnFindings
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$commandTimeoutSeconds = $TimeoutSeconds

$startedAt = [DateTime]::UtcNow
$findings = [System.Collections.Generic.List[object]]::new()
$partial = $false
$severityRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }

function Get-StableFingerprint {
    param([Parameter(Mandatory)][string]$Value)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return "sha256:" + [Convert]::ToHexString($hash).ToLowerInvariant()
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet("info", "low", "medium", "high", "critical")][string]$Severity,
        [Parameter(Mandatory)][ValidateSet("low", "medium", "high")][string]$Confidence,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Recommendation,
        [Parameter(Mandatory)][string]$ResourceType,
        [Parameter(Mandatory)][string]$ResourceName,
        [Parameter(Mandatory)][string]$Summary
    )
    $fingerprint = Get-StableFingerprint "$Id`u{001f}$ResourceType`u{001f}$ResourceName`u{001f}$Title"
    $findings.Add([ordered]@{
        id = $Id
        tool = "workstation-doctor"
        category = "workstation"
        severity = $Severity
        confidence = $Confidence
        title = $Title
        description = "Read-only workstation inspection identified a configuration or readiness issue."
        recommendation = $Recommendation
        fingerprint = $fingerprint
        resource = [ordered]@{ type = $ResourceType; name = $ResourceName }
        evidence = [ordered]@{ summary = $Summary }
        references = @()
        suppressed = $false
    }) | Out-Null
}

function Invoke-SafeProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string[]]$Arguments = @()
    )
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -NoNewWindow -PassThru `
            -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
        if (-not $process.WaitForExit($commandTimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch { Write-Verbose "Unable to terminate timed-out process: $($_.Exception.Message)" }
            return [ordered]@{ ExitCode = 124; Stdout = ""; Stderr = "command timed out"; TimedOut = $true }
        }
        return [ordered]@{
            ExitCode = $process.ExitCode
            Stdout = ([System.IO.File]::ReadAllText($stdoutFile) | Select-Object -First 1)
            Stderr = ([System.IO.File]::ReadAllText($stderrFile) | Select-Object -First 1)
            TimedOut = $false
        }
    }
    catch {
        return [ordered]@{ ExitCode = 127; Stdout = ""; Stderr = $_.Exception.Message; TimedOut = $false }
    }
    finally {
        Remove-Item -LiteralPath $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-ToolVersion {
    param([Parameter(Mandatory)][string]$Tool)
    $versionArguments = switch ($Tool) {
        "git" { @("--version") }
        "ssh" { @("-V") }
        "docker" { @("--version") }
        "wsl" { @("--version") }
        "kubectl" { @("version", "--client", "--output=json") }
        "terraform" { @("version", "-json") }
        "tofu" { @("version", "-json") }
        "helm" { @("version", "--short") }
        "gh" { @("--version") }
        "az" { @("version") }
        "aws" { @("--version") }
        default { @("--version") }
    }
    $result = Invoke-SafeProcess -FilePath $Tool -Arguments $versionArguments
    if ($result.TimedOut) { return "timeout" }
    $value = if ($result.Stdout) { $result.Stdout } else { $result.Stderr }
    if (-not $value) { return $null }
    $firstLine = ($value -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if ($null -eq $firstLine) { return $null }
    return $firstLine.Trim().Substring(0, [Math]::Min(200, $firstLine.Trim().Length))
}

$toolInventory = @()
foreach ($toolName in $RequiredTools) {
    $commands = @(Get-Command -Name $toolName -All -ErrorAction SilentlyContinue)
    $available = $commands.Count -gt 0
    $sources = @($commands | ForEach-Object { $_.Source } | Where-Object { $_ } | Select-Object -Unique)
    $version = if ($available) { Get-ToolVersion -Tool $toolName } else { $null }
    $toolInventory += [ordered]@{
        name = $toolName
        available = $available
        sources = $sources
        version = $version
    }
    if (-not $available) {
        Add-Finding -Id "WORKSTATION-TOOL-MISSING" -Severity "medium" -Confidence "high" `
            -Title "Required tool '$toolName' is unavailable" `
            -Recommendation "Install the approved version and verify that its directory precedes conflicting entries in PATH." `
            -ResourceType "Executable" -ResourceName $toolName -Summary "Get-Command returned no executable."
    }
    elseif ($sources.Count -gt 1) {
        Add-Finding -Id "WORKSTATION-TOOL-DUPLICATE" -Severity "low" -Confidence "high" `
            -Title "Multiple '$toolName' executables are discoverable" `
            -Recommendation "Remove obsolete installations or reorder PATH so automation resolves a single intended executable." `
            -ResourceType "Executable" -ResourceName $toolName -Summary "$($sources.Count) unique executable paths were found."
    }
}

$pathEntries = @($env:PATH -split [System.IO.Path]::PathSeparator | Where-Object { $_ })
$normalizedPathEntries = @($pathEntries | ForEach-Object { $_.Trim().TrimEnd('\').ToLowerInvariant() })
$duplicates = @($normalizedPathEntries | Group-Object | Where-Object { $_.Count -gt 1 })
foreach ($duplicate in $duplicates) {
    Add-Finding -Id "WORKSTATION-PATH-DUPLICATE" -Severity "low" -Confidence "high" `
        -Title "PATH contains a duplicate directory" `
        -Recommendation "Remove duplicate PATH entries to make executable resolution deterministic." `
        -ResourceType "EnvironmentVariable" -ResourceName "PATH" -Summary "A normalized PATH entry occurs $($duplicate.Count) times."
}
$missingPathEntries = @()
$inaccessiblePathEntries = 0
foreach ($pathEntry in $pathEntries) {
    try {
        if (-not (Test-Path -LiteralPath $pathEntry -PathType Container -ErrorAction Stop)) {
            $missingPathEntries += $pathEntry
        }
    }
    catch {
        $inaccessiblePathEntries++
        $partial = $true
    }
}
if ($missingPathEntries.Count -gt 0) {
    Add-Finding -Id "WORKSTATION-PATH-MISSING" -Severity "low" -Confidence "high" `
        -Title "PATH references directories that do not exist" `
        -Recommendation "Remove stale PATH entries after confirming no application still requires them." `
        -ResourceType "EnvironmentVariable" -ResourceName "PATH" -Summary "$($missingPathEntries.Count) nonexistent directories were detected."
}
if ($inaccessiblePathEntries -gt 0) {
    Add-Finding -Id "WORKSTATION-PATH-INACCESSIBLE" -Severity "low" -Confidence "high" `
        -Title "Some PATH directories could not be inspected" `
        -Recommendation "Review directory permissions and remove entries that should not be visible to this account." `
        -ResourceType "EnvironmentVariable" -ResourceName "PATH" -Summary "$inaccessiblePathEntries PATH entries returned an access error; their values were not recorded."
}

$gitMetadata = [ordered]@{ user_name_configured = $false; user_email_configured = $false; credential_helper = $null }
if (Get-Command -Name git -ErrorAction SilentlyContinue) {
    $gitName = Invoke-SafeProcess -FilePath "git" -Arguments @("config", "--global", "--get", "user.name")
    $gitEmail = Invoke-SafeProcess -FilePath "git" -Arguments @("config", "--global", "--get", "user.email")
    $gitHelper = Invoke-SafeProcess -FilePath "git" -Arguments @("config", "--global", "--get", "credential.helper")
    $gitMetadata.user_name_configured = $gitName.ExitCode -eq 0 -and [bool]$gitName.Stdout.Trim()
    $gitMetadata.user_email_configured = $gitEmail.ExitCode -eq 0 -and [bool]$gitEmail.Stdout.Trim()
    $gitMetadata.credential_helper = if ($gitHelper.ExitCode -eq 0) { $gitHelper.Stdout.Trim() } else { $null }
    if (-not $gitMetadata.user_name_configured -or -not $gitMetadata.user_email_configured) {
        Add-Finding -Id "WORKSTATION-GIT-IDENTITY" -Severity "low" -Confidence "high" `
            -Title "Global Git author identity is incomplete" `
            -Recommendation "Configure the intended user.name and user.email, or use repository-scoped identities where appropriate." `
            -ResourceType "GitConfiguration" -ResourceName "global" -Summary "Git user.name or user.email is absent."
    }
    if ($gitMetadata.credential_helper -eq "store") {
        Add-Finding -Id "WORKSTATION-GIT-CREDENTIAL-STORE" -Severity "high" -Confidence "high" `
            -Title "Git credential.helper uses plaintext store" `
            -Recommendation "Use Git Credential Manager, Windows Credential Manager, SSH, or another encrypted credential helper." `
            -ResourceType "GitConfiguration" -ResourceName "credential.helper" -Summary "The configured helper is 'store'."
    }
}

$sshMetadata = [ordered]@{ directory_exists = $false; private_key_files = 0; broadly_accessible_keys = 0 }
$sshDirectory = Join-Path $HOME ".ssh"
if (Test-Path -LiteralPath $sshDirectory -PathType Container) {
    $sshMetadata.directory_exists = $true
    $privateKeys = @(Get-ChildItem -LiteralPath $sshDirectory -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^(id_|.*\.pem$)' -and $_.Name -notmatch '\.pub$'
    })
    $sshMetadata.private_key_files = $privateKeys.Count
    foreach ($key in $privateKeys) {
        try {
            $acl = Get-Acl -LiteralPath $key.FullName
            $broadRules = @($acl.Access | Where-Object {
                $_.IdentityReference.Value -match '(Everyone|BUILTIN\\Users|Authenticated Users)' -and
                $_.AccessControlType -eq 'Allow' -and
                $_.FileSystemRights.ToString() -match '(Read|FullControl|Modify)'
            })
            if ($broadRules.Count -gt 0) {
                $sshMetadata.broadly_accessible_keys++
                Add-Finding -Id "WORKSTATION-SSH-KEY-PERMISSIONS" -Severity "high" -Confidence "medium" `
                    -Title "SSH private key may be readable by a broad Windows group" `
                    -Recommendation "Restrict the key ACL to the current user and required system principals, then verify SSH still works." `
                    -ResourceType "File" -ResourceName $key.Name -Summary "A broad Allow ACL was found; key contents were not read."
            }
        }
        catch { $partial = $true }
    }
}

$wslMetadata = [ordered]@{ available = $false; distributions = @(); default_version = $null }
if (Get-Command -Name wsl -ErrorAction SilentlyContinue) {
    $wslMetadata.available = $true
    $wslList = Invoke-SafeProcess -FilePath "wsl.exe" -Arguments @("--list", "--quiet")
    if ($wslList.TimedOut) { $partial = $true }
    elseif ($wslList.ExitCode -eq 0) {
        $wslMetadata.distributions = @($wslList.Stdout -split "`r?`n" | ForEach-Object { ([regex]::Replace($_, "\x00", "")).Trim() } | Where-Object { $_ })
    }
    else { $partial = $true }
    if ($wslMetadata.distributions.Count -eq 0) {
        Add-Finding -Id "WORKSTATION-WSL-NO-DISTRO" -Severity "low" -Confidence "medium" `
            -Title "WSL is available but no distribution was discovered" `
            -Recommendation "Install or repair an approved WSL 2 distribution if Linux tooling is expected on this workstation." `
            -ResourceType "WSL" -ResourceName "local" -Summary "wsl --list --quiet returned no distribution."
    }
}

$dockerMetadata = [ordered]@{ cli_available = $false; daemon_reachable = $false }
if (Get-Command -Name docker -ErrorAction SilentlyContinue) {
    $dockerMetadata.cli_available = $true
    $dockerInfo = Invoke-SafeProcess -FilePath "docker" -Arguments @("info", "--format", "{{json .ServerVersion}}")
    $dockerMetadata.daemon_reachable = $dockerInfo.ExitCode -eq 0
    if ($dockerInfo.TimedOut) { $partial = $true }
    elseif (-not $dockerMetadata.daemon_reachable) {
        Add-Finding -Id "WORKSTATION-DOCKER-UNREACHABLE" -Severity "medium" -Confidence "high" `
            -Title "Docker CLI cannot reach the container engine" `
            -Recommendation "Start or repair Docker Desktop or the selected container engine and verify the active Docker context." `
            -ResourceType "ContainerRuntime" -ResourceName "docker" -Summary "docker info returned a nonzero exit code."
    }
}

$kubernetesMetadata = [ordered]@{ contexts = @(); current_context = $null }
if (Get-Command -Name kubectl -ErrorAction SilentlyContinue) {
    $contexts = Invoke-SafeProcess -FilePath "kubectl" -Arguments @("config", "get-contexts", "-o", "name")
    $current = Invoke-SafeProcess -FilePath "kubectl" -Arguments @("config", "current-context")
    if ($contexts.ExitCode -eq 0) {
        $kubernetesMetadata.contexts = @($contexts.Stdout -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
    }
    if ($current.ExitCode -eq 0) { $kubernetesMetadata.current_context = $current.Stdout.Trim() }
    if ($kubernetesMetadata.current_context -match '(?i)(^|[-_/])(prod|production|live)([-_/]|$)') {
        Add-Finding -Id "WORKSTATION-KUBE-PRODUCTION-CONTEXT" -Severity "medium" -Confidence "high" `
            -Title "Current kubectl context appears production-like" `
            -Recommendation "Use explicit --context flags, namespace restrictions, read-only roles, and a distinct terminal profile for production access." `
            -ResourceType "KubernetesContext" -ResourceName $kubernetesMetadata.current_context -Summary "The current context name matched the production safety pattern."
    }
}

$authenticationMetadata = [ordered]@{ checked = [bool]$CheckAuthentication; github = "not-checked"; azure = "not-checked"; aws = "not-checked" }
if ($CheckAuthentication) {
    if (Get-Command -Name gh -ErrorAction SilentlyContinue) {
        $result = Invoke-SafeProcess -FilePath "gh" -Arguments @("auth", "status", "--hostname", "github.com")
        $authenticationMetadata.github = if ($result.ExitCode -eq 0) { "authenticated" } else { "not-authenticated" }
    }
    if (Get-Command -Name az -ErrorAction SilentlyContinue) {
        $result = Invoke-SafeProcess -FilePath "az" -Arguments @("account", "show", "--output", "none")
        $authenticationMetadata.azure = if ($result.ExitCode -eq 0) { "authenticated" } else { "not-authenticated" }
    }
    if (Get-Command -Name aws -ErrorAction SilentlyContinue) {
        $result = Invoke-SafeProcess -FilePath "aws" -Arguments @("sts", "get-caller-identity", "--output", "json")
        $authenticationMetadata.aws = if ($result.ExitCode -eq 0) { "authenticated" } else { "not-authenticated" }
    }
}

$activeFindings = @($findings | Where-Object { -not $_.suppressed })
$thresholdExceeded = @($activeFindings | Where-Object { $severityRank[$_.severity] -ge $severityRank[$SeverityThreshold] }).Count -gt 0
$status = if ($thresholdExceeded) { "fail" } elseif ($activeFindings.Count -gt 0 -or $partial) { "warning" } else { "pass" }
$summary = [ordered]@{ info = 0; low = 0; medium = 0; high = 0; critical = 0; suppressed = 0; total = $findings.Count }
foreach ($finding in $findings) { $summary[$finding.severity]++ }

$payload = [ordered]@{
    schema_version = "1.0"
    metadata = [ordered]@{
        tool = "workstation-doctor"
        tool_version = "1.0.1"
        started_at = $startedAt.ToString("o")
        completed_at = [DateTime]::UtcNow.ToString("o")
        target = "local-windows-workstation"
        partial = $partial
        capabilities = @("tool-discovery", "path-analysis", "git-hygiene", "ssh-hygiene", "wsl", "docker", "kubernetes-contexts", "optional-auth-status")
    }
    findings = @($findings)
    status = $status
    summary = $summary
    extensions = [ordered]@{
        native = [ordered]@{
            powershell_version = $PSVersionTable.PSVersion.ToString()
            operating_system = [System.Environment]::OSVersion.VersionString
            is_64_bit_process = [System.Environment]::Is64BitProcess
            tools = $toolInventory
            path = [ordered]@{ entries = $pathEntries.Count; duplicate_groups = $duplicates.Count; missing_entries = $missingPathEntries.Count }
            git = $gitMetadata
            ssh = $sshMetadata
            wsl = $wslMetadata
            docker = $dockerMetadata
            kubernetes = $kubernetesMetadata
            authentication = $authenticationMetadata
        }
    }
}

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$json = $payload | ConvertTo-Json -Depth 12
$tempPath = "$OutputPath.tmp"
[System.IO.File]::WriteAllText($tempPath, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $tempPath -Destination $OutputPath -Force
Write-Output $OutputPath
if ($FailOnFindings -and $thresholdExceeded) { exit 1 }
if ($partial) { exit 5 }
exit 0
