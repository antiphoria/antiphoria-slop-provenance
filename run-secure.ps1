# BYOV launcher for Slop Orchestrator (Windows)
# Mounts VeraCrypt vault, injects key paths, runs command, unmounts on exit.
# Requires: Administrator privileges, VeraCrypt, keys_vault.hc at project root.

$ErrorActionPreference = "Stop"

# UAC: Virtual volume mounting requires Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Please run this script in an Administrator PowerShell prompt. Virtual volume mounting requires elevated privileges."
    exit 1
}

$VaultPath = if ($env:KEYS_VAULT_PATH) { $env:KEYS_VAULT_PATH } else { Join-Path $PSScriptRoot "keys_vault.hc" }
$VaultPath = [System.IO.Path]::GetFullPath($VaultPath)

if (-not (Test-Path $VaultPath)) {
    Write-Error "Vault not found: $VaultPath. Create keys_vault.hc per SECURITY.md."
    exit 1
}

# Resolve VeraCrypt executable
$VeraCryptExe = $null
if (Get-Command VeraCrypt -ErrorAction SilentlyContinue) {
    $VeraCryptExe = (Get-Command VeraCrypt).Source
} elseif (Test-Path "${env:ProgramFiles}\VeraCrypt\VeraCrypt.exe") {
    $VeraCryptExe = "${env:ProgramFiles}\VeraCrypt\VeraCrypt.exe"
} elseif (Test-Path "${env:ProgramFiles(x86)}\VeraCrypt\VeraCrypt.exe") {
    $VeraCryptExe = "${env:ProgramFiles(x86)}\VeraCrypt\VeraCrypt.exe"
}
if (-not $VeraCryptExe) {
    Write-Error "VeraCrypt not found. Install VeraCrypt and ensure it is in PATH or Program Files."
    exit 1
}

# Multi-process check: is vault already mounted?
$TargetLetter = $null
$WeMounted = $false
try {
    $listOut = & $VeraCryptExe /q /l 2>&1 | Out-String
    $vaultPathEscaped = [regex]::Escape($VaultPath)
    foreach ($line in ($listOut -split "`n")) {
        if ($line -match 'Drive\s+([A-Z]):\s+' -and $line -match $vaultPathEscaped) {
            $TargetLetter = $Matches[1]
            break
        }
    }
} catch {
    # /l may not exist or output format differs; proceed to mount
}

$LettersToTry = @('K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T')

if (-not $TargetLetter) {
    # Mount: try letters in order
    foreach ($letter in $LettersToTry) {
        $existing = Get-PSDrive -Name $letter -ErrorAction SilentlyContinue
        if (-not $existing) {
            $TargetLetter = $letter
            break
        }
    }
    if (-not $TargetLetter) {
        Write-Error "No free drive letter in K..T. Free one and retry."
        exit 1
    }

    # VeraCrypt /volume "path" /letter X /quit - spawns GUI, returns immediately
    & $VeraCryptExe /volume $VaultPath /letter "${TargetLetter}:" /quit
    $WeMounted = $true

    # Poll until private.key appears (user may still be typing password)
    $timeout = 120
    $elapsed = 0
    $interval = 2
    while (-not (Test-Path "${TargetLetter}:\private.key")) {
        Start-Sleep -Seconds $interval
        $elapsed += $interval
        if ($elapsed -ge $timeout) {
            Write-Error "Timeout: vault not mounted within ${timeout}s. Ensure you entered the password."
            exit 1
        }
    }
}

$PqcKey = "${TargetLetter}:\private.key"
$C2paKey = "${TargetLetter}:\c2pa-private-key.pem"

if (-not (Test-Path $PqcKey)) {
    Write-Error "Missing $PqcKey in vault. Add private.key per SECURITY.md."
    exit 1
}
if (-not (Test-Path $C2paKey)) {
    Write-Error "Missing $C2paKey in vault. Add c2pa-private-key.pem per SECURITY.md."
    exit 1
}

$env:PQC_PRIVATE_KEY_PATH = $PqcKey
$env:C2PA_PRIVATE_KEY_PATH = $C2paKey

$exitCode = 0
try {
    if ($args.Count -gt 0) {
        & $args[0] @args[1..($args.Count - 1)]
        $exitCode = $LASTEXITCODE
    } else {
        pwsh -NoExit
    }
} finally {
    if ($WeMounted) {
        & $VeraCryptExe /dismount $TargetLetter
    }
}
if ($args.Count -gt 0) { exit $exitCode }
