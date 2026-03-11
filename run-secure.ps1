# BYOV launcher for Slop Orchestrator (Windows)
# Mount keys_vault.hc manually in VeraCrypt first. This script finds it, injects key paths, runs your command.
# Usage: .\run-secure.ps1 slop-cli generate --prompt "..." --repo-path <path>

$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

# Find mounted vault: scan K..T for private.key and c2pa-private-key.pem
$TargetLetter = $null
foreach ($letter in @('K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T')) {
    if ((Test-Path "${letter}:\private.key") -and (Test-Path "${letter}:\c2pa-private-key.pem")) {
        $TargetLetter = $letter
        break
    }
}

if (-not $TargetLetter) {
    Write-Error "Vault not found. Mount keys_vault.hc in VeraCrypt first (drive K..T)."
    exit 1
}

$env:PQC_PRIVATE_KEY_PATH = "${TargetLetter}:\private.key"
$env:C2PA_PRIVATE_KEY_PATH = "${TargetLetter}:\c2pa-private-key.pem"

# Prepend venv so slop-cli is found
foreach ($venv in @(".venv-freeze", ".venv")) {
    $scripts = Join-Path $PSScriptRoot "$venv\Scripts"
    if (Test-Path $scripts) {
        $env:PATH = "$scripts;$env:PATH"
        break
    }
}

if ($args.Count -gt 0) {
    $cmd = $args[0]
    $cmdArgs = $args[1..($args.Count - 1)]
    & $cmd @cmdArgs
    exit $LASTEXITCODE
} else {
    Write-Host "Keys injected. Run your command, or start interactive: .\run-secure.ps1 pwsh"
    $shellExe = (Get-Process -Id $PID).Path
    & $shellExe -NoExit
}
