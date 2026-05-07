#Requires -Version 5.1
<#
.SYNOPSIS
    secops-squad installer for Windows
.DESCRIPTION
    Installs secops-squad — AI SecOps team for Microsoft Security stack.
    Checks prerequisites, clones the repository, installs dependencies.
.EXAMPLE
    irm https://raw.githubusercontent.com/x3nc0n/secops-squad-starter-kit/main/install.ps1 | iex
.EXAMPLE
    .\install.ps1
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:USERPROFILE\secops-squad"
)

$ErrorActionPreference = "Stop"

$RepoUrl = "https://github.com/x3nc0n/secops-squad-starter-kit.git"

function Write-Banner {
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │  secops-squad installer               │" -ForegroundColor Cyan
    Write-Host "  │  AI SecOps team for Microsoft        │" -ForegroundColor Cyan
    Write-Host "  │  Security stack                      │" -ForegroundColor Cyan
    Write-Host "  └─────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
}

function Test-CommandAvailable {
    param(
        [string]$Command,
        [string]$DisplayName,
        [string]$InstallUrl,
        [bool]$Required = $true
    )

    $cmd = Get-Command $Command -ErrorAction SilentlyContinue
    if ($cmd) {
        try {
            $version = & $Command --version 2>&1 | Select-Object -First 1
        } catch {
            $version = "installed"
        }
        Write-Host "  ✅ ${DisplayName}: $version" -ForegroundColor Green
        return $true
    } else {
        if ($Required) {
            Write-Host "  ❌ ${DisplayName} not found" -ForegroundColor Red
            Write-Host "     Install: $InstallUrl" -ForegroundColor DarkGray
            return $false
        } else {
            Write-Host "  ⚠️  ${DisplayName} not found (optional)" -ForegroundColor Yellow
            Write-Host "     Install: $InstallUrl" -ForegroundColor DarkGray
            return $true
        }
    }
}

function Test-NodeVersion {
    $nodeCmd = Get-Command "node" -ErrorAction SilentlyContinue
    if (-not $nodeCmd) {
        Write-Host "  ❌ Node.js not found" -ForegroundColor Red
        Write-Host "     Install Node.js 18+: https://nodejs.org" -ForegroundColor DarkGray
        return $false
    }

    $version = & node -v 2>&1
    $major = [int]($version -replace "^v" -split "\." | Select-Object -First 1)

    if ($major -ge 18) {
        Write-Host "  ✅ Node.js $version (>= 18 required)" -ForegroundColor Green
        return $true
    } else {
        Write-Host "  ❌ Node.js $version — version 18+ required" -ForegroundColor Red
        Write-Host "     Upgrade: https://nodejs.org" -ForegroundColor DarkGray
        return $false
    }
}

function Install-SecOpsSquad {
    Write-Banner

    Write-Host "Checking prerequisites..." -ForegroundColor White
    Write-Host ""

    $failed = $false

    if (-not (Test-NodeVersion)) { $failed = $true }
    if (-not (Test-CommandAvailable "git" "Git" "https://git-scm.com" $true)) { $failed = $true }
    Test-CommandAvailable "gh" "GitHub CLI" "https://cli.github.com" $false | Out-Null
    Test-CommandAvailable "az" "Azure CLI" "https://aka.ms/installazurecliwindows" $false | Out-Null

    Write-Host ""

    if ($failed) {
        Write-Host "Prerequisites check failed." -ForegroundColor Red
        Write-Host "Install the missing tools above and re-run this script." -ForegroundColor DarkGray
        Write-Host ""
        exit 1
    }

    Write-Host "✅ All required prerequisites met." -ForegroundColor Green
    Write-Host ""

    if (Test-Path $InstallDir) {
        Write-Host "Directory $InstallDir already exists." -ForegroundColor Yellow
        Write-Host "Remove it first or choose a different location with -InstallDir." -ForegroundColor DarkGray
        Write-Host ""
        exit 1
    }

    # Download the repo content (shallow clone), then create a standalone repo
    Write-Host "Downloading secops-squad..." -ForegroundColor Cyan
    $TempDir = Join-Path $env:TEMP "secops-squad-download-$(Get-Random)"
    & git clone --depth 1 $RepoUrl $TempDir 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Failed to download secops-squad." -ForegroundColor Red
        exit 1
    }

    # Copy content (without .git) to create a standalone project
    Write-Host "Creating your secops-squad project..." -ForegroundColor Cyan
    Copy-Item -Path $TempDir -Destination $InstallDir -Recurse -Force
    Remove-Item -Path (Join-Path $InstallDir ".git") -Recurse -Force

    # Initialize a fresh git repo
    Push-Location $InstallDir
    & git init --quiet
    & git add .
    & git commit --quiet -m "Initialize secops-squad project"
    Pop-Location

    # Clean up temp download
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

    # Install dependencies
    Write-Host "Installing dependencies..." -ForegroundColor Cyan
    Push-Location $InstallDir
    try {
        & npm install --production --quiet 2>$null
    } catch {
        Write-Host "  npm install had warnings (non-blocking)" -ForegroundColor Yellow
    }
    Pop-Location

    Write-Host ""
    Write-Host "✅ secops-squad installed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To use the CLI, either:" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. Add to PATH:" -ForegroundColor Cyan
    Write-Host "     `$env:Path += `";$InstallDir\cli`"" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  2. Or run directly:" -ForegroundColor Cyan
    Write-Host "     node $InstallDir\cli\index.js" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Getting started:" -ForegroundColor White
    Write-Host "  cd $InstallDir" -ForegroundColor Cyan
    Write-Host "  node cli\index.js init" -ForegroundColor Cyan
    Write-Host "  node cli\index.js doctor" -ForegroundColor Cyan
    Write-Host ""
}

Install-SecOpsSquad
