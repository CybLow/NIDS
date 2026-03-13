# setup-dev.ps1 -- Automated developer environment setup for NIDS (Windows)
#
# Installs all build dependencies via winget/pip, configures Conan 2 with the
# in-repo profile, and runs conan install for Debug + Release.
#
# Usage:
#   .\scripts\dev\setup-dev.ps1               # Full setup
#   .\scripts\dev\setup-dev.ps1 -NoInstall    # Skip package installation (Conan only)
#   .\scripts\dev\setup-dev.ps1 -Help
#
# Requirements:
#   - Windows 10/11 with winget
#   - PowerShell 5.1+ (ships with Windows)
#   - Internet connection
#   - Run as Administrator (for winget installs)

param(
    [switch]$NoInstall,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ConanProfile = Join-Path $ProjectRoot "conan\profiles\windows-msvc17"

# ── Helpers ──────────────────────────────────────────────────────

function Write-Info  { Write-Host "[INFO]  $args" -ForegroundColor Blue }
function Write-Ok    { Write-Host "[OK]    $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "[WARN]  $args" -ForegroundColor Yellow }
function Write-Err   { Write-Host "[ERROR] $args" -ForegroundColor Red }

function Test-Command { param([string]$Name) return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue) }

# ── Help ─────────────────────────────────────────────────────────

if ($Help) {
    Write-Host @"
Usage: .\scripts\dev\setup-dev.ps1 [-NoInstall] [-Help]

  -NoInstall   Skip package installation (Conan setup only)
  -Help        Show this message

This script installs:
  - Visual Studio 2022 Build Tools (C++ workload)
  - CMake, Ninja, Python 3, Conan 2
  - Npcap SDK (for packet capture)
  - Qt6 (via aqtinstall)

Then configures Conan with the in-repo profile and installs dependencies.
"@
    exit 0
}

# ── Install packages ─────────────────────────────────────────────

function Install-Packages {
    Write-Info "Installing build tools via winget..."

    # CMake
    if (-not (Test-Command "cmake")) {
        Write-Info "Installing CMake..."
        winget install --id Kitware.CMake --accept-package-agreements --accept-source-agreements
    } else {
        Write-Ok "CMake already installed: $(cmake --version | Select-Object -First 1)"
    }

    # Ninja
    if (-not (Test-Command "ninja")) {
        Write-Info "Installing Ninja..."
        winget install --id Ninja-build.Ninja --accept-package-agreements --accept-source-agreements
    } else {
        Write-Ok "Ninja already installed"
    }

    # Python
    if (-not (Test-Command "python")) {
        Write-Info "Installing Python..."
        winget install --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    } else {
        Write-Ok "Python already installed: $(python --version)"
    }

    # Visual Studio Build Tools
    Write-Info "Checking Visual Studio Build Tools..."
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $vsPath = & $vsWhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsPath) {
            Write-Ok "Visual Studio C++ tools found: $vsPath"
        } else {
            Write-Warn "Visual Studio found but C++ workload missing. Install it manually:"
            Write-Host "  winget install --id Microsoft.VisualStudio.2022.BuildTools --override '--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'"
        }
    } else {
        Write-Info "Installing Visual Studio 2022 Build Tools..."
        Write-Warn "This may take 10-20 minutes for the C++ workload."
        winget install --id Microsoft.VisualStudio.2022.BuildTools `
            --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --quiet --wait" `
            --accept-package-agreements --accept-source-agreements
    }

    # Npcap SDK
    $NpcapPaths = @("$env:NPCAP_SDK", "C:\npcap-sdk", "${env:ProgramFiles}\Npcap\SDK")
    $NpcapFound = $false
    foreach ($p in $NpcapPaths) {
        if ($p -and (Test-Path $p)) {
            Write-Ok "Npcap SDK found: $p"
            $NpcapFound = $true
            break
        }
    }
    if (-not $NpcapFound) {
        Write-Warn "Npcap SDK not found. Please install manually:"
        Write-Host "  1. Download Npcap installer from https://npcap.com/#download"
        Write-Host "  2. Download Npcap SDK and extract to C:\npcap-sdk"
        Write-Host '  3. Set environment variable: $env:NPCAP_SDK = "C:\npcap-sdk"'
    }

    # Qt6 via aqtinstall
    $Qt6Dir = $null
    $Qt6Candidates = @(
        "C:\Qt\6.8.0\msvc2022_64",
        "C:\Qt\6.7.0\msvc2022_64",
        "$env:USERPROFILE\Qt\6.8.0\msvc2022_64"
    )
    foreach ($p in $Qt6Candidates) {
        if (Test-Path $p) {
            $Qt6Dir = $p
            break
        }
    }
    if ($Qt6Dir) {
        Write-Ok "Qt6 found: $Qt6Dir"
    } else {
        Write-Info "Installing Qt6 via aqtinstall..."
        python -m pip install aqtinstall
        python -m aqt install-qt windows desktop 6.8.0 win64_msvc2022_64 -O C:\Qt
        $Qt6Dir = "C:\Qt\6.8.0\msvc2022_64"
        if (Test-Path $Qt6Dir) {
            Write-Ok "Qt6 installed: $Qt6Dir"
        } else {
            Write-Warn "Qt6 installation may have failed. Check C:\Qt manually."
        }
    }

    if ($Qt6Dir) {
        Write-Info "Setting CMAKE_PREFIX_PATH for Qt6..."
        [System.Environment]::SetEnvironmentVariable("CMAKE_PREFIX_PATH", $Qt6Dir, "User")
        $env:CMAKE_PREFIX_PATH = $Qt6Dir
    }

    Write-Ok "Package installation complete"
}

# ── Install Conan ────────────────────────────────────────────────

function Install-Conan {
    if (Test-Command "conan") {
        $ver = (conan --version 2>&1) -replace '.*?(\d+\.\d+\.\d+).*', '$1'
        Write-Ok "Conan already installed (v$ver)"
    } else {
        Write-Info "Installing Conan 2..."
        python -m pip install conan
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        Write-Ok "Conan installed"
    }

    # Verify
    conan --version
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Conan installation failed"
        exit 1
    }
}

# ── Configure Conan ──────────────────────────────────────────────

function Configure-Conan {
    Write-Info "Detecting Conan default profile..."
    conan profile detect --force 2>&1 | Out-Null

    if (-not (Test-Path $ConanProfile)) {
        Write-Err "In-repo Conan profile not found: $ConanProfile"
        exit 1
    }
    Write-Ok "Using in-repo Conan profile: $ConanProfile"
}

# ── Install Conan deps ──────────────────────────────────────────

function Install-ConanDeps {
    Push-Location $ProjectRoot
    try {
        Write-Info "Installing Conan dependencies (Debug)..."
        conan install . -pr:h $ConanProfile -s build_type=Debug --build=missing

        Write-Info "Installing Conan dependencies (Release)..."
        conan install . -pr:h $ConanProfile -s build_type=Release --build=missing

        Write-Ok "Conan dependencies installed for Debug + Release"
    } finally {
        Pop-Location
    }
}

# ── Print next steps ─────────────────────────────────────────────

function Show-NextSteps {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  NIDS development environment is ready " -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Conan has generated CMakeUserPresets.json with 'conan-debug' and"
    Write-Host "'conan-release' presets that include the toolchain automatically."
    Write-Host ""
    Write-Host "Quick start (from Developer Command Prompt or VS terminal):"
    Write-Host ""
    Write-Host "  # Debug build:"
    Write-Host "  cmake --preset conan-debug"
    Write-Host "  cmake --build --preset conan-debug"
    Write-Host "  ctest --preset conan-debug"
    Write-Host ""
    Write-Host "  # Release build:"
    Write-Host "  cmake --preset conan-release"
    Write-Host "  cmake --build --preset conan-release"
    Write-Host "  ctest --preset conan-release"
    Write-Host ""
    Write-Host "  # Run:"
    Write-Host "  .\build\Release\NIDS.exe"
    Write-Host ""
}

# ── Main ─────────────────────────────────────────────────────────

Write-Host ""
Write-Info "NIDS Developer Environment Setup (Windows)"
Write-Info "Project root: $ProjectRoot"
Write-Host ""

if (-not $NoInstall) {
    Install-Packages
} else {
    Write-Info "Skipping package installation (-NoInstall)"
}

Install-Conan
Configure-Conan
Install-ConanDeps
Show-NextSteps
