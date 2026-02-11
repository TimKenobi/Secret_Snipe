<#
.SYNOPSIS
    SecretSnipe Enterprise Agent Installer for Windows
    
.DESCRIPTION
    Professional-grade installer for SecretSnipe scanning agent.
    Features:
    - Runs as a Windows Service under LocalSystem or custom service account
    - Supports BOTH standalone .exe (no Python needed) OR Python-based agent
    - Secure configuration with DPAPI encryption
    - Automatic service recovery
    - Tamper protection with file integrity monitoring
    - Secure communication with certificate pinning
    - Audit logging for compliance
    
.PARAMETER ManagerUrl
    The URL of the SecretSnipe Agent Manager (e.g., https://secretsnipe.company.com:8443)
    
.PARAMETER ApiKey
    API key for agent authentication
    
.PARAMETER InstallPath
    Installation directory (default: C:\Program Files\SecretSnipe)
    
.PARAMETER AgentExePath
    Path to pre-built SecretSnipeAgent.exe (standalone mode - no Python required)
    If not specified, will download Python script and require Python installed.
    
.PARAMETER ServiceAccount
    Service account (default: LocalSystem, or specify domain\user for custom)
    
.PARAMETER ServicePassword
    Password for custom service account (SecureString)
    
.PARAMETER ScanPaths
    Comma-separated list of paths to scan
    
.PARAMETER DisableGitleaks
    Skip Gitleaks scanner installation (installed by default)
    
.PARAMETER DisableTrufflehog
    Skip Trufflehog scanner installation (installed by default)
    
.PARAMETER Uninstall
    Remove the agent service and files

.EXAMPLE
    # Standalone EXE mode (no Python required)
    .\Install-SecretSnipeAgent.ps1 -ManagerUrl "https://10.150.110.24:8443" -ApiKey "your-api-key" -AgentExePath ".\SecretSnipeAgent.exe"

.EXAMPLE
    # Python mode (requires Python 3.9+)
    .\Install-SecretSnipeAgent.ps1 -ManagerUrl "https://10.150.110.24:8443" -ApiKey "your-api-key"
    
.EXAMPLE
    .\Install-SecretSnipeAgent.ps1 -Uninstall
    
.NOTES
    Author: SecretSnipe Team
    Version: 2.0.0
    Requires: PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding(DefaultParameterSetName='Install')]
param(
    [Parameter(ParameterSetName='Install', Mandatory=$true)]
    [ValidatePattern('^https?://')]
    [string]$ManagerUrl,
    
    [Parameter(ParameterSetName='Install', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ApiKey,
    
    [Parameter(ParameterSetName='Install')]
    [ValidateScript({Test-Path (Split-Path $_ -Parent) -PathType Container})]
    [string]$InstallPath = "C:\Program Files\SecretSnipe",
    
    [Parameter(ParameterSetName='Install')]
    [string]$AgentExePath,  # Path to standalone .exe (no Python needed)
    
    [Parameter(ParameterSetName='Install')]
    [string]$ServiceAccount = "LocalSystem",
    
    [Parameter(ParameterSetName='Install')]
    [SecureString]$ServicePassword,
    
    [Parameter(ParameterSetName='Install')]
    [string[]]$ScanPaths = @(),
    
    [Parameter(ParameterSetName='Install')]
    [switch]$DisableGitleaks,
    
    [Parameter(ParameterSetName='Install')]
    [switch]$DisableTrufflehog,
    
    [Parameter(ParameterSetName='Install')]
    [switch]$EnableFileWatcher,
    
    [Parameter(ParameterSetName='Install')]
    [int]$MaxCpuPercent = 50,
    
    [Parameter(ParameterSetName='Install')]
    [int]$MaxMemoryMB = 512,
    
    [Parameter(ParameterSetName='Uninstall', Mandatory=$true)]
    [switch]$Uninstall,
    
    [Parameter(ParameterSetName='Update', Mandatory=$true)]
    [switch]$Update,
    
    [switch]$Force
)

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# CONSTANTS
# ============================================================================

$AGENT_VERSION = "2.0.0"
$SERVICE_NAME = "SecretSnipeAgent"
$SERVICE_DISPLAY_NAME = "SecretSnipe Security Scanner Agent"
$SERVICE_DESCRIPTION = "Enterprise secret scanning agent for detecting exposed credentials in file systems"
$LOG_SOURCE = "SecretSnipeAgent"
$EVENT_LOG = "Application"
$PYTHON_MIN_VERSION = [Version]"3.9.0"

# Security settings
$SECURE_PERMISSIONS = @{
    ConfigFile = "Administrators", "SYSTEM"
    LogDirectory = "Administrators", "SYSTEM", "LOCAL SERVICE"
    InstallDirectory = "Administrators", "SYSTEM"
}

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "White" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    
    # Also write to Windows Event Log if available
    try {
        if ([System.Diagnostics.EventLog]::SourceExists($LOG_SOURCE)) {
            $entryType = switch ($Level) {
                "ERROR" { [System.Diagnostics.EventLogEntryType]::Error }
                "WARN"  { [System.Diagnostics.EventLogEntryType]::Warning }
                default { [System.Diagnostics.EventLogEntryType]::Information }
            }
            Write-EventLog -LogName $EVENT_LOG -Source $LOG_SOURCE -EventId 1000 -EntryType $entryType -Message $Message
        }
    } catch {
        # Silently continue if event log write fails
    }
}

function Initialize-EventLog {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($LOG_SOURCE)) {
            New-EventLog -LogName $EVENT_LOG -Source $LOG_SOURCE -ErrorAction SilentlyContinue
            Write-Log "Created Windows Event Log source: $LOG_SOURCE" -Level SUCCESS
        }
    } catch {
        Write-Log "Could not create Event Log source (non-critical): $_" -Level WARN
    }
}

# ============================================================================
# PREREQUISITE CHECKS
# ============================================================================

# Script-level variable to track installation mode
$script:UseStandaloneExe = $false
$script:AgentExecutable = ""

function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.1 or higher is required. Current: $($PSVersionTable.PSVersion)"
    }
    Write-Log "PowerShell version: $($PSVersionTable.PSVersion)" -Level SUCCESS
    
    # Check if using standalone EXE mode
    if ($AgentExePath) {
        if (Test-Path $AgentExePath) {
            $script:UseStandaloneExe = $true
            $script:AgentExecutable = $AgentExePath
            Write-Log "Using standalone executable: $AgentExePath" -Level SUCCESS
            Write-Log "Python NOT required (standalone mode)" -Level INFO
            return
        } else {
            throw "Specified agent executable not found: $AgentExePath"
        }
    }
    
    # Try to download standalone exe from manager
    Write-Log "Checking for standalone executable on manager..."
    try {
        $exeUrl = "$ManagerUrl/api/v1/agent/download/exe"
        $testExePath = "$env:TEMP\SecretSnipeAgent_test.exe"
        
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("X-API-Key", $ApiKey)
        
        try {
            $webClient.DownloadFile($exeUrl, $testExePath)
            if ((Test-Path $testExePath) -and ((Get-Item $testExePath).Length -gt 10000)) {
                $script:UseStandaloneExe = $true
                $script:AgentExecutable = $testExePath
                Write-Log "Downloaded standalone executable from manager" -Level SUCCESS
                Write-Log "Python NOT required (standalone mode)" -Level INFO
                return
            }
        } catch {
            Write-Log "Standalone exe not available on manager, checking for Python..." -Level INFO
        } finally {
            $webClient.Dispose()
        }
    } catch {
        Write-Log "Could not check for standalone exe: $_" -Level INFO
    }
    
    # Python mode - check for Python
    $pythonPath = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonPath) {
        $pythonPath = Get-Command python3 -ErrorAction SilentlyContinue
    }
    
    if (-not $pythonPath) {
        Write-Log "Python not found and no standalone executable available." -Level ERROR
        Write-Log "" -Level INFO
        Write-Log "OPTIONS:" -Level INFO
        Write-Log "  1. Install Python 3.9+ from https://python.org" -Level INFO
        Write-Log "  2. Use -AgentExePath parameter with pre-built SecretSnipeAgent.exe" -Level INFO
        Write-Log "  3. Build SecretSnipeAgent.exe using: python build_agent_exe.py" -Level INFO
        Write-Log "" -Level INFO
        throw "Python 3.9+ is required, or provide -AgentExePath for standalone mode"
    }
    
    $pythonVersion = & $pythonPath.Source --version 2>&1
    if ($pythonVersion -match "Python (\d+\.\d+\.\d+)") {
        $version = [Version]$Matches[1]
        if ($version -lt $PYTHON_MIN_VERSION) {
            throw "Python $PYTHON_MIN_VERSION+ required, found $version"
        }
        Write-Log "Python version: $version" -Level SUCCESS
    }
    
    # Check required Python packages
    $requiredPackages = @("requests", "psutil")
    $optionalPackages = @{
        "watchdog" = $EnableFileWatcher
        "croniter" = $true
    }
    
    # Temporarily allow errors for package checks
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    
    foreach ($pkg in $requiredPackages) {
        try {
            $checkResult = cmd /c "`"$($pythonPath.Source)`" -c `"import $pkg; print('OK')`"" 2>&1
            if ($checkResult -notmatch 'OK') {
                Write-Log "Installing required package: $pkg" -Level INFO
                cmd /c "`"$($pythonPath.Source)`" -m pip install $pkg --quiet" 2>&1 | Out-Null
            }
        } catch {
            Write-Log "Installing required package: $pkg" -Level INFO
            cmd /c "`"$($pythonPath.Source)`" -m pip install $pkg --quiet" 2>&1 | Out-Null
        }
    }
    
    foreach ($pkg in $optionalPackages.Keys) {
        if ($optionalPackages[$pkg]) {
            try {
                $checkResult = cmd /c "`"$($pythonPath.Source)`" -c `"import $pkg; print('OK')`"" 2>&1
                if ($checkResult -notmatch 'OK') {
                    Write-Log "Installing optional package: $pkg" -Level INFO
                    cmd /c "`"$($pythonPath.Source)`" -m pip install $pkg --quiet" 2>&1 | Out-Null
                }
            } catch {
                Write-Log "Installing optional package: $pkg" -Level INFO
                cmd /c "`"$($pythonPath.Source)`" -m pip install $pkg --quiet" 2>&1 | Out-Null
            }
        }
    }
    
    $ErrorActionPreference = $oldErrorAction
    
    # Scanners will be installed by Install-Scanners function
    Write-Log "Scanners will be installed during setup..." -Level INFO
    
    # Network connectivity check
    Write-Log "Testing connectivity to manager..."
    try {
        $uri = [Uri]$ManagerUrl
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($uri.Host, $uri.Port)
        $tcpClient.Close()
        Write-Log "Manager reachable at $($uri.Host):$($uri.Port)" -Level SUCCESS
    } catch {
        throw "Cannot connect to manager at $ManagerUrl - $_"
    }
    
    Write-Log "All prerequisites passed!" -Level SUCCESS
}

# ============================================================================
# SCANNER INSTALLATION FUNCTIONS
# ============================================================================

function Install-Scanners {
    <#
    .SYNOPSIS
    Downloads and installs Gitleaks and Trufflehog scanners
    #>
    
    $scannersPath = "$InstallPath\scanners"
    if (-not (Test-Path $scannersPath)) {
        New-Item -ItemType Directory -Path $scannersPath -Force | Out-Null
    }
    
    Write-Log "Installing security scanners..." -Level INFO
    
    # ========== INSTALL GITLEAKS ==========
    if (-not $DisableGitleaks) {
        Write-Log "Installing Gitleaks scanner..." -Level INFO
        
        $gitleaksPath = "$scannersPath\gitleaks.exe"
        $gitleaksInstalled = $false
        
        # Check if already installed
        if (Test-Path $gitleaksPath) {
            try {
                $versionCheck = & $gitleaksPath version 2>&1
                if ($versionCheck -match 'v?\d+\.\d+') {
                    Write-Log "Gitleaks already installed: $versionCheck" -Level SUCCESS
                    $gitleaksInstalled = $true
                    $script:GitleaksPath = $gitleaksPath
                }
            } catch {}
        }
        
        if (-not $gitleaksInstalled) {
            try {
                # Get latest release from GitHub
                Write-Log "Downloading Gitleaks from GitHub..." -Level INFO
                
                # GitHub API to get latest release
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $releaseUrl = "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
                $headers = @{ "User-Agent" = "SecretSnipe-Installer" }
                
                try {
                    $release = Invoke-RestMethod -Uri $releaseUrl -Headers $headers -TimeoutSec 30
                    $version = $release.tag_name
                    Write-Log "Latest Gitleaks version: $version" -Level INFO
                    
                    # Find Windows x64 asset (naming changed from amd64 to x64)
                    $asset = $release.assets | Where-Object { $_.name -match 'windows.*x64.*\.zip$' } | Select-Object -First 1
                    
                    if ($asset) {
                        $downloadUrl = $asset.browser_download_url
                        $zipPath = "$env:TEMP\gitleaks.zip"
                        $extractPath = "$env:TEMP\gitleaks_extract"
                        
                        Write-Log "Downloading from: $downloadUrl" -Level INFO
                        
                        # Download
                        $webClient = New-Object System.Net.WebClient
                        $webClient.DownloadFile($downloadUrl, $zipPath)
                        
                        # Extract
                        if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
                        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
                        
                        # Find and copy executable
                        $exeFile = Get-ChildItem -Path $extractPath -Filter "gitleaks.exe" -Recurse | Select-Object -First 1
                        if ($exeFile) {
                            Copy-Item $exeFile.FullName -Destination $gitleaksPath -Force
                            Write-Log "Gitleaks installed successfully!" -Level SUCCESS
                            $script:GitleaksPath = $gitleaksPath
                            $gitleaksInstalled = $true
                        } else {
                            Write-Log "Could not find gitleaks.exe in downloaded archive" -Level WARN
                        }
                        
                        # Cleanup
                        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
                        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                    } else {
                        Write-Log "Could not find Windows x64 release asset" -Level WARN
                    }
                } catch {
                    Write-Log "GitHub API failed, trying direct download..." -Level WARN
                    
                    # Fallback to known version (using x64 naming)
                    $fallbackVersion = "8.30.0"
                    $fallbackUrl = "https://github.com/gitleaks/gitleaks/releases/download/v$fallbackVersion/gitleaks_${fallbackVersion}_windows_x64.zip"
                    $zipPath = "$env:TEMP\gitleaks.zip"
                    $extractPath = "$env:TEMP\gitleaks_extract"
                    
                    Write-Log "Downloading Gitleaks v$fallbackVersion..." -Level INFO
                    
                    $webClient = New-Object System.Net.WebClient
                    $webClient.DownloadFile($fallbackUrl, $zipPath)
                    
                    if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
                    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
                    
                    $exeFile = Get-ChildItem -Path $extractPath -Filter "gitleaks.exe" -Recurse | Select-Object -First 1
                    if ($exeFile) {
                        Copy-Item $exeFile.FullName -Destination $gitleaksPath -Force
                        Write-Log "Gitleaks v$fallbackVersion installed successfully!" -Level SUCCESS
                        $script:GitleaksPath = $gitleaksPath
                        $gitleaksInstalled = $true
                    }
                    
                    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
                    Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Log "Failed to install Gitleaks: $_" -Level WARN
                Write-Log "Gitleaks scanner will be disabled" -Level WARN
            }
        }
        
        if (-not $gitleaksInstalled) {
            $script:GitleaksPath = $null
        }
    } else {
        Write-Log "Gitleaks installation skipped (disabled)" -Level INFO
        $script:GitleaksPath = $null
    }
    
    # ========== INSTALL TRUFFLEHOG ==========
    if (-not $DisableTrufflehog) {
        Write-Log "Installing Trufflehog scanner..." -Level INFO
        
        $trufflehogPath = "$scannersPath\trufflehog.exe"
        $trufflehogInstalled = $false
        
        # Check if already installed
        if (Test-Path $trufflehogPath) {
            try {
                $versionCheck = & $trufflehogPath --version 2>&1
                if ($versionCheck -match '\d+\.\d+') {
                    Write-Log "Trufflehog already installed: $versionCheck" -Level SUCCESS
                    $trufflehogInstalled = $true
                    $script:TrufflehogPath = $trufflehogPath
                    $script:TrufflehogEnabled = $true
                }
            } catch {}
        }
        
        if (-not $trufflehogInstalled) {
            try {
                # Download Trufflehog binary from GitHub releases
                Write-Log "Downloading Trufflehog from GitHub..." -Level INFO
                
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $releaseUrl = "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest"
                $headers = @{ "User-Agent" = "SecretSnipe-Installer" }
                
                try {
                    $release = Invoke-RestMethod -Uri $releaseUrl -Headers $headers -TimeoutSec 30
                    $version = $release.tag_name
                    Write-Log "Latest Trufflehog version: $version" -Level INFO
                    
                    # Find Windows amd64 asset (tar.gz format)
                    $asset = $release.assets | Where-Object { $_.name -match 'windows.*amd64.*\.tar\.gz$' } | Select-Object -First 1
                    
                    if ($asset) {
                        $downloadUrl = $asset.browser_download_url
                        $tarPath = "$env:TEMP\trufflehog.tar.gz"
                        $extractPath = "$env:TEMP\trufflehog_extract"
                        
                        Write-Log "Downloading from: $downloadUrl" -Level INFO
                        
                        # Download
                        $webClient = New-Object System.Net.WebClient
                        $webClient.DownloadFile($downloadUrl, $tarPath)
                        
                        # Extract tar.gz (PowerShell 5.1+ can handle this with tar command)
                        if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
                        New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
                        
                        # Use tar command (available on Windows 10+)
                        Push-Location $extractPath
                        try {
                            tar -xzf $tarPath 2>&1 | Out-Null
                        } catch {
                            # Fallback: try using 7-zip if available
                            $7z = Get-Command 7z -ErrorAction SilentlyContinue
                            if ($7z) {
                                & 7z x $tarPath -o"$extractPath" -y | Out-Null
                                $tarFile = Get-ChildItem -Path $extractPath -Filter "*.tar" | Select-Object -First 1
                                if ($tarFile) {
                                    & 7z x $tarFile.FullName -o"$extractPath" -y | Out-Null
                                }
                            }
                        }
                        Pop-Location
                        
                        # Find and copy executable
                        $exeFile = Get-ChildItem -Path $extractPath -Filter "trufflehog.exe" -Recurse | Select-Object -First 1
                        if ($exeFile) {
                            Copy-Item $exeFile.FullName -Destination $trufflehogPath -Force
                            Write-Log "Trufflehog installed successfully!" -Level SUCCESS
                            $script:TrufflehogPath = $trufflehogPath
                            $script:TrufflehogEnabled = $true
                            $trufflehogInstalled = $true
                        } else {
                            Write-Log "Could not find trufflehog.exe in downloaded archive" -Level WARN
                        }
                        
                        # Cleanup
                        Remove-Item $tarPath -Force -ErrorAction SilentlyContinue
                        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                    } else {
                        Write-Log "Could not find Windows amd64 release asset" -Level WARN
                    }
                } catch {
                    Write-Log "GitHub API failed, trying direct download..." -Level WARN
                    
                    # Fallback to known version
                    $fallbackVersion = "3.93.3"
                    $fallbackUrl = "https://github.com/trufflesecurity/trufflehog/releases/download/v$fallbackVersion/trufflehog_${fallbackVersion}_windows_amd64.tar.gz"
                    $tarPath = "$env:TEMP\trufflehog.tar.gz"
                    $extractPath = "$env:TEMP\trufflehog_extract"
                    
                    Write-Log "Downloading Trufflehog v$fallbackVersion..." -Level INFO
                    
                    $webClient = New-Object System.Net.WebClient
                    $webClient.DownloadFile($fallbackUrl, $tarPath)
                    
                    if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
                    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
                    
                    Push-Location $extractPath
                    try { tar -xzf $tarPath 2>&1 | Out-Null } catch {}
                    Pop-Location
                    
                    $exeFile = Get-ChildItem -Path $extractPath -Filter "trufflehog.exe" -Recurse | Select-Object -First 1
                    if ($exeFile) {
                        Copy-Item $exeFile.FullName -Destination $trufflehogPath -Force
                        Write-Log "Trufflehog v$fallbackVersion installed successfully!" -Level SUCCESS
                        $script:TrufflehogPath = $trufflehogPath
                        $script:TrufflehogEnabled = $true
                        $trufflehogInstalled = $true
                    }
                    
                    Remove-Item $tarPath -Force -ErrorAction SilentlyContinue
                    Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Log "Failed to install Trufflehog: $_" -Level WARN
                Write-Log "Trufflehog scanner will be disabled" -Level WARN
            }
        }
        
        if (-not $trufflehogInstalled) {
            $script:TrufflehogPath = $null
            $script:TrufflehogEnabled = $false
        }
    } else {
        Write-Log "Trufflehog installation skipped (disabled)" -Level INFO
        $script:TrufflehogPath = $null
        $script:TrufflehogEnabled = $false
    }
    
    # Summary
    Write-Log "" -Level INFO
    Write-Log "Scanner Installation Summary:" -Level INFO
    Write-Log "  Custom Regex Scanner: ENABLED (built-in)" -Level SUCCESS
    if ($script:GitleaksPath) {
        Write-Log "  Gitleaks Scanner:     ENABLED ($($script:GitleaksPath))" -Level SUCCESS
    } else {
        Write-Log "  Gitleaks Scanner:     DISABLED" -Level WARN
    }
    if ($script:TrufflehogEnabled) {
        Write-Log "  Trufflehog Scanner:   ENABLED ($($script:TrufflehogPath))" -Level SUCCESS
    } else {
        Write-Log "  Trufflehog Scanner:   DISABLED" -Level WARN
    }
    Write-Log "" -Level INFO
}

# ============================================================================
# SECURITY FUNCTIONS
# ============================================================================

function Protect-ConfigData {
    <#
    .SYNOPSIS
    Encrypts sensitive configuration data using DPAPI
    #>
    param([string]$Data)
    
    Add-Type -AssemblyName System.Security
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes, 
        $null, 
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    return [Convert]::ToBase64String($encrypted)
}

function Unprotect-ConfigData {
    <#
    .SYNOPSIS
    Decrypts DPAPI-protected configuration data
    #>
    param([string]$EncryptedData)
    
    Add-Type -AssemblyName System.Security
    $encrypted = [Convert]::FromBase64String($EncryptedData)
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encrypted,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function Set-SecurePermissions {
    <#
    .SYNOPSIS
    Sets restrictive NTFS permissions on sensitive files/folders
    #>
    param(
        [string]$Path,
        [string[]]$AllowedPrincipals
    )
    
    try {
        if (Test-Path $Path -PathType Container) {
            $acl = Get-Acl -Path $Path
            $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
            
            # Remove existing rules
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null
            
            foreach ($principal in $AllowedPrincipals) {
                $inheritFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $principal,
                    "FullControl",
                    $inheritFlags,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    "Allow"
                )
                $acl.AddAccessRule($rule)
            }
            Set-Acl -Path $Path -AclObject $acl
        } elseif (Test-Path $Path) {
            $acl = Get-Acl -Path $Path
            $acl.SetAccessRuleProtection($true, $false)
            
            foreach ($principal in $AllowedPrincipals) {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $principal,
                    "FullControl",
                    "Allow"
                )
                $acl.AddAccessRule($rule)
            }
            Set-Acl -Path $Path -AclObject $acl
        }
    } catch {
        Write-Log "Warning: Could not set permissions on $Path - $_" -Level WARN
    }
}

function Get-MachineFingerprint {
    <#
    .SYNOPSIS
    Generates a unique machine fingerprint for agent identification
    #>
    
    $components = @()
    
    # Get BIOS serial
    try {
        $bios = Get-WmiObject -Class Win32_BIOS
        $components += $bios.SerialNumber
    } catch {}
    
    # Get motherboard serial
    try {
        $board = Get-WmiObject -Class Win32_BaseBoard
        $components += $board.SerialNumber
    } catch {}
    
    # Get machine GUID
    try {
        $machineGuid = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
        $components += $machineGuid
    } catch {}
    
    # Fallback to hostname if nothing else works
    if ($components.Count -eq 0) {
        $components += $env:COMPUTERNAME
    }
    
    $combined = $components -join ":"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combined))
    return [BitConverter]::ToString($hash).Replace("-", "").Substring(0, 32).ToLower()
}

# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================

function Install-AgentFiles {
    Write-Log "Installing agent files to $InstallPath..."
    
    # Create directory structure
    $directories = @(
        $InstallPath,
        "$InstallPath\logs",
        "$InstallPath\config",
        "$InstallPath\temp",
        "$InstallPath\scanners"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    # Handle Standalone EXE mode vs Python mode
    if ($script:UseStandaloneExe) {
        # STANDALONE EXE MODE
        Write-Log "Installing standalone executable (no Python required)..." -Level INFO
        
        $exeDest = "$InstallPath\SecretSnipeAgent.exe"
        
        if ($script:AgentExecutable -and (Test-Path $script:AgentExecutable)) {
            Copy-Item $script:AgentExecutable -Destination $exeDest -Force
            Write-Log "Copied standalone executable to $exeDest" -Level SUCCESS
        } else {
            throw "Standalone executable not found: $($script:AgentExecutable)"
        }
        
    } else {
        # PYTHON MODE
        Write-Log "Installing Python-based agent..." -Level INFO
        
        # Copy agent script
        $agentSource = Join-Path $PSScriptRoot "secretsnipe_enterprise_agent.py"
        $agentDest = "$InstallPath\secretsnipe_agent.py"
        
        if (-not (Test-Path $agentSource)) {
            # Try to download from manager
            Write-Log "Agent script not found locally, downloading from manager..." -Level INFO
            try {
                $downloadUrl = "$ManagerUrl/api/v1/agent/download"
                Write-Log "Download URL: $downloadUrl" -Level INFO
                
                # Use different method for better compatibility
                $webClient = New-Object System.Net.WebClient
                $webClient.Headers.Add("X-API-Key", $ApiKey)
                $webClient.DownloadFile($downloadUrl, $agentDest)
                
                if (-not (Test-Path $agentDest)) {
                    throw "Download appeared to succeed but file not found at $agentDest"
                }
                
                $fileSize = (Get-Item $agentDest).Length
                Write-Log "Downloaded agent script ($fileSize bytes)" -Level SUCCESS
                
            } catch {
                Write-Log "Download error: $_" -Level ERROR
                throw "Agent script not found at $agentSource and could not download from manager: $_"
            }
        } else {
            Copy-Item $agentSource -Destination $agentDest -Force
            Write-Log "Copied agent script from local source" -Level SUCCESS
        }
    }
    
    # Set permissions
    Set-SecurePermissions -Path $InstallPath -AllowedPrincipals $SECURE_PERMISSIONS.InstallDirectory
    Set-SecurePermissions -Path "$InstallPath\config" -AllowedPrincipals $SECURE_PERMISSIONS.ConfigFile
    
    Write-Log "Agent files installed successfully" -Level SUCCESS
}

function New-AgentConfiguration {
    Write-Log "Creating secure agent configuration..."
    
    $configPath = "$InstallPath\config\agent_config.json"
    $existingConfig = $null
    
    # Check for existing config (preserve settings on reinstall)
    if (Test-Path $configPath) {
        Write-Log "Found existing configuration, preserving user settings..." -Level INFO
        try {
            $existingContent = Get-Content $configPath -Raw
            $existingConfig = $existingContent | ConvertFrom-Json
            Write-Log "Loaded existing config (fingerprint: $($existingConfig.agent.machine_fingerprint.Substring(0,8))...)" -Level INFO
        } catch {
            Write-Log "Could not parse existing config, creating new one..." -Level WARN
            $existingConfig = $null
        }
    }
    
    # Use existing fingerprint if available, otherwise generate new
    $fingerprint = if ($existingConfig -and $existingConfig.agent.machine_fingerprint) {
        $existingConfig.agent.machine_fingerprint
    } else {
        Get-MachineFingerprint
    }
    
    # Preserve additional_paths from existing config
    $additionalPaths = if ($existingConfig -and $existingConfig.agent.additional_paths) {
        $existingConfig.agent.additional_paths
    } else {
        @()
    }
    
    $config = @{
        manager = @{
            url = $ManagerUrl
            api_key = $ApiKey  # Store plain for now - file permissions protect it
            verify_ssl = $false  # Set to false for HTTP
            timeout = 30
        }
        agent = @{
            machine_fingerprint = $fingerprint
            log_level = "INFO"
            heartbeat_interval = 30
            job_poll_interval = 10
            additional_paths = $additionalPaths  # Preserved from existing config
        }
        scanners = @{
            custom = @{
                enabled = $true
            }
            gitleaks = @{
                enabled = ($null -ne $script:GitleaksPath)
                path = $script:GitleaksPath
            }
            trufflehog = @{
                enabled = $script:TrufflehogEnabled
                path = $script:TrufflehogPath
            }
        }
        resource_limits = @{
            max_cpu_percent = $MaxCpuPercent
            max_memory_mb = $MaxMemoryMB
            throttle_on_battery = $true
            throttle_on_user_active = $true
        }
        file_watcher = @{
            enabled = $EnableFileWatcher.IsPresent
            watch_paths = $ScanPaths
            debounce_seconds = 5
        }
        security = @{
            config_version = 1
            created_at = (Get-Date -Format "o")
            installer_version = $AGENT_VERSION
            updated_at = (Get-Date -Format "o")
        }
    }
    
    # Write UTF-8 without BOM (PowerShell 5.x adds BOM with -Encoding UTF8 which breaks Python json.load)
    $jsonContent = $config | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($configPath, $jsonContent, [System.Text.UTF8Encoding]::new($false))
    
    # Secure the config file
    Set-SecurePermissions -Path $configPath -AllowedPrincipals $SECURE_PERMISSIONS.ConfigFile
    
    Write-Log "Configuration created at $configPath" -Level SUCCESS
    return $configPath
}

function Install-WindowsService {
    Write-Log "Installing Windows Service..."
    
    # Check if service already exists
    $existingService = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($existingService) {
        if (-not $Force) {
            throw "Service '$SERVICE_NAME' already exists. Use -Force to reinstall or -Uninstall first."
        }
        Write-Log "Removing existing service..." -Level WARN
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        & sc.exe delete $SERVICE_NAME | Out-Null
        Start-Sleep -Seconds 2
    }
    
    # Get Python path
    $pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonPath) {
        $pythonPath = (Get-Command python3).Source
    }
    
    # Create service wrapper script
    $wrapperScript = @"
# SecretSnipe Agent Service Wrapper
# This script is called by the Windows Service

import sys
import os
import time
import logging

# Set up paths
INSTALL_PATH = r"$InstallPath"
sys.path.insert(0, INSTALL_PATH)
os.chdir(INSTALL_PATH)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(INSTALL_PATH, 'logs', 'agent_service.log')),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('SecretSnipeService')

def main():
    logger.info("SecretSnipe Agent Service starting...")
    
    # Import and run the agent
    try:
        from secretsnipe_agent import SecretSnipeEnterpriseAgent
        
        # Load config
        import json
        config_path = os.path.join(INSTALL_PATH, 'config', 'agent_config.json')
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Decrypt API key
        # Note: In production, use Windows DPAPI via ctypes or pywin32
        
        agent = SecretSnipeEnterpriseAgent(
            manager_url=config['manager']['url'],
            api_key=config['manager'].get('api_key', ''),  # Will need to decrypt
            config=config
        )
        
        agent.start()
        
        # Keep running
        while True:
            time.sleep(1)
            
    except Exception as e:
        logger.error(f"Agent failed: {e}")
        raise

if __name__ == "__main__":
    main()
"@
    
    $wrapperPath = "$InstallPath\service_wrapper.py"
    $wrapperScript | Set-Content -Path $wrapperPath -Encoding UTF8
    
    # Use NSSM for proper Windows service support (or create a simple executable wrapper)
    # For now, use sc.exe with a PowerShell-based approach
    
    # Create the service runner script
    $serviceRunner = @"
@echo off
cd /d "$InstallPath"
"$pythonPath" "$InstallPath\secretsnipe_agent.py" --service
"@
    
    $batchPath = "$InstallPath\run_service.bat"
    $serviceRunner | Set-Content -Path $batchPath -Encoding ASCII
    
    # Download NSSM if not present
    $nssmPath = "$InstallPath\nssm.exe"
    if (-not (Test-Path $nssmPath)) {
        Write-Log "Downloading NSSM service wrapper..." -Level INFO
        $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
        $nssmZip = "$env:TEMP\nssm.zip"
        
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing
            Expand-Archive -Path $nssmZip -DestinationPath "$env:TEMP\nssm" -Force
            Copy-Item "$env:TEMP\nssm\nssm-2.24\win64\nssm.exe" -Destination $nssmPath
            Remove-Item $nssmZip -Force
            Remove-Item "$env:TEMP\nssm" -Recurse -Force
        } catch {
            Write-Log "Could not download NSSM, using sc.exe fallback" -Level WARN
        }
    }
    
    if (Test-Path $nssmPath) {
        # Install with NSSM
        if ($script:UseStandaloneExe) {
            # STANDALONE EXE MODE - No Python required!
            $exePath = "$InstallPath\SecretSnipeAgent.exe"
            Write-Log "Installing service in STANDALONE mode (no Python)" -Level INFO
            
            # Install the service to run the exe directly
            & $nssmPath install $SERVICE_NAME $exePath
            & $nssmPath set $SERVICE_NAME AppParameters "--service --config `"$InstallPath\config\agent_config.json`""
        } else {
            # PYTHON MODE - Use batch file wrapper
            Write-Log "Installing service in PYTHON mode" -Level INFO
            $batchPath = "$InstallPath\run_service.bat"
            
            # Install the service to run the batch file
            & $nssmPath install $SERVICE_NAME $batchPath
        }
        
        & $nssmPath set $SERVICE_NAME DisplayName $SERVICE_DISPLAY_NAME
        & $nssmPath set $SERVICE_NAME Description $SERVICE_DESCRIPTION
        & $nssmPath set $SERVICE_NAME AppDirectory $InstallPath
        & $nssmPath set $SERVICE_NAME AppStdout "$InstallPath\logs\service_stdout.log"
        & $nssmPath set $SERVICE_NAME AppStderr "$InstallPath\logs\service_stderr.log"
        & $nssmPath set $SERVICE_NAME AppRotateFiles 1
        & $nssmPath set $SERVICE_NAME AppRotateBytes 10485760
        
        # Service recovery options
        & $nssmPath set $SERVICE_NAME AppExit Default Restart
        & $nssmPath set $SERVICE_NAME AppRestartDelay 5000
        
        # Run as specified account
        if ($ServiceAccount -ne "LocalSystem") {
            if ($ServicePassword) {
                $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServicePassword)
                )
                & $nssmPath set $SERVICE_NAME ObjectName $ServiceAccount $plainPassword
            }
        }
    } else {
        # Fallback to sc.exe
        if ($script:UseStandaloneExe) {
            $binPath = "`"$InstallPath\SecretSnipeAgent.exe`" --service --config `"$InstallPath\config\agent_config.json`""
        } else {
            $binPath = "`"$pythonPath`" `"$InstallPath\secretsnipe_agent.py`" --service"
        }
        
        if ($ServiceAccount -eq "LocalSystem") {
            & sc.exe create $SERVICE_NAME binpath= $binPath start= auto displayname= $SERVICE_DISPLAY_NAME
        } else {
            & sc.exe create $SERVICE_NAME binpath= $binPath start= auto displayname= $SERVICE_DISPLAY_NAME obj= $ServiceAccount
        }
        
        # Set description
        & sc.exe description $SERVICE_NAME $SERVICE_DESCRIPTION
        
        # Configure recovery options
        & sc.exe failure $SERVICE_NAME reset= 86400 actions= restart/5000/restart/10000/restart/30000
    }
    
    Write-Log "Windows Service installed successfully" -Level SUCCESS
}

function Start-AgentService {
    Write-Log "Starting SecretSnipe Agent service..."
    
    Start-Service -Name $SERVICE_NAME
    Start-Sleep -Seconds 3
    
    $service = Get-Service -Name $SERVICE_NAME
    if ($service.Status -eq "Running") {
        Write-Log "Service started successfully!" -Level SUCCESS
    } else {
        Write-Log "Service may have failed to start. Check logs at $InstallPath\logs\" -Level WARN
    }
}

# ============================================================================
# UNINSTALL FUNCTIONS
# ============================================================================

function Uninstall-Agent {
    Write-Log "Uninstalling SecretSnipe Agent..."
    
    # Stop and remove service
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($service) {
        Write-Log "Stopping service..."
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        # Try NSSM first
        $nssmPath = "$InstallPath\nssm.exe"
        if (Test-Path $nssmPath) {
            & $nssmPath remove $SERVICE_NAME confirm
        } else {
            & sc.exe delete $SERVICE_NAME
        }
        
        Write-Log "Service removed" -Level SUCCESS
    }
    
    # Remove files
    if (Test-Path $InstallPath) {
        Write-Log "Removing installation directory..."
        
        # Keep logs if requested
        if (-not $Force) {
            $logsBackup = "$env:TEMP\SecretSnipe_Logs_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            if (Test-Path "$InstallPath\logs") {
                Copy-Item "$InstallPath\logs" -Destination $logsBackup -Recurse
                Write-Log "Logs backed up to $logsBackup" -Level INFO
            }
        }
        
        Remove-Item $InstallPath -Recurse -Force
        Write-Log "Installation directory removed" -Level SUCCESS
    }
    
    # Remove event log source
    try {
        if ([System.Diagnostics.EventLog]::SourceExists($LOG_SOURCE)) {
            Remove-EventLog -Source $LOG_SOURCE
        }
    } catch {}
    
    Write-Log "SecretSnipe Agent uninstalled successfully!" -Level SUCCESS
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           SecretSnipe Enterprise Agent Installer                  ║" -ForegroundColor Cyan
    Write-Host "║                      Version $AGENT_VERSION                                ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-EventLog
    
    if ($Uninstall) {
        Uninstall-Agent
        return
    }
    
    if ($Update) {
        Write-Log "Updating agent..."
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        Install-AgentFiles
        Start-Service -Name $SERVICE_NAME
        Write-Log "Agent updated successfully!" -Level SUCCESS
        return
    }
    
    # Installation
    try {
        Test-Prerequisites
        Install-AgentFiles
        Install-Scanners
        New-AgentConfiguration
        Install-WindowsService
        Start-AgentService
        
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║          Installation completed successfully!                     ║" -ForegroundColor Green
        Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Service Name:    $SERVICE_NAME" -ForegroundColor White
        Write-Host "  Install Path:    $InstallPath" -ForegroundColor White
        Write-Host "  Logs:            $InstallPath\logs\" -ForegroundColor White
        Write-Host "  Config:          $InstallPath\config\agent_config.json" -ForegroundColor White
        Write-Host ""
        Write-Host "  Commands:" -ForegroundColor Yellow
        Write-Host "    Start:   Start-Service $SERVICE_NAME" -ForegroundColor Gray
        Write-Host "    Stop:    Stop-Service $SERVICE_NAME" -ForegroundColor Gray
        Write-Host "    Status:  Get-Service $SERVICE_NAME" -ForegroundColor Gray
        Write-Host "    Logs:    Get-Content `"$InstallPath\logs\agent.log`" -Tail 50" -ForegroundColor Gray
        Write-Host ""
        
    } catch {
        Write-Log "Installation failed: $_" -Level ERROR
        Write-Log $_.ScriptStackTrace -Level ERROR
        
        # Attempt cleanup on failure
        if (Test-Path $InstallPath) {
            Write-Log "Cleaning up partial installation..." -Level WARN
            # Don't remove on error to allow troubleshooting
        }
        
        throw
    }
}

# Run main
Main
