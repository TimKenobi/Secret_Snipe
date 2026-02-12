# SecretSnipe Enterprise Agent - Comprehensive Installer
# Run as Administrator
# This script handles: fresh install, update, cleanup, and reinstall

param(
    [Parameter(Position=0)]
    [ValidateSet("install", "update", "uninstall", "reinstall", "status", "repair")]
    [string]$Action = "install",
    
    [string]$ServerUrl = "http://10.150.110.24:8443",
    [string]$ApiKey = "",
    [switch]$Force,
    [switch]$SkipScanners
)

$ErrorActionPreference = "Continue"

# ============================================================================
# CONFIGURATION
# ============================================================================
$AgentPath = "C:\Program Files\SecretSnipe"
$LogPath = "$AgentPath\logs"
$ScannersPath = "$AgentPath\scanners"
$ServiceName = "SecretSnipe Agent"
$ServiceDisplayName = "SecretSnipe Enterprise Agent"

# Gitleaks download URL (latest release)
$GitleaksVersion = "8.18.4"
$GitleaksUrl = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion/gitleaks_${GitleaksVersion}_windows_amd64.zip"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        "INFO"    { "White" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        default   { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    
    # Also log to file if log path exists
    if (Test-Path $LogPath) {
        Add-Content -Path "$LogPath\installer.log" -Value "[$timestamp] [$Level] $Message"
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PythonPath {
    # Check common Python locations
    $pythonPaths = @(
        "python",
        "python3",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe",
        "C:\Python39\python.exe"
    )
    
    foreach ($path in $pythonPaths) {
        try {
            $result = & $path --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                if ($path -eq "python" -or $path -eq "python3") {
                    return (Get-Command $path).Source
                }
                return $path
            }
        } catch { }
    }
    return $null
}

function Install-PythonDependencies {
    param([string]$PythonPath)
    
    Write-Log "Installing Python dependencies..."
    
    # Core dependencies
    $corePackages = @(
        "requests>=2.28.0",
        "psutil>=5.9.0",
        "pywin32>=305"
    )
    
    # Detection Engine dependencies (V1 scanner parity)
    $detectionPackages = @(
        "PyMuPDF>=1.23.0",      # PDF extraction (fitz)
        "openpyxl>=3.1.0",       # Excel .xlsx support
        "xlrd>=2.0.0",           # Excel .xls support
        "python-docx>=1.0.0",    # Word document support
        "Pillow>=10.0.0"         # Image processing for OCR
    )
    
    # OCR dependencies (optional - Tesseract preferred for lower memory)
    $ocrPackages = @(
        "pytesseract>=0.3.10"    # Tesseract OCR wrapper
        # Note: Tesseract OCR engine must be installed separately on Windows
        # Download from: https://github.com/UB-Mannheim/tesseract/wiki
    )
    
    # Install core packages
    Write-Log "  Installing core packages..."
    foreach ($package in $corePackages) {
        Write-Log "    $package..."
        $result = & $PythonPath -m pip install $package --quiet 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "    Warning: Failed to install $package" -Level "WARNING"
        }
    }
    
    # Install detection engine packages
    Write-Log "  Installing detection engine packages (PDF, Excel, Word)..."
    foreach ($package in $detectionPackages) {
        Write-Log "    $package..."
        $result = & $PythonPath -m pip install $package --quiet 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "    Warning: Failed to install $package" -Level "WARNING"
        }
    }
    
    # Install OCR packages
    Write-Log "  Installing OCR packages..."
    foreach ($package in $ocrPackages) {
        Write-Log "    $package..."
        $result = & $PythonPath -m pip install $package --quiet 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "    Warning: Failed to install $package (OCR may be limited)" -Level "WARNING"
        }
    }
    
    Write-Log "Python dependencies installed" -Level "SUCCESS"
    
    # Check for Tesseract OCR installation
    $tesseractPath = "C:\Program Files\Tesseract-OCR\tesseract.exe"
    if (Test-Path $tesseractPath) {
        Write-Log "  Tesseract OCR found at $tesseractPath" -Level "SUCCESS"
    } else {
        Write-Log "  Tesseract OCR not found - OCR will be limited" -Level "WARNING"
        Write-Log "  Download from: https://github.com/UB-Mannheim/tesseract/wiki" -Level "WARNING"
    }
}

function Install-Gitleaks {
    Write-Log "Installing Gitleaks scanner..."
    
    $gitleaksExe = "$ScannersPath\gitleaks.exe"
    
    # Create scanners directory
    if (-not (Test-Path $ScannersPath)) {
        New-Item -ItemType Directory -Path $ScannersPath -Force | Out-Null
    }
    
    # Download gitleaks
    $zipPath = "$env:TEMP\gitleaks.zip"
    try {
        Write-Log "  Downloading from $GitleaksUrl..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $GitleaksUrl -OutFile $zipPath -UseBasicParsing
        
        # Extract
        Write-Log "  Extracting..."
        Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\gitleaks" -Force
        
        # Copy executable
        Copy-Item "$env:TEMP\gitleaks\gitleaks.exe" -Destination $gitleaksExe -Force
        
        # Cleanup
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\gitleaks" -Recurse -Force -ErrorAction SilentlyContinue
        
        # Verify
        $version = & $gitleaksExe version 2>&1
        Write-Log "  Gitleaks installed: $version" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "  Failed to install Gitleaks: $_" -Level "ERROR"
        return $false
    }
}

function Stop-AgentService {
    Write-Log "Stopping agent service..."
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force
            Start-Sleep -Seconds 3
            Write-Log "  Service stopped" -Level "SUCCESS"
        } else {
            Write-Log "  Service not running or doesn't exist"
        }
    } catch {
        Write-Log "  Warning: Could not stop service: $_" -Level "WARNING"
    }
}

function Start-AgentService {
    Write-Log "Starting agent service..."
    try {
        Start-Service -Name $ServiceName
        Start-Sleep -Seconds 5
        $service = Get-Service -Name $ServiceName
        if ($service.Status -eq "Running") {
            Write-Log "  Service started successfully" -Level "SUCCESS"
            return $true
        } else {
            Write-Log "  Service status: $($service.Status)" -Level "WARNING"
            return $false
        }
    } catch {
        Write-Log "  Failed to start service: $_" -Level "ERROR"
        return $false
    }
}

function Remove-AgentService {
    Write-Log "Removing agent service..."
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            Stop-AgentService
            sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 2
            Write-Log "  Service removed" -Level "SUCCESS"
        } else {
            Write-Log "  Service doesn't exist"
        }
    } catch {
        Write-Log "  Warning: Could not remove service: $_" -Level "WARNING"
    }
}

function Install-AgentService {
    param([string]$PythonPath)
    
    Write-Log "Installing agent service..."
    
    $agentScript = "$AgentPath\secretsnipe_enterprise_agent.py"
    
    if (-not (Test-Path $agentScript)) {
        Write-Log "  Agent script not found at $agentScript" -Level "ERROR"
        return $false
    }
    
    try {
        # Install the service using the agent's service install function
        $result = & $PythonPath $agentScript install 2>&1
        Start-Sleep -Seconds 2
        
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            Write-Log "  Service installed successfully" -Level "SUCCESS"
            return $true
        } else {
            Write-Log "  Service installation may have failed" -Level "WARNING"
            return $false
        }
    } catch {
        Write-Log "  Failed to install service: $_" -Level "ERROR"
        return $false
    }
}

function Download-AgentScript {
    Write-Log "Downloading agent scripts from server..."
    
    $agentScript = "$AgentPath\secretsnipe_enterprise_agent.py"
    $detectionEngine = "$AgentPath\detection_engine.py"
    $signaturesFile = "$AgentPath\signatures.json"
    $downloadUrl = "$ServerUrl/api/v1/agent/download"
    $detectionUrl = "$ServerUrl/api/v1/agent/download/detection_engine"
    $signaturesUrl = "$ServerUrl/api/v1/agent/download/signatures"
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Download main agent script
        Write-Log "  Downloading agent script..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $agentScript -UseBasicParsing
        
        if (Test-Path $agentScript) {
            $size = (Get-Item $agentScript).Length
            Write-Log "    Agent script ($size bytes)" -Level "SUCCESS"
        }
        
        # Download detection engine
        Write-Log "  Downloading detection engine..."
        try {
            Invoke-WebRequest -Uri $detectionUrl -OutFile $detectionEngine -UseBasicParsing -ErrorAction Stop
            if (Test-Path $detectionEngine) {
                $size = (Get-Item $detectionEngine).Length
                Write-Log "    Detection engine ($size bytes)" -Level "SUCCESS"
            }
        } catch {
            Write-Log "    Detection engine not available from server (will use basic scanning)" -Level "WARNING"
        }
        
        # Download signatures.json
        Write-Log "  Downloading signatures..."
        try {
            Invoke-WebRequest -Uri $signaturesUrl -OutFile $signaturesFile -UseBasicParsing -ErrorAction Stop
            if (Test-Path $signaturesFile) {
                $size = (Get-Item $signaturesFile).Length
                Write-Log "    Signatures file ($size bytes)" -Level "SUCCESS"
            }
        } catch {
            Write-Log "    Signatures file not available (will use defaults)" -Level "WARNING"
        }
        
        return $true
    } catch {
        Write-Log "  Failed to download agent scripts: $_" -Level "ERROR"
    }
    return $false
}

function Create-AgentConfig {
    Write-Log "Creating agent configuration..."
    
    $configPath = "$AgentPath\config.json"
    
    # Prompt for API key if not provided
    if (-not $ApiKey) {
        $ApiKey = Read-Host "Enter the API Key from the V2 Dashboard"
    }
    
    $config = @{
        manager = @{
            url = $ServerUrl
            api_key = $ApiKey
            verify_ssl = $false
        }
        agent = @{
            log_level = "INFO"
            heartbeat_interval = 30
            job_poll_interval = 10
        }
        scanners = @{
            custom = @{ enabled = $true }
            gitleaks = @{
                enabled = $true
                path = "$ScannersPath\gitleaks.exe"
            }
            trufflehog = @{ enabled = $true }
        }
        resource_limits = @{
            max_cpu_percent = 50
            max_memory_mb = 90
        }
    }
    
    # Write config without BOM (important!)
    $json = $config | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($configPath, $json, [System.Text.UTF8Encoding]::new($false))
    
    Write-Log "  Configuration created at $configPath" -Level "SUCCESS"
    return $true
}

function Show-Status {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   SecretSnipe Agent Status" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Service status
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        $statusColor = if ($service.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host "Service Status: $($service.Status)" -ForegroundColor $statusColor
    } else {
        Write-Host "Service Status: Not Installed" -ForegroundColor Red
    }
    
    # Installation check
    Write-Host ""
    Write-Host "Installation:" -ForegroundColor Yellow
    
    $checks = @(
        @{ Name = "Agent Directory"; Path = $AgentPath },
        @{ Name = "Agent Script"; Path = "$AgentPath\secretsnipe_enterprise_agent.py" },
        @{ Name = "Configuration"; Path = "$AgentPath\config.json" },
        @{ Name = "Logs Directory"; Path = $LogPath },
        @{ Name = "Gitleaks"; Path = "$ScannersPath\gitleaks.exe" }
    )
    
    foreach ($check in $checks) {
        $exists = Test-Path $check.Path
        $status = if ($exists) { "OK" } else { "Missing" }
        $color = if ($exists) { "Green" } else { "Red" }
        Write-Host "  $($check.Name): $status" -ForegroundColor $color
    }
    
    # Python and packages
    Write-Host ""
    Write-Host "Python Environment:" -ForegroundColor Yellow
    $pythonPath = Get-PythonPath
    if ($pythonPath) {
        $version = & $pythonPath --version 2>&1
        Write-Host "  Python: $version" -ForegroundColor Green
        
        # Check trufflehog
        $trufflehog = & $pythonPath -m pip show trufflehog3 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Trufflehog: Installed" -ForegroundColor Green
        } else {
            Write-Host "  Trufflehog: Not Installed" -ForegroundColor Red
        }
    } else {
        Write-Host "  Python: Not Found" -ForegroundColor Red
    }
    
    # Recent logs
    $logFile = "$LogPath\agent.log"
    if (Test-Path $logFile) {
        Write-Host ""
        Write-Host "Recent Logs (last 10 lines):" -ForegroundColor Yellow
        Get-Content $logFile -Tail 10 | ForEach-Object { Write-Host "  $_" }
    }
    
    Write-Host ""
}

function Cleanup-Agent {
    Write-Log "Cleaning up agent installation..."
    
    Stop-AgentService
    Remove-AgentService
    
    # Remove files but keep config and logs if they exist (for reinstall)
    $filesToRemove = @(
        "$AgentPath\secretsnipe_enterprise_agent.py",
        "$ScannersPath\gitleaks.exe"
    )
    
    foreach ($file in $filesToRemove) {
        if (Test-Path $file) {
            Remove-Item $file -Force
            Write-Log "  Removed $file"
        }
    }
    
    Write-Log "Cleanup complete" -Level "SUCCESS"
}

function Full-Uninstall {
    Write-Log "Performing full uninstall..."
    
    Stop-AgentService
    Remove-AgentService
    
    # Confirm deletion
    if (-not $Force) {
        $confirm = Read-Host "This will delete all agent files including logs. Continue? (y/N)"
        if ($confirm -ne "y" -and $confirm -ne "Y") {
            Write-Log "Uninstall cancelled"
            return
        }
    }
    
    # Remove entire directory
    if (Test-Path $AgentPath) {
        Remove-Item $AgentPath -Recurse -Force
        Write-Log "  Removed $AgentPath"
    }
    
    Write-Log "Uninstall complete" -Level "SUCCESS"
}

# ============================================================================
# MAIN INSTALLATION FUNCTION
# ============================================================================

function Install-Agent {
    param([switch]$IsReinstall)
    
    $actionName = if ($IsReinstall) { "Reinstalling" } else { "Installing" }
    
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   SecretSnipe Agent Installer" -ForegroundColor Cyan
    Write-Host "   $actionName Agent..." -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Step 1: Check prerequisites
    Write-Log "Step 1: Checking prerequisites..."
    
    $pythonPath = Get-PythonPath
    if (-not $pythonPath) {
        Write-Log "Python not found! Please install Python 3.9+ first." -Level "ERROR"
        Write-Log "Download from: https://www.python.org/downloads/" -Level "ERROR"
        return $false
    }
    Write-Log "  Python found: $pythonPath" -Level "SUCCESS"
    
    # Step 2: Create directories
    Write-Log "Step 2: Creating directories..."
    
    $directories = @($AgentPath, $LogPath, $ScannersPath)
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Log "  Created $dir"
        }
    }
    
    # Step 3: Stop existing service if running
    Write-Log "Step 3: Checking existing service..."
    Stop-AgentService
    
    # Step 4: Download agent script
    Write-Log "Step 4: Downloading agent..."
    if (-not (Download-AgentScript)) {
        Write-Log "Failed to download agent script" -Level "ERROR"
        return $false
    }
    
    # Step 5: Install Python dependencies
    Write-Log "Step 5: Installing Python dependencies..."
    Install-PythonDependencies -PythonPath $pythonPath
    
    # Step 6: Install scanners
    if (-not $SkipScanners) {
        Write-Log "Step 6: Installing scanners..."
        Install-Gitleaks
    } else {
        Write-Log "Step 6: Skipping scanner installation (--SkipScanners)"
    }
    
    # Step 7: Create config if needed
    Write-Log "Step 7: Checking configuration..."
    $configPath = "$AgentPath\config.json"
    if (-not (Test-Path $configPath) -or $IsReinstall) {
        Create-AgentConfig
    } else {
        Write-Log "  Using existing configuration"
    }
    
    # Step 8: Install and start service
    Write-Log "Step 8: Installing service..."
    
    # First remove existing service if any
    Remove-AgentService
    
    # Install new service
    if (Install-AgentService -PythonPath $pythonPath) {
        # Start the service
        Start-AgentService
    } else {
        Write-Log "Failed to install service" -Level "ERROR"
        return $false
    }
    
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   Installation Complete!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Check agent status: .\install_agent.ps1 status"
    Write-Host "2. View logs: Get-Content '$LogPath\agent.log' -Tail 50 -Wait"
    Write-Host "3. Create a scan job from the V2 Dashboard"
    Write-Host ""
    
    return $true
}

function Update-Agent {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   Updating SecretSnipe Agent" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Stop service
    Stop-AgentService
    
    # Download new agent
    if (-not (Download-AgentScript)) {
        Write-Log "Failed to download agent script" -Level "ERROR"
        return $false
    }
    
    # Update Python deps
    $pythonPath = Get-PythonPath
    if ($pythonPath) {
        Install-PythonDependencies -PythonPath $pythonPath
    }
    
    # Update gitleaks if needed
    if (-not $SkipScanners) {
        $gitleaksExe = "$ScannersPath\gitleaks.exe"
        if (-not (Test-Path $gitleaksExe)) {
            Install-Gitleaks
        }
    }
    
    # Start service
    Start-AgentService
    
    Write-Log "Update complete!" -Level "SUCCESS"
    return $true
}

function Repair-Agent {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   Repairing SecretSnipe Agent" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Stop service
    Stop-AgentService
    
    # Fix Python dependencies
    $pythonPath = Get-PythonPath
    if ($pythonPath) {
        Write-Log "Reinstalling Python dependencies..."
        & $pythonPath -m pip install --upgrade --force-reinstall requests psutil pywin32 trufflehog3 2>&1 | Out-Null
    }
    
    # Reinstall gitleaks
    Write-Log "Reinstalling Gitleaks..."
    Install-Gitleaks
    
    # Fix permissions
    Write-Log "Fixing permissions..."
    icacls $AgentPath /grant "Everyone:(OI)(CI)F" /T | Out-Null
    
    # Download fresh agent script
    Download-AgentScript
    
    # Reinstall service
    Remove-AgentService
    Start-Sleep -Seconds 2
    
    if ($pythonPath) {
        Install-AgentService -PythonPath $pythonPath
        Start-AgentService
    }
    
    Write-Log "Repair complete!" -Level "SUCCESS"
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

# Check admin rights
if (-not (Test-Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Execute requested action
switch ($Action) {
    "install" {
        Install-Agent
    }
    "update" {
        Update-Agent
    }
    "uninstall" {
        Full-Uninstall
    }
    "reinstall" {
        Cleanup-Agent
        Install-Agent -IsReinstall
    }
    "status" {
        Show-Status
    }
    "repair" {
        Repair-Agent
    }
}
