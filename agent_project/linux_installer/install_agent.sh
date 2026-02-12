#!/bin/bash
# ============================================================================
# SecretSnipe Enterprise Agent - Linux Installer
# Supports: Ubuntu/Debian, RHEL/CentOS/Fedora, SUSE
# Run as root or with sudo
# ============================================================================

set -e

# Configuration
AGENT_PATH="/opt/secretsnipe"
LOG_PATH="${AGENT_PATH}/logs"
CONFIG_PATH="${AGENT_PATH}/config.json"
SERVICE_NAME="secretsnipe-agent"
SERVER_URL="${SS_SERVER_URL:-http://10.150.110.24:8443}"
API_KEY="${SS_API_KEY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_info() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
}

log_success() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    else
        OS="unknown"
    fi
    log_info "Detected OS: $OS $OS_VERSION"
}

# ============================================================================
# PACKAGE INSTALLATION
# ============================================================================

install_system_packages() {
    log_info "Installing system packages..."
    
    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq python3 python3-pip python3-venv \
                tesseract-ocr tesseract-ocr-eng \
                curl wget git
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &> /dev/null; then
                dnf install -y python3 python3-pip \
                    tesseract tesseract-langpack-eng \
                    curl wget git
            else
                yum install -y python3 python3-pip \
                    tesseract tesseract-langpack-eng \
                    curl wget git
            fi
            ;;
        opensuse*|sles)
            zypper install -y python3 python3-pip \
                tesseract-ocr tesseract-ocr-traineddata-eng \
                curl wget git
            ;;
        *)
            log_warning "Unknown OS - attempting generic package install"
            if command -v apt-get &> /dev/null; then
                apt-get update && apt-get install -y python3 python3-pip
            elif command -v yum &> /dev/null; then
                yum install -y python3 python3-pip
            fi
            ;;
    esac
    
    log_success "System packages installed"
}

install_python_packages() {
    log_info "Installing Python packages..."
    
    # Core packages
    pip3 install --quiet \
        requests>=2.28.0 \
        psutil>=5.9.0
    
    # Detection engine packages
    pip3 install --quiet \
        PyMuPDF>=1.23.0 \
        openpyxl>=3.1.0 \
        xlrd>=2.0.0 \
        python-docx>=1.0.0 \
        Pillow>=10.0.0 \
        pytesseract>=0.3.10
    
    log_success "Python packages installed"
}

install_gitleaks() {
    log_info "Installing Gitleaks..."
    
    GITLEAKS_VERSION="8.18.4"
    ARCH=$(uname -m)
    
    case $ARCH in
        x86_64|amd64) GITLEAKS_ARCH="linux_amd64" ;;
        aarch64|arm64) GITLEAKS_ARCH="linux_arm64" ;;
        *) 
            log_warning "Unsupported architecture for Gitleaks: $ARCH"
            return 1
            ;;
    esac
    
    GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz"
    
    mkdir -p ${AGENT_PATH}/scanners
    cd /tmp
    curl -sL $GITLEAKS_URL -o gitleaks.tar.gz
    tar -xzf gitleaks.tar.gz
    mv gitleaks ${AGENT_PATH}/scanners/gitleaks
    chmod +x ${AGENT_PATH}/scanners/gitleaks
    rm -f gitleaks.tar.gz
    
    VERSION=$(${AGENT_PATH}/scanners/gitleaks version 2>&1 || echo "installed")
    log_success "Gitleaks installed: $VERSION"
}

# ============================================================================
# AGENT INSTALLATION
# ============================================================================

download_agent() {
    log_info "Downloading agent scripts from ${SERVER_URL}..."
    
    mkdir -p ${AGENT_PATH}
    mkdir -p ${LOG_PATH}
    
    # Download main agent script
    curl -sL "${SERVER_URL}/api/v1/agent/download" -o ${AGENT_PATH}/secretsnipe_agent.py
    if [ $? -eq 0 ] && [ -f ${AGENT_PATH}/secretsnipe_agent.py ]; then
        SIZE=$(stat -c %s ${AGENT_PATH}/secretsnipe_agent.py 2>/dev/null || stat -f %z ${AGENT_PATH}/secretsnipe_agent.py)
        log_success "Agent script downloaded (${SIZE} bytes)"
    else
        log_error "Failed to download agent script"
        return 1
    fi
    
    # Download detection engine
    curl -sL "${SERVER_URL}/api/v1/agent/download/detection_engine" -o ${AGENT_PATH}/detection_engine.py 2>/dev/null || true
    if [ -f ${AGENT_PATH}/detection_engine.py ] && [ -s ${AGENT_PATH}/detection_engine.py ]; then
        log_success "Detection engine downloaded"
    else
        log_warning "Detection engine not available (basic scanning only)"
        rm -f ${AGENT_PATH}/detection_engine.py
    fi
    
    # Download signatures
    curl -sL "${SERVER_URL}/api/v1/agent/download/signatures" -o ${AGENT_PATH}/signatures.json 2>/dev/null || true
    if [ -f ${AGENT_PATH}/signatures.json ] && [ -s ${AGENT_PATH}/signatures.json ]; then
        log_success "Signatures file downloaded"
    else
        log_warning "Signatures file not available (using defaults)"
        rm -f ${AGENT_PATH}/signatures.json
    fi
}

create_config() {
    log_info "Creating agent configuration..."
    
    # Prompt for API key if not provided
    if [ -z "$API_KEY" ]; then
        read -p "Enter API Key from V2 Dashboard: " API_KEY
    fi
    
    cat > ${CONFIG_PATH} << EOF
{
    "manager": {
        "url": "${SERVER_URL}",
        "api_key": "${API_KEY}",
        "verify_ssl": false
    },
    "agent": {
        "log_level": "INFO",
        "heartbeat_interval": 30,
        "job_poll_interval": 10
    },
    "scanners": {
        "custom": { "enabled": true },
        "gitleaks": {
            "enabled": true,
            "path": "${AGENT_PATH}/scanners/gitleaks"
        }
    },
    "resource_limits": {
        "max_cpu_percent": 50,
        "max_memory_percent": 80
    }
}
EOF
    
    chmod 600 ${CONFIG_PATH}
    log_success "Configuration created at ${CONFIG_PATH}"
}

create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=SecretSnipe Enterprise Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${AGENT_PATH}
ExecStart=/usr/bin/python3 ${AGENT_PATH}/secretsnipe_agent.py run
Restart=always
RestartSec=10
StandardOutput=append:${LOG_PATH}/agent.log
StandardError=append:${LOG_PATH}/agent.log

# Resource limits
CPUQuota=50%
MemoryLimit=2G

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_success "Systemd service created"
}

start_service() {
    log_info "Starting agent service..."
    
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
    
    sleep 3
    
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        log_success "Agent service started successfully"
        systemctl status ${SERVICE_NAME} --no-pager
    else
        log_error "Failed to start agent service"
        journalctl -u ${SERVICE_NAME} --no-pager -n 20
        return 1
    fi
}

stop_service() {
    log_info "Stopping agent service..."
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    systemctl disable ${SERVICE_NAME} 2>/dev/null || true
    log_success "Agent service stopped"
}

remove_service() {
    log_info "Removing agent service..."
    stop_service
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload
    log_success "Service removed"
}

show_status() {
    echo ""
    echo "============================================"
    echo "   SecretSnipe Agent Status"
    echo "============================================"
    echo ""
    
    # Agent installation
    if [ -f ${AGENT_PATH}/secretsnipe_agent.py ]; then
        VERSION=$(grep -oP 'AGENT_VERSION\s*=\s*"\K[^"]+' ${AGENT_PATH}/secretsnipe_agent.py 2>/dev/null || echo "unknown")
        echo "Agent Version: $VERSION"
        echo "Install Path:  ${AGENT_PATH}"
    else
        echo "Agent: NOT INSTALLED"
    fi
    
    # Detection engine
    if [ -f ${AGENT_PATH}/detection_engine.py ]; then
        echo "Detection Engine: INSTALLED"
    else
        echo "Detection Engine: NOT INSTALLED (basic scanning only)"
    fi
    
    # Gitleaks
    if [ -x ${AGENT_PATH}/scanners/gitleaks ]; then
        GL_VER=$(${AGENT_PATH}/scanners/gitleaks version 2>&1 || echo "unknown")
        echo "Gitleaks: $GL_VER"
    else
        echo "Gitleaks: NOT INSTALLED"
    fi
    
    # Tesseract OCR
    if command -v tesseract &> /dev/null; then
        TESS_VER=$(tesseract --version 2>&1 | head -1)
        echo "Tesseract: $TESS_VER"
    else
        echo "Tesseract: NOT INSTALLED (OCR disabled)"
    fi
    
    # Service status
    echo ""
    if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
        echo "Service Status: RUNNING"
    else
        echo "Service Status: STOPPED"
    fi
    
    # Config
    if [ -f ${CONFIG_PATH} ]; then
        echo "Config: ${CONFIG_PATH}"
    fi
    
    echo ""
}

uninstall() {
    log_info "Uninstalling SecretSnipe Agent..."
    
    stop_service
    remove_service
    
    if [ -d ${AGENT_PATH} ]; then
        rm -rf ${AGENT_PATH}
        log_success "Agent files removed"
    fi
    
    log_success "SecretSnipe Agent uninstalled"
}

# ============================================================================
# MAIN
# ============================================================================

usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install    Install the SecretSnipe agent (default)"
    echo "  update     Update agent to latest version"
    echo "  uninstall  Remove the agent completely"
    echo "  status     Show agent status"
    echo "  restart    Restart the agent service"
    echo ""
    echo "Environment variables:"
    echo "  SS_SERVER_URL  Manager server URL (default: http://10.150.110.24:8443)"
    echo "  SS_API_KEY     API key for agent registration"
    echo ""
    echo "Example:"
    echo "  sudo SS_API_KEY='your-api-key' $0 install"
    echo ""
}

main() {
    ACTION=${1:-install}
    
    case $ACTION in
        install)
            check_root
            detect_os
            log_info "Installing SecretSnipe Enterprise Agent..."
            install_system_packages
            install_python_packages
            install_gitleaks
            download_agent
            create_config
            create_systemd_service
            start_service
            log_success "SecretSnipe Agent installation complete!"
            show_status
            ;;
        update)
            check_root
            log_info "Updating SecretSnipe Agent..."
            stop_service
            download_agent
            install_python_packages
            start_service
            log_success "Agent updated successfully"
            show_status
            ;;
        uninstall)
            check_root
            uninstall
            ;;
        status)
            show_status
            ;;
        restart)
            check_root
            stop_service
            start_service
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $ACTION"
            usage
            exit 1
            ;;
    esac
}

main "$@"
