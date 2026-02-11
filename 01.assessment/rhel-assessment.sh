#!/bin/bash

SCRIPT_VERSION="1.0.3"

################################################################################
# RHEL Server Assessment Script
# Version: 1.0.3
# Purpose: Assess RHEL/Rocky Linux servers and generate remediation plans
#
# Change Log:
# - 1.0.3: Further enhanced non-systemd process detection
#   * Captures PID, owner, full command line, and working directory (CWD)
#   * Improved systemd management detection using cgroups
#   * Reports all matching PIDs for monitored process names
# - 1.0.2: Enhanced application detection
#   * Oracle detection now includes running processes (ora_pmon_*)
#   * Non-systemd processes now show executable paths
#   * JDK detection: Dynamic /u0* scanning, running process detection, duplicate prevention
#   * Tomcat detection: Dynamic /u0* scanning, catalina.home extraction from processes
#   * Increased search depth (maxdepth 5) for nested installations
# - 1.0.1: Added list of non-systemd managed processes to markdown report
# - 1.0.0: Initial script development and testing
################################################################################

set -u  # Catch undefined variables
# DO NOT use set -e - script must continue on individual check failures

################################################################################
# GLOBAL VARIABLES
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(dirname "$SCRIPT_DIR")"
LOGS_DIR="$WORKSPACE_DIR/logs"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOGS_DIR/01-assessment-$TIMESTAMP.log"
JSON_FILE="$LOGS_DIR/01-assessment-$TIMESTAMP.json"
PREVIOUS_JSON="$LOGS_DIR/latest-assessment.json"
MD_FILE="$WORKSPACE_DIR/01-assessment.md"

# Track if we're using sudo
USE_SUDO=""

# Failed checks counter
FAILED_CHECKS=0

# Declare associative arrays for data collection
declare -A SYSTEM_INFO
declare -A OS_INFO
declare -A HARDWARE_INFO
declare -A TIME_SYNC
declare -A SECURITY_SSH
declare -A SECURITY_SELINUX
declare -A SECURITY_FIREWALL
declare -A SUBSCRIPTION_INFO
declare -A SYSTEMD_INFO
declare -A NETWORK_INFO

# Regular arrays
declare -a FILESYSTEMS
declare -a LISTENING_PORTS
declare -a SECURITY_UPDATES
declare -a UNWANTED_PACKAGES
declare -a JDK_INSTALLATIONS
declare -a TOMCAT_INSTALLATIONS
declare -a ORACLE_HOMES
declare -a WEB_SERVERS
declare -a BANNER_COMPONENTS
declare -a MONITORING_AGENTS
declare -a REMEDIATION_ITEMS
declare -a FAILED_SERVICES
declare -a NON_SYSTEMD_PROCESSES
declare -a CERTIFICATES
declare -a ENABLED_REPOS
declare -a THIRD_PARTY_REPOS
declare -a ORPHANED_PACKAGES

################################################################################
# LOGGING FUNCTIONS
################################################################################

# Initialize logging
init_logging() {
    mkdir -p "$LOGS_DIR"

    # Print header to both stdout and log
    {
        echo "=================================================="
        echo "Server Remediation Assessment Script"
        echo "Version: $SCRIPT_VERSION"
        echo "=================================================="
        echo "Execution Time: $(date)"
        echo "Current User: $(whoami)"
        echo "Log File: $LOG_FILE"
        echo "=================================================="
    } | tee "$LOG_FILE"
}

# Log message with level
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $level: $message" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
}

log_warn() {
    log "WARN" "$@"
}

log_error() {
    log "ERROR" "$@"
    ((FAILED_CHECKS++))
}

log_debug() {
    log "DEBUG" "$@"
}

################################################################################
# PRIVILEGE CHECKING
################################################################################

check_privileges() {
    log_info "Checking privileges..."

    if [[ $EUID -eq 0 ]]; then
        log_info "Running as root: OK"
        USE_SUDO=""
        return 0
    fi

    # Check if sudo is available
    if sudo -n true 2>/dev/null; then
        log_info "Running with sudo privileges: OK"
        USE_SUDO="sudo"
        return 0
    fi

    log_error "This script requires root privileges or sudo access"
    log_error "Please run as root or with sudo privileges"
    exit 1
}

# Helper function to run commands with sudo if needed
run_privileged() {
    if [[ -n "$USE_SUDO" ]]; then
        sudo "$@"
    else
        "$@"
    fi
}

################################################################################
# PHASE 1: SYSTEM IDENTIFICATION
################################################################################

phase1_system_identification() {
    log_info "=== Phase 1: System Identification ==="

    # OS Detection
    log_info "Detecting operating system..."
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_INFO[name]="${NAME:-Unknown}"
        OS_INFO[version]="${VERSION_ID:-Unknown}"
        OS_INFO[id]="${ID:-Unknown}"
        OS_INFO[pretty_name]="${PRETTY_NAME:-Unknown}"
        log_info "Detected OS: ${OS_INFO[name]} ${OS_INFO[version]}"
    else
        OS_INFO[name]="Unknown"
        OS_INFO[version]="Unknown"
        OS_INFO[id]="Unknown"
        log_warn "Could not detect OS from /etc/os-release"
    fi

    # Kernel version
    OS_INFO[kernel]=$(uname -r)
    log_info "Kernel: ${OS_INFO[kernel]}"

    # Architecture
    OS_INFO[architecture]=$(uname -m)
    log_info "Architecture: ${OS_INFO[architecture]}"

    # Package manager detection
    if command -v dnf &>/dev/null; then
        OS_INFO[pkg_manager]="dnf"
    elif command -v yum &>/dev/null; then
        OS_INFO[pkg_manager]="yum"
    elif command -v apt &>/dev/null; then
        OS_INFO[pkg_manager]="apt"
    else
        OS_INFO[pkg_manager]="unknown"
    fi
    log_info "Package manager: ${OS_INFO[pkg_manager]}"

    # Hardware Information
    log_info "Collecting hardware information..."

    # CPU
    HARDWARE_INFO[cpu_count]=$(grep -c ^processor /proc/cpuinfo)
    HARDWARE_INFO[cpu_model]=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
    log_info "CPU: ${HARDWARE_INFO[cpu_count]} x ${HARDWARE_INFO[cpu_model]}"

    # Memory
    local mem_total_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_available_kb=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    HARDWARE_INFO[memory_total_gb]=$(echo "scale=2; $mem_total_kb / 1024 / 1024" | bc)
    HARDWARE_INFO[memory_available_gb]=$(echo "scale=2; $mem_available_kb / 1024 / 1024" | bc)
    log_info "Memory: ${HARDWARE_INFO[memory_total_gb]} GB total, ${HARDWARE_INFO[memory_available_gb]} GB available"

    # Swap
    local swap_total_kb=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
    HARDWARE_INFO[swap_size_gb]=$(echo "scale=2; $swap_total_kb / 1024 / 1024" | bc)
    log_info "Swap: ${HARDWARE_INFO[swap_size_gb]} GB"

    # Virtualization detection
    if command -v systemd-detect-virt &>/dev/null; then
        HARDWARE_INFO[virtualization]=$(systemd-detect-virt)
    elif [[ -f /sys/hypervisor/type ]]; then
        HARDWARE_INFO[virtualization]=$(cat /sys/hypervisor/type)
    elif grep -q "hypervisor" /proc/cpuinfo; then
        HARDWARE_INFO[virtualization]="yes"
    else
        HARDWARE_INFO[virtualization]="none"
    fi
    log_info "Virtualization: ${HARDWARE_INFO[virtualization]}"

    # System State
    log_info "Collecting system state..."

    # Uptime
    SYSTEM_INFO[uptime_seconds]=$(awk '{print int($1)}' /proc/uptime)
    local uptime_human=$(uptime -p 2>/dev/null || echo "unknown")
    SYSTEM_INFO[uptime_human]="$uptime_human"
    log_info "Uptime: $uptime_human"

    # Load average
    read -r load1 load5 load15 _ < /proc/loadavg
    SYSTEM_INFO[load_1]=$load1
    SYSTEM_INFO[load_5]=$load5
    SYSTEM_INFO[load_15]=$load15
    log_info "Load average: $load1, $load5, $load15"

    # Reboot required check
    SYSTEM_INFO[reboot_required]="false"
    if [[ -f /var/run/reboot-required ]]; then
        SYSTEM_INFO[reboot_required]="true"
        log_warn "Reboot required"
    elif command -v needs-restarting &>/dev/null; then
        if needs-restarting -r &>/dev/null; then
            SYSTEM_INFO[reboot_required]="false"
        else
            SYSTEM_INFO[reboot_required]="true"
            log_warn "Reboot required (needs-restarting)"
        fi
    fi

    # Hostname
    SYSTEM_INFO[hostname]=$(hostname -f 2>/dev/null || hostname)
    log_info "Hostname: ${SYSTEM_INFO[hostname]}"
}

################################################################################
# PHASE 2: STORAGE ASSESSMENT
################################################################################

phase2_storage_assessment() {
    log_info "=== Phase 2: Storage Assessment ==="

    log_info "Checking disk space..."

    # Parse df output
    while IFS= read -r line; do
        local mount_point size used avail use_pct
        read -r _ size used avail use_pct mount_point <<< "$line"

        # Remove % from use_pct
        use_pct=${use_pct%\%}

        # Convert sizes to GB for important mount points
        local size_gb=$(echo "$size" | numfmt --from=auto --to=none 2>/dev/null | awk '{print int($1/1024/1024/1024)}')
        local used_gb=$(echo "$used" | numfmt --from=auto --to=none 2>/dev/null | awk '{print int($1/1024/1024/1024)}')
        local avail_gb=$(echo "$avail" | numfmt --from=auto --to=none 2>/dev/null | awk '{print int($1/1024/1024/1024)}')

        FILESYSTEMS+=("{\"mount_point\":\"$mount_point\",\"size_gb\":$size_gb,\"used_gb\":$used_gb,\"available_gb\":$avail_gb,\"use_percent\":$use_pct}")

        if [[ $use_pct -ge 90 ]]; then
            log_error "CRITICAL: $mount_point is ${use_pct}% full"
        elif [[ $use_pct -ge 80 ]]; then
            log_warn "WARNING: $mount_point is ${use_pct}% full"
        else
            log_info "Free space in $mount_point: ${avail_gb}GB (${use_pct}% used)"
        fi
    done < <(df -h | grep -E '^/dev/' | awk '{print $0}')

    # LVM check
    if command -v vgs &>/dev/null; then
        if run_privileged vgs &>/dev/null; then
            log_info "LVM detected and active"
            SYSTEM_INFO[lvm_present]="true"
        else
            SYSTEM_INFO[lvm_present]="false"
        fi
    else
        SYSTEM_INFO[lvm_present]="false"
    fi

    # RAID check
    if [[ -f /proc/mdstat ]]; then
        if grep -q "active" /proc/mdstat 2>/dev/null; then
            log_info "Software RAID detected"
            SYSTEM_INFO[raid_present]="true"
        else
            SYSTEM_INFO[raid_present]="false"
        fi
    else
        SYSTEM_INFO[raid_present]="false"
    fi

    # Check for NFS mounts
    log_info "Checking for NFS/CIFS mounts..."
    local nfs_count=$(mount | grep "type nfs" | wc -l)
    local cifs_count=$(mount | grep "type cifs" | wc -l)
    if [[ $nfs_count -gt 0 ]] || [[ $cifs_count -gt 0 ]]; then
        log_info "Remote mounts: $nfs_count NFS, $cifs_count CIFS"
    fi
}

################################################################################
# PHASE 3: NETWORK ASSESSMENT
################################################################################

phase3_network_assessment() {
    log_info "=== Phase 3: Network Assessment ==="

    # DNS check
    log_info "Checking DNS resolution..."
    if nslookup redhat.com &>/dev/null || host redhat.com &>/dev/null; then
        NETWORK_INFO[dns_working]="true"
        log_info "DNS resolution: OK"
    else
        NETWORK_INFO[dns_working]="false"
        log_error "DNS resolution: FAILED"
    fi

    # Internet connectivity check
    log_info "Checking internet connectivity..."
    local http_code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 https://redhat.com 2>/dev/null || echo "000")
    if [[ "$http_code" =~ ^(200|301|302)$ ]]; then
        NETWORK_INFO[internet_working]="true"
        log_info "Internet connectivity: OK"
    else
        NETWORK_INFO[internet_working]="false"
        log_warn "Internet connectivity: Issues detected (HTTP $http_code)"
    fi

    # Gateway check
    local gateway=$(ip route | grep default | awk '{print $3}' | head -1)
    if [[ -n "$gateway" ]]; then
        NETWORK_INFO[gateway_ip]="$gateway"
        log_info "Default gateway: $gateway"
    else
        NETWORK_INFO[gateway_ip]="none"
        log_warn "No default gateway found"
    fi

    # Network interfaces
    log_info "Checking network interfaces..."
    local interface_count=0
    while IFS= read -r line; do
        ((interface_count++))
    done < <(ip -br addr | grep -v "^lo" | grep "UP")
    log_info "Active network interfaces: $interface_count"

    # Listening ports
    log_info "Checking listening ports..."
    if command -v ss &>/dev/null; then
        while IFS= read -r line; do
            local port=$(echo "$line" | awk '{print $5}' | sed 's/.*://')
            local process=$(echo "$line" | awk -F'"' '{print $2}')
            LISTENING_PORTS+=("{\"port\":$port,\"protocol\":\"tcp\",\"process\":\"$process\"}")
        done < <(run_privileged ss -tlnp 2>/dev/null | grep LISTEN | head -20)
        log_info "Found ${#LISTENING_PORTS[@]} listening ports"
    elif command -v netstat &>/dev/null; then
        while IFS= read -r line; do
            local port=$(echo "$line" | awk '{print $4}' | sed 's/.*://')
            local process=$(echo "$line" | awk '{print $7}' | cut -d'/' -f2)
            LISTENING_PORTS+=("{\"port\":$port,\"protocol\":\"tcp\",\"process\":\"$process\"}")
        done < <(run_privileged netstat -tlnp 2>/dev/null | grep LISTEN | head -20)
        log_info "Found ${#LISTENING_PORTS[@]} listening ports"
    fi
}

################################################################################
# PHASE 4: TIME AND DATE
################################################################################

phase4_time_and_date() {
    log_info "=== Phase 4: Time and Date ==="

    # Check time sync service
    log_info "Checking time synchronization..."

    if systemctl is-active chronyd &>/dev/null; then
        TIME_SYNC[service]="chronyd"
        TIME_SYNC[status]="active"
        if chronyc tracking &>/dev/null; then
            TIME_SYNC[synchronized]="true"
            log_info "Time sync (chrony): OK"
        else
            TIME_SYNC[synchronized]="false"
            log_warn "Chrony service active but not synchronized"
        fi
    elif systemctl is-active ntpd &>/dev/null; then
        TIME_SYNC[service]="ntpd"
        TIME_SYNC[status]="active"
        if ntpq -p &>/dev/null; then
            TIME_SYNC[synchronized]="true"
            log_info "Time sync (ntpd): OK"
        else
            TIME_SYNC[synchronized]="false"
            log_warn "NTP service active but not synchronized"
        fi
    elif systemctl is-active systemd-timesyncd &>/dev/null; then
        TIME_SYNC[service]="systemd-timesyncd"
        TIME_SYNC[status]="active"
        TIME_SYNC[synchronized]="true"
        log_info "Time sync (systemd-timesyncd): OK"
    else
        TIME_SYNC[service]="none"
        TIME_SYNC[status]="inactive"
        TIME_SYNC[synchronized]="false"
        log_error "No time synchronization service detected"
    fi

    # Timezone
    if command -v timedatectl &>/dev/null; then
        TIME_SYNC[timezone]=$(timedatectl | grep "Time zone" | awk '{print $3}')
        log_info "Timezone: ${TIME_SYNC[timezone]}"
    else
        TIME_SYNC[timezone]="unknown"
    fi
}

################################################################################
# PHASE 5: OS SUPPORT AND LIFECYCLE
################################################################################

phase5_os_lifecycle() {
    log_info "=== Phase 5: OS Support and Lifecycle ==="

    # Calculate EOL date based on OS
    local os_major_version="${OS_INFO[version]%%.*}"
    local eol_date=""
    local extended_eol_date=""

    case "${OS_INFO[id]}" in
        rhel)
            case "$os_major_version" in
                7)
                    eol_date="2024-06-30"
                    extended_eol_date="2028-06-30"
                    ;;
                8)
                    eol_date="2029-05-31"
                    extended_eol_date="2032-05-31"
                    ;;
                9)
                    eol_date="2032-05-31"
                    extended_eol_date="2035-05-31"
                    ;;
                *)
                    eol_date="unknown"
                    ;;
            esac
            ;;
        rocky|ol)
            # Rocky and Oracle Linux follow similar lifecycle to RHEL
            case "$os_major_version" in
                7) eol_date="2024-06-30" ;;
                8) eol_date="2029-05-31" ;;
                9) eol_date="2032-05-31" ;;
                *) eol_date="unknown" ;;
            esac
            ;;
        *)
            eol_date="unknown"
            ;;
    esac

    OS_INFO[eol_date]="$eol_date"
    OS_INFO[extended_eol_date]="${extended_eol_date:-none}"

    if [[ "$eol_date" != "unknown" ]]; then
        local eol_epoch=$(date -d "$eol_date" +%s)
        local now_epoch=$(date +%s)
        local days_until_eol=$(( (eol_epoch - now_epoch) / 86400 ))

        OS_INFO[days_until_eol]=$days_until_eol

        if [[ $days_until_eol -lt 0 ]]; then
            OS_INFO[is_eol]="true"
            log_error "OS is PAST END OF LIFE (EOL: $eol_date)"
        elif [[ $days_until_eol -lt 180 ]]; then
            OS_INFO[is_eol]="false"
            log_warn "OS approaching EOL in $days_until_eol days (EOL: $eol_date)"
        else
            OS_INFO[is_eol]="false"
            log_info "OS version is supported ($days_until_eol days until EOL)"
        fi
    else
        OS_INFO[days_until_eol]="-1"
        OS_INFO[is_eol]="unknown"
        log_warn "Could not determine OS EOL status"
    fi

    # Kernel status
    log_info "Checking kernel status..."
    OS_INFO[current_kernel]="${OS_INFO[kernel]}"

    if [[ "${OS_INFO[pkg_manager]}" == "dnf" ]] || [[ "${OS_INFO[pkg_manager]}" == "yum" ]]; then
        local latest_kernel=$(${OS_INFO[pkg_manager]} list available kernel 2>/dev/null | grep "^kernel" | tail -1 | awk '{print $2}')
        if [[ -n "$latest_kernel" ]]; then
            OS_INFO[latest_kernel]="$latest_kernel"
            if [[ "${OS_INFO[kernel]}" != *"$latest_kernel"* ]]; then
                OS_INFO[kernel_update_available]="true"
                log_warn "Kernel update available: $latest_kernel"
            else
                OS_INFO[kernel_update_available]="false"
                log_info "Kernel is up to date"
            fi
        fi
    fi
}

################################################################################
# PHASE 6: PACKAGE MANAGEMENT
################################################################################

phase6_package_management() {
    log_info "=== Phase 6: Package Management ==="

    # RHEL Subscription check
    if [[ "${OS_INFO[id]}" == "rhel" ]]; then
        log_info "Checking RHEL subscription status..."
        if command -v subscription-manager &>/dev/null; then
            if subscription-manager status &>/dev/null; then
                SUBSCRIPTION_INFO[registered]="true"
                SUBSCRIPTION_INFO[status]="Current"
                log_info "RHEL subscription: Registered"

                # Get subscription details
                local sub_info=$(subscription-manager list --consumed 2>/dev/null | head -20)
                if [[ -n "$sub_info" ]]; then
                    log_info "Subscription details collected"
                fi
            else
                SUBSCRIPTION_INFO[registered]="false"
                SUBSCRIPTION_INFO[status]="Not registered"
                log_error "RHEL system is not registered with subscription manager"
            fi
        else
            SUBSCRIPTION_INFO[registered]="unknown"
            log_warn "subscription-manager not available"
        fi
    else
        SUBSCRIPTION_INFO[registered]="n/a"
        SUBSCRIPTION_INFO[status]="n/a"
    fi

    # Package inventory
    log_info "Collecting package inventory..."

    if [[ "${OS_INFO[pkg_manager]}" == "dnf" ]] || [[ "${OS_INFO[pkg_manager]}" == "yum" ]]; then
        # Total packages
        local total_pkgs=$(rpm -qa | wc -l)
        SYSTEM_INFO[total_packages]=$total_pkgs
        log_info "Total packages installed: $total_pkgs"

        # Available updates
        log_info "Checking for available updates..."
        local updates_available=$(${OS_INFO[pkg_manager]} check-update -q 2>/dev/null | grep -v "^$" | grep -v "^Last metadata" | wc -l || echo 0)
        SYSTEM_INFO[updates_available]=$updates_available
        log_info "Updates available: $updates_available"

        # Security updates
        if [[ "${OS_INFO[pkg_manager]}" == "dnf" ]]; then
            local sec_updates=$(dnf updateinfo list sec 2>/dev/null | grep "^RHSA\|^RLSA" | wc -l)
        else
            local sec_updates=$(yum updateinfo list security 2>/dev/null | grep "RHSA\|RLSA" | wc -l)
        fi
        SYSTEM_INFO[security_updates_available]=$sec_updates
        log_info "Security updates available: $sec_updates"

        # Check for unwanted packages (GUI on headless server)
        log_info "Checking for unwanted packages..."
        local unwanted=("gnome-desktop" "gnome-session" "firefox" "thunderbird" "libreoffice-core")
        for pkg in "${unwanted[@]}"; do
            if rpm -qa | grep -q "^$pkg"; then
                local size=$(rpm -qi "$pkg" 2>/dev/null | grep "^Size" | awk '{print int($3/1024/1024)}')
                UNWANTED_PACKAGES+=("{\"name\":\"$pkg\",\"size_mb\":${size:-0}}")
                log_warn "Unwanted package found: $pkg"
            fi
        done

        # Repository check
        local enabled_repos=$(${OS_INFO[pkg_manager]} repolist enabled 2>/dev/null | grep "^" | wc -l)
        log_info "Enabled repositories: $enabled_repos"

    elif [[ "${OS_INFO[pkg_manager]}" == "apt" ]]; then
        local total_pkgs=$(dpkg -l | grep -c "^ii")
        SYSTEM_INFO[total_packages]=$total_pkgs
        log_info "Total packages installed: $total_pkgs"
    fi

    # LEAPP check (for RHEL 7->8 or 8->9)
    if [[ "${OS_INFO[id]}" == "rhel" ]]; then
        local os_major="${OS_INFO[version]%%.*}"
        if [[ "$os_major" == "7" ]] || [[ "$os_major" == "8" ]]; then
            if command -v leapp &>/dev/null; then
                log_info "LEAPP available for upgrade assessment"
                SYSTEM_INFO[leapp_available]="true"
            else
                log_info "LEAPP not installed"
                SYSTEM_INFO[leapp_available]="false"
            fi
        else
            log_info "LEAPP not applicable for RHEL 9"
            SYSTEM_INFO[leapp_available]="false"
        fi
    fi
}

################################################################################
# PHASE 7: SECURITY ASSESSMENT
################################################################################

phase7_security_assessment() {
    log_info "=== Phase 7: Security Assessment ==="

    # SELinux
    log_info "Checking SELinux status..."
    if command -v getenforce &>/dev/null; then
        SECURITY_SELINUX[current_mode]=$(getenforce)
        log_info "SELinux: ${SECURITY_SELINUX[current_mode]}"

        if [[ -f /etc/selinux/config ]]; then
            local config_mode=$(grep "^SELINUX=" /etc/selinux/config | cut -d= -f2)
            SECURITY_SELINUX[config_mode]="$config_mode"
        fi

        # Check for recent denials
        if command -v ausearch &>/dev/null; then
            local denials=$(run_privileged ausearch -m avc -ts recent 2>/dev/null | grep "type=AVC" | wc -l)
            SECURITY_SELINUX[denials_recent]=$denials
            if [[ $denials -gt 0 ]]; then
                log_warn "Recent SELinux denials: $denials"
            fi
        fi
    else
        SECURITY_SELINUX[current_mode]="not installed"
        log_warn "SELinux not available"
    fi

    # Firewall
    log_info "Checking firewall status..."
    if systemctl is-active firewalld &>/dev/null; then
        SECURITY_FIREWALL[type]="firewalld"
        SECURITY_FIREWALL[active]="true"
        SECURITY_FIREWALL[default_zone]=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
        log_info "Firewall: firewalld active (zone: ${SECURITY_FIREWALL[default_zone]})"
    elif systemctl is-active iptables &>/dev/null; then
        SECURITY_FIREWALL[type]="iptables"
        SECURITY_FIREWALL[active]="true"
        log_info "Firewall: iptables active"
    elif systemctl is-active ufw &>/dev/null; then
        SECURITY_FIREWALL[type]="ufw"
        SECURITY_FIREWALL[active]="true"
        log_info "Firewall: ufw active"
    else
        SECURITY_FIREWALL[type]="none"
        SECURITY_FIREWALL[active]="false"
        log_error "No active firewall detected"
    fi

    # SSH Configuration
    log_info "Checking SSH configuration..."
    if [[ -f /etc/ssh/sshd_config ]]; then
        # PermitRootLogin
        local permit_root=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
        SECURITY_SSH[permit_root_login]="${permit_root:-not set}"
        log_info "SSH PermitRootLogin: ${SECURITY_SSH[permit_root_login]}"

        # PasswordAuthentication
        local pass_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
        SECURITY_SSH[password_authentication]="${pass_auth:-not set}"
        log_info "SSH PasswordAuthentication: ${SECURITY_SSH[password_authentication]}"

        # Port
        local ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')
        SECURITY_SSH[port]="${ssh_port:-22}"

        # PubkeyAuthentication
        local pubkey_auth=$(grep "^PubkeyAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
        SECURITY_SSH[pubkey_authentication]="${pubkey_auth:-not set}"
    fi

    # SSL Certificates
    log_info "Checking for SSL certificates..."
    local cert_dirs=("/etc/pki/tls/certs" "/etc/ssl/certs" "/etc/httpd/conf" "/etc/nginx")
    local cert_count=0

    for cert_dir in "${cert_dirs[@]}"; do
        if [[ -d "$cert_dir" ]]; then
            while IFS= read -r cert_file; do
                if [[ -f "$cert_file" ]]; then
                    local expiry=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
                    if [[ -n "$expiry" ]]; then
                        ((cert_count++))
                        CERTIFICATES+=("{\"path\":\"$cert_file\",\"expires\":\"$expiry\"}")
                    fi
                fi
            done < <(find "$cert_dir" -name "*.crt" -o -name "*.pem" 2>/dev/null | head -10)
        fi
    done

    if [[ $cert_count -gt 0 ]]; then
        log_info "SSL certificates found: $cert_count"
    fi

    # Auditd
    if systemctl is-active auditd &>/dev/null; then
        SYSTEM_INFO[auditd_running]="true"
        log_info "Auditd: active"
    else
        SYSTEM_INFO[auditd_running]="false"
        log_warn "Auditd: inactive"
    fi

    # Failed login attempts
    log_info "Checking failed login attempts..."
    local failed_logins=0
    if [[ -f /var/log/secure ]]; then
        failed_logins=$(run_privileged grep "Failed password" /var/log/secure 2>/dev/null | wc -l || echo 0)
    elif [[ -f /var/log/auth.log ]]; then
        failed_logins=$(run_privileged grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l || echo 0)
    fi
    SYSTEM_INFO[failed_login_count]=$failed_logins
    if [[ $failed_logins -gt 100 ]]; then
        log_warn "High number of failed login attempts: $failed_logins"
    else
        log_info "Failed login attempts: $failed_logins"
    fi
}

################################################################################
# PHASE 8: SYSTEM CONFIGURATION
################################################################################

phase8_system_configuration() {
    log_info "=== Phase 8: System Configuration ==="

    # Systemd configuration
    log_info "Checking systemd configuration..."
    SYSTEMD_INFO[default_target]=$(systemctl get-default 2>/dev/null || echo "unknown")
    log_info "Default target: ${SYSTEMD_INFO[default_target]}"

    if [[ "${SYSTEMD_INFO[default_target]}" == "graphical.target" ]]; then
        log_warn "System is set to graphical target (may be unnecessary for headless server)"
    fi

    # Failed services
    log_info "Checking for failed services..."
    local failed_count=0
    while IFS= read -r service; do
        FAILED_SERVICES+=("\"$service\"")
        log_warn "Failed service: $service"
        ((failed_count++))
    done < <(systemctl --failed --no-legend 2>/dev/null | awk '{print $1}')

    SYSTEMD_INFO[failed_services_count]=$failed_count
    if [[ $failed_count -eq 0 ]]; then
        log_info "No failed services"
    fi

    # Boot configuration
    if [[ -f /etc/default/grub ]]; then
        local grub_cmdline=$(grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub | cut -d'"' -f2)
        SYSTEMD_INFO[grub_cmdline]="$grub_cmdline"
        log_info "GRUB command line parameters collected"
    fi

    # Scheduled tasks
    log_info "Checking scheduled tasks..."
    local cron_count=$(run_privileged ls /etc/cron.* 2>/dev/null | wc -l || echo 0)
    local timer_count=$(systemctl list-timers --no-legend 2>/dev/null | wc -l || echo 0)
    log_info "Scheduled tasks: $cron_count cron jobs, $timer_count systemd timers"

    # Core dumps
    log_info "Checking for core dumps..."
    local core_dump_count=0
    local core_dirs=("/var/crash" "/var/lib/systemd/coredump" "/var/tmp")
    for core_dir in "${core_dirs[@]}"; do
        if [[ -d "$core_dir" ]]; then
            local cores=$(find "$core_dir" -name "core*" -o -name "*.core" 2>/dev/null | wc -l)
            core_dump_count=$((core_dump_count + cores))
        fi
    done

    if [[ $core_dump_count -gt 0 ]]; then
        log_warn "Core dumps found: $core_dump_count"
        SYSTEM_INFO[core_dumps_count]=$core_dump_count
    else
        log_info "No core dumps found"
        SYSTEM_INFO[core_dumps_count]=0
    fi
}

################################################################################
# PHASE 9: APPLICATION DETECTION
################################################################################

phase9_application_detection() {
    log_info "=== Phase 9: Application Detection ==="

    # Java/JDK Detection
    log_info "Detecting Java installations..."

    # Build list of directories to search including all /u0* directories
    local java_dirs=("/usr/lib/jvm" "/usr/java" "/opt/java" "/opt" "/usr/local")
    for u_dir in /u0*; do
        if [[ -d "$u_dir" ]]; then
            java_dirs+=("$u_dir")
        fi
    done

    # Track found installations to avoid duplicates
    declare -A found_jdks

    # Search standard locations
    for base_dir in "${java_dirs[@]}"; do
        if [[ -d "$base_dir" ]]; then
            while IFS= read -r java_home; do
                if [[ -f "$java_home/bin/java" ]] && [[ -z "${found_jdks[$java_home]:-}" ]]; then
                    local version=$("$java_home/bin/java" -version 2>&1 | head -1 | cut -d'"' -f2)
                    JDK_INSTALLATIONS+=("{\"path\":\"$java_home\",\"version\":\"$version\",\"in_use\":false}")
                    found_jdks[$java_home]=1
                    log_info "Found JDK: $java_home (version: $version)"
                fi
            done < <(find "$base_dir" -maxdepth 5 -type d \( -name "jdk*" -o -name "java-*" -o -name "jre*" \) 2>/dev/null)
        fi
    done

    # Detect JDK from running Java processes
    if pgrep -f "java" &>/dev/null; then
        log_info "Detecting Java installations from running processes..."
        while IFS= read -r pid; do
            if [[ -r "/proc/$pid/exe" ]]; then
                local java_exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
                if [[ -n "$java_exe" ]] && [[ "$java_exe" =~ /bin/java$ ]]; then
                    # Get JAVA_HOME (two directories up from bin/java)
                    local java_home=$(dirname $(dirname "$java_exe"))
                    if [[ -d "$java_home" ]] && [[ -z "${found_jdks[$java_home]:-}" ]]; then
                        local version=$("$java_home/bin/java" -version 2>&1 | head -1 | cut -d'"' -f2 2>/dev/null || echo "unknown")
                        JDK_INSTALLATIONS+=("{\"path\":\"$java_home\",\"version\":\"$version\",\"in_use\":true}")
                        found_jdks[$java_home]=1
                        log_info "Found running JDK: $java_home (version: $version)"
                    fi
                fi
            fi
        done < <(pgrep -f "java")
    fi

    # Tomcat Detection
    log_info "Detecting Tomcat installations..."

    # Build list of directories to search including all /u0* directories
    local tomcat_dirs=("/opt" "/usr/share" "/var/lib" "/usr/local")
    for u_dir in /u0*; do
        if [[ -d "$u_dir" ]]; then
            tomcat_dirs+=("$u_dir")
        fi
    done

    # Track found installations to avoid duplicates
    declare -A found_tomcats

    # Search standard locations
    for base_dir in "${tomcat_dirs[@]}"; do
        if [[ -d "$base_dir" ]]; then
            while IFS= read -r tomcat_home; do
                if [[ -f "$tomcat_home/bin/catalina.sh" ]] && [[ -z "${found_tomcats[$tomcat_home]:-}" ]]; then
                    local version="unknown"
                    if [[ -f "$tomcat_home/bin/version.sh" ]]; then
                        version=$("$tomcat_home/bin/version.sh" 2>/dev/null | grep "Server number" | awk '{print $3}')
                    fi

                    # Check if running
                    local running="false"
                    if pgrep -f "$tomcat_home" &>/dev/null; then
                        running="true"
                    fi

                    TOMCAT_INSTALLATIONS+=("{\"path\":\"$tomcat_home\",\"version\":\"$version\",\"running\":$running}")
                    found_tomcats[$tomcat_home]=1
                    log_info "Found Tomcat: $tomcat_home (version: $version, running: $running)"
                fi
            done < <(find "$base_dir" -maxdepth 5 -type d -name "tomcat*" 2>/dev/null)
        fi
    done

    # Detect Tomcat from running processes
    if pgrep -f "catalina" &>/dev/null || pgrep -f "org.apache.catalina" &>/dev/null; then
        log_info "Detecting Tomcat installations from running processes..."
        while IFS= read -r pid; do
            # Try to extract catalina.home or catalina.base from process command line
            if [[ -r "/proc/$pid/cmdline" ]]; then
                local cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)

                # Look for -Dcatalina.home or -Dcatalina.base
                local catalina_home=$(echo "$cmdline" | grep -oP '(?<=-Dcatalina\.home=)[^ ]+' | head -1)
                if [[ -z "$catalina_home" ]]; then
                    catalina_home=$(echo "$cmdline" | grep -oP '(?<=-Dcatalina\.base=)[^ ]+' | head -1)
                fi

                if [[ -n "$catalina_home" ]] && [[ -d "$catalina_home" ]] && [[ -f "$catalina_home/bin/catalina.sh" ]] && [[ -z "${found_tomcats[$catalina_home]:-}" ]]; then
                    local version="unknown"
                    if [[ -f "$catalina_home/bin/version.sh" ]]; then
                        version=$("$catalina_home/bin/version.sh" 2>/dev/null | grep "Server number" | awk '{print $3}')
                    fi

                    TOMCAT_INSTALLATIONS+=("{\"path\":\"$catalina_home\",\"version\":\"$version\",\"running\":true}")
                    found_tomcats[$catalina_home]=1
                    log_info "Found running Tomcat: $catalina_home (version: $version)"
                fi
            fi
        done < <(pgrep -f "catalina|org.apache.catalina")
    fi

    # Oracle Database Detection
    log_info "Detecting Oracle Database installations..."

    # Check oratab
    if [[ -f /etc/oratab ]]; then
        while IFS=: read -r sid oracle_home _; do
            if [[ -n "$oracle_home" ]] && [[ -d "$oracle_home" ]]; then
                local version="unknown"
                if [[ -f "$oracle_home/bin/sqlplus" ]]; then
                    version=$("$oracle_home/bin/sqlplus" -version 2>/dev/null | grep "Release" | awk '{print $3}')
                fi

                # Check if instance is running
                local instance_running="false"
                if pgrep -f "ora_pmon_$sid" &>/dev/null; then
                    instance_running="true"
                fi

                ORACLE_HOMES+=("{\"oracle_home\":\"$oracle_home\",\"sid\":\"$sid\",\"version\":\"$version\",\"running\":$instance_running}")
                log_info "Found Oracle instance: $sid at $oracle_home (version: $version, running: $instance_running)"
            fi
        done < <(grep -v "^#" /etc/oratab | grep -v "^$")
    fi

    # Search for Oracle homes in standard locations
    local oracle_dirs=("/u01/app/oracle/product" "/u02/app/oracle/product" "/opt/oracle")
    for base_dir in "${oracle_dirs[@]}"; do
        if [[ -d "$base_dir" ]]; then
            while IFS= read -r oracle_home; do
                if [[ -f "$oracle_home/bin/sqlplus" ]]; then
                    log_info "Found Oracle home: $oracle_home"
                fi
            done < <(find "$base_dir" -maxdepth 2 -type d -name "dbhome_*" 2>/dev/null)
        fi
    done

    # Detect running Oracle processes
    if pgrep -f "ora_pmon_" &>/dev/null; then
        log_info "Detecting Oracle instances from running processes..."
        while IFS= read -r pid; do
            # Get the SID from the process name (ora_pmon_SIDNAME)
            local pmon_sid=$(ps -p "$pid" -o comm= | sed 's/ora_pmon_//')
            if [[ -n "$pmon_sid" ]]; then
                # Try to get ORACLE_HOME from process environment
                local proc_oracle_home=""
                if [[ -r "/proc/$pid/environ" ]]; then
                    proc_oracle_home=$(strings "/proc/$pid/environ" 2>/dev/null | grep "^ORACLE_HOME=" | cut -d= -f2 | head -1)
                fi

                # If we found an ORACLE_HOME and it's not already in our list, add it
                if [[ -n "$proc_oracle_home" ]] && [[ -d "$proc_oracle_home" ]]; then
                    # Check if this SID is already recorded
                    set +u
                    local already_found=false
                    for existing in "${ORACLE_HOMES[@]}"; do
                        if echo "$existing" | grep -q "\"sid\":\"$pmon_sid\""; then
                            already_found=true
                            break
                        fi
                    done
                    set -u

                    if [[ "$already_found" != "true" ]]; then
                        local version="unknown"
                        if [[ -f "$proc_oracle_home/bin/sqlplus" ]]; then
                            version=$("$proc_oracle_home/bin/sqlplus" -version 2>/dev/null | grep "Release" | awk '{print $3}')
                        fi
                        ORACLE_HOMES+=("{\"oracle_home\":\"$proc_oracle_home\",\"sid\":\"$pmon_sid\",\"version\":\"$version\",\"running\":true}")
                        log_info "Found running Oracle instance: $pmon_sid at $proc_oracle_home (version: $version)"
                    fi
                fi
            fi
        done < <(pgrep -f "ora_pmon_")
    fi

    # Web Server Detection
    log_info "Detecting web servers..."

    # Apache
    if command -v httpd &>/dev/null; then
        local apache_version=$(httpd -v 2>/dev/null | grep "Server version" | awk '{print $3}')
        local apache_running="false"
        if systemctl is-active httpd &>/dev/null; then
            apache_running="true"
        fi
        WEB_SERVERS+=("{\"type\":\"apache\",\"version\":\"$apache_version\",\"running\":$apache_running}")
        log_info "Apache detected: $apache_version (running: $apache_running)"
    fi

    # Nginx
    if command -v nginx &>/dev/null; then
        local nginx_version=$(nginx -v 2>&1 | cut -d'/' -f2)
        local nginx_running="false"
        if systemctl is-active nginx &>/dev/null; then
            nginx_running="true"
        fi
        WEB_SERVERS+=("{\"type\":\"nginx\",\"version\":\"$nginx_version\",\"running\":$nginx_running}")
        log_info "Nginx detected: $nginx_version (running: $nginx_running)"
    fi

    # Banner Component Detection
    log_info "Detecting Ellucian Banner components..."
    local banner_dirs=("/u01/banner" "/u02/banner" "/opt/banner")

    for banner_dir in "${banner_dirs[@]}"; do
        if [[ -d "$banner_dir" ]]; then
            log_info "Banner directory found: $banner_dir"
            BANNER_COMPONENTS+=("{\"type\":\"banner_app\",\"path\":\"$banner_dir\"}")

            # Look for specific Banner components
            if [[ -d "$banner_dir/forms" ]]; then
                log_info "Banner Forms detected"
            fi
            if [[ -d "$banner_dir/self-service" ]]; then
                log_info "Banner Self-Service detected"
            fi
        fi
    done

    # Container Detection
    log_info "Checking for container runtimes..."

    if command -v docker &>/dev/null; then
        local docker_version=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')
        log_info "Docker detected: $docker_version"
        SYSTEM_INFO[container_runtime]="docker"
    elif command -v podman &>/dev/null; then
        local podman_version=$(podman --version 2>/dev/null | awk '{print $3}')
        log_info "Podman detected: $podman_version"
        SYSTEM_INFO[container_runtime]="podman"
    else
        SYSTEM_INFO[container_runtime]="none"
    fi

    # Monitoring Agents
    log_info "Checking for monitoring agents..."

    if systemctl is-active nrpe &>/dev/null; then
        MONITORING_AGENTS+=("{\"type\":\"nrpe\",\"running\":true}")
        log_info "Nagios NRPE detected"
    fi

    if systemctl is-active zabbix-agent &>/dev/null || systemctl is-active zabbix-agent2 &>/dev/null; then
        MONITORING_AGENTS+=("{\"type\":\"zabbix\",\"running\":true}")
        log_info "Zabbix agent detected"
    fi

    if systemctl is-active snmpd &>/dev/null; then
        MONITORING_AGENTS+=("{\"type\":\"snmpd\",\"running\":true}")
        log_info "SNMP daemon detected"
    fi
}

################################################################################
# PHASE 10: PROCESS ANALYSIS
################################################################################

phase10_process_analysis() {
    log_info "=== Phase 10: Process Analysis ==="

    # Count running processes
    local process_count=$(ps aux | wc -l)
    log_info "Total running processes: $process_count"

    # Check for non-systemd managed processes
    log_info "Checking for non-systemd managed processes..."
    local non_systemd_count=0

    # Look for processes that should be managed but aren't
    local check_processes=("java" "tomcat" "oracle" "httpd" "nginx")
    for proc_name in "${check_processes[@]}"; do
        if pgrep -f "$proc_name" &>/dev/null; then
            # Get all PIDs matching the process name
            local pids=$(pgrep -f "$proc_name")

            for pid in $pids; do
                # Check if this specific PID is managed by systemd
                # We check the cgroup to see if it's within a system.slice
                if ! grep -q "system.slice" "/proc/$pid/cgroup" 2>/dev/null; then
                    ((non_systemd_count++))

                    # Get the executable path
                    local exe_path="unknown"
                    if [[ -L "/proc/$pid/exe" ]]; then
                        exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
                    fi

                    # Get the process owner
                    local user=$(ps -p "$pid" -o user= 2>/dev/null || echo "unknown")

                    # Get the full command line (tr nulls to spaces)
                    local cmdline="unknown"
                    if [[ -f "/proc/$pid/cmdline" ]]; then
                        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | xargs || echo "unknown")
                    fi

                    # Get the current working directory
                    local cwd="unknown"
                    if [[ -L "/proc/$pid/cwd" ]]; then
                        cwd=$(readlink -f "/proc/$pid/cwd" 2>/dev/null || echo "unknown")
                    fi

                    log_warn "Process '$proc_name' (PID: $pid, User: $user) running but not managed by systemd"
                    log_debug "  Command: $cmdline"
                    log_debug "  CWD: $cwd"
                    log_debug "  Executable: $exe_path"

                    # Escape quotes for JSON
                    local safe_cmdline=$(echo "$cmdline" | sed 's/"/\\"/g')
                    local safe_cwd=$(echo "$cwd" | sed 's/"/\\"/g')
                    local safe_exe=$(echo "$exe_path" | sed 's/"/\\"/g')

                    NON_SYSTEMD_PROCESSES+=("{\"pid\":$pid,\"name\":\"$proc_name\",\"user\":\"$user\",\"command\":\"$safe_cmdline\",\"cwd\":\"$safe_cwd\",\"executable\":\"$safe_exe\"}")
                fi
            done
        fi
    done

    log_info "Non-systemd managed processes: $non_systemd_count"
    SYSTEM_INFO[non_systemd_processes_count]=$non_systemd_count
}

################################################################################
# REMEDIATION GENERATION
################################################################################

generate_remediation_recommendations() {
    log_info "=== Generating Remediation Recommendations ==="

    local rem_id=1
    log_info "Starting remediation checks (rem_id=$rem_id)"

    # Storage recommendations
    log_info "Checking storage recommendations..."
    local fs_count=0
    set +u
    fs_count=${#FILESYSTEMS[@]}
    set -u
    log_info "Found $fs_count filesystem(s) to check"

    if [[ $fs_count -gt 0 ]]; then
        local i
        for ((i=0; i<fs_count; i++)); do
            set +u
            local fs_json="${FILESYSTEMS[$i]}"
            set -u
            local mount_point=$(echo "$fs_json" | grep -o '"mount_point":"[^"]*"' | cut -d'"' -f4)
            local use_percent=$(echo "$fs_json" | grep -o '"use_percent":[0-9]*' | cut -d':' -f2)

            # Skip if we couldn't extract the data
            [[ -z "$mount_point" || -z "$use_percent" ]] && continue

            if [[ $use_percent -ge 90 ]]; then
                REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"CRITICAL","category":"storage","title":"Critical disk space on %s","description":"Filesystem %s is %d%% full","impact":"System may become unresponsive or fail","effort":"1-2 hours","risk":"Requires cleanup or expansion"}' $rem_id "$mount_point" "$mount_point" "$use_percent")")
                ((rem_id++))
            elif [[ $use_percent -ge 80 ]]; then
                REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"HIGH","category":"storage","title":"Low disk space on %s","description":"Filesystem %s is %d%% full","impact":"May run out of space soon","effort":"30 minutes","risk":"Requires cleanup"}' $rem_id "$mount_point" "$mount_point" "$use_percent")")
                ((rem_id++))
            fi
        done
    fi
    log_info "Storage checks complete"

    # OS EOL recommendations
    log_info "Checking OS EOL status..."
    if [[ "${OS_INFO[is_eol]:-false}" == "true" ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"CRITICAL","category":"os","title":"Operating System is End of Life","description":"OS %s %s is past EOL","impact":"No security updates available, system vulnerable","effort":"4-8 hours","risk":"Requires major OS upgrade"}' $rem_id "${OS_INFO[name]:-unknown}" "${OS_INFO[version]:-unknown}")")
        ((rem_id++))
    elif [[ ${OS_INFO[days_until_eol]:-999} -lt 180 ]] && [[ ${OS_INFO[days_until_eol]:-999} -gt 0 ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"HIGH","category":"os","title":"Operating System approaching EOL","description":"OS EOL in %d days","impact":"Need to plan upgrade","effort":"4-8 hours","risk":"Requires major OS upgrade"}' $rem_id "${OS_INFO[days_until_eol]:-999}")")
        ((rem_id++))
    fi
    log_info "OS EOL checks complete"

    # Kernel update recommendation
    log_info "Checking kernel updates..."
    if [[ "${OS_INFO[kernel_update_available]:-false}" == "true" ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"MEDIUM","category":"os","title":"Kernel update available","description":"Update from %s to %s","impact":"Missing kernel security fixes","effort":"30 minutes","risk":"Requires reboot"}' $rem_id "${OS_INFO[current_kernel]:-unknown}" "${OS_INFO[latest_kernel]:-unknown}")")
        ((rem_id++))
    fi
    log_info "Kernel checks complete"

    # Security recommendations
    log_info "Checking security settings..."
    if [[ "${SECURITY_SELINUX[current_mode]:-unknown}" == "Disabled" ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"CRITICAL","category":"security","title":"SELinux is disabled","description":"SELinux provides mandatory access controls","impact":"Reduced security posture","effort":"1-2 hours","risk":"May affect applications, requires testing"}' $rem_id)")
        ((rem_id++))
    fi

    if [[ "${SECURITY_FIREWALL[active]:-false}" == "false" ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"HIGH","category":"security","title":"No active firewall","description":"System has no firewall protection","impact":"All ports exposed to network","effort":"30 minutes","risk":"May affect connectivity"}' $rem_id)")
        ((rem_id++))
    fi

    if [[ "${SECURITY_SSH[permit_root_login]:-unknown}" != "no" ]] && [[ "${SECURITY_SSH[permit_root_login]:-unknown}" != "prohibit-password" ]] && [[ "${SECURITY_SSH[password_authentication]:-unknown}" != "no" ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"CRITICAL","category":"security","title":"Root SSH login with password enabled","description":"PermitRootLogin: %s, PasswordAuth: %s","impact":"High risk of brute force attacks","effort":"5 minutes","risk":"Ensure SSH key access configured first"}' $rem_id "${SECURITY_SSH[permit_root_login]:-unknown}" "${SECURITY_SSH[password_authentication]:-unknown}")")
        ((rem_id++))
    fi

    if [[ ${SYSTEM_INFO[security_updates_available]:-0} -gt 0 ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"HIGH","category":"security","title":"Security updates available","description":"%d security updates pending","impact":"System vulnerable to known CVEs","effort":"30 minutes","risk":"May require reboot"}' $rem_id "${SYSTEM_INFO[security_updates_available]:-0}")")
        ((rem_id++))
    fi
    log_info "Security checks complete"

    # Subscription recommendation
    log_info "Checking subscription status..."
    if [[ "${SUBSCRIPTION_INFO[registered]:-false}" == "false" ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"HIGH","category":"packages","title":"RHEL system not registered","description":"System cannot receive updates","impact":"No access to security updates","effort":"15 minutes","risk":"Requires subscription or migration to Rocky"}' $rem_id)")
        ((rem_id++))
    fi
    log_info "Subscription checks complete"

    # Unwanted packages
    log_info "Checking for unwanted packages..."
    local unwanted_count=0
    set +u
    unwanted_count=${#UNWANTED_PACKAGES[@]}
    set -u
    if [[ $unwanted_count -gt 0 ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"MEDIUM","category":"packages","title":"Remove unnecessary GUI packages","description":"Found %d unwanted packages on headless server","impact":"Wastes disk space and resources","effort":"15 minutes","risk":"Ensure not needed"}' $rem_id "$unwanted_count")")
        ((rem_id++))
    fi
    log_info "Unwanted package checks complete"

    # Tomcat EOL check
    log_info "Checking Tomcat installations..."

    # Temporarily disable set -u for array operations
    set +u
    local tomcat_count=${#TOMCAT_INSTALLATIONS[@]}
    set -u

    log_info "Found $tomcat_count Tomcat installation(s) to check"

    if [[ $tomcat_count -gt 0 ]]; then
        local i=0
        while [[ $i -lt $tomcat_count ]]; do
            # Temporarily disable set -u for array access
            set +u
            local tomcat="${TOMCAT_INSTALLATIONS[$i]}"
            set -u

            if [[ -n "$tomcat" ]]; then
                log_info "Processing Tomcat entry $((i+1))/$tomcat_count"
                local version=$(echo "$tomcat" | grep -o '"version":"[^"]*"' | cut -d'"' -f4 2>/dev/null || echo "")
                if [[ -n "$version" ]] && [[ "$version" != "unknown" ]]; then
                    log_info "Tomcat version: $version"
                    if [[ "$version" =~ ^9\.0 ]]; then
                        # Tomcat 9.0 EOL was March 31, 2024
                        log_info "Tomcat $version is EOL, adding remediation"
                        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"HIGH","category":"applications","title":"Tomcat installation is EOL","description":"Tomcat %s reached EOL on 2024-03-31","impact":"No security updates available","effort":"2-4 hours","risk":"Requires testing"}' $rem_id "$version")")
                        ((rem_id++))
                    fi
                else
                    log_info "Could not extract version or version unknown, skipping"
                fi
            fi
            ((i++))
        done
    fi
    log_info "Tomcat checks complete"

    # Time sync recommendation
    log_info "Checking time synchronization..."
    if [[ "${TIME_SYNC[synchronized]:-false}" == "false" ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"HIGH","category":"system","title":"Time synchronization not working","description":"System time may drift","impact":"Log correlation issues, auth failures","effort":"15 minutes","risk":"Low"}' $rem_id)")
        ((rem_id++))
    fi
    log_info "Time sync checks complete"

    # Failed services
    log_info "Checking failed services..."
    if [[ ${SYSTEMD_INFO[failed_services_count]:-0} -gt 0 ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"MEDIUM","category":"system","title":"Failed systemd services","description":"Found %d failed services","impact":"Services not running as expected","effort":"30 minutes","risk":"Investigate each service"}' $rem_id "${SYSTEMD_INFO[failed_services_count]:-0}")")
        ((rem_id++))
    fi
    log_info "Failed services checks complete"

    # Graphical target on headless
    log_info "Checking systemd target..."
    if [[ "${SYSTEMD_INFO[default_target]:-unknown}" == "graphical.target" ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"MEDIUM","category":"system","title":"Change default target to multi-user","description":"Graphical target unnecessary for headless server","impact":"Wastes resources","effort":"2 minutes","risk":"Low"}' $rem_id)")
        ((rem_id++))
    fi
    log_info "Systemd target checks complete"

    # Non-systemd processes
    log_info "Checking non-systemd processes..."
    if [[ ${SYSTEM_INFO[non_systemd_processes_count]:-0} -gt 0 ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"MEDIUM","category":"system","title":"Create systemd units for manual processes","description":"Found %d processes not managed by systemd","impact":"Manual startup required after reboot","effort":"1 hour","risk":"Requires service configuration"}' $rem_id "${SYSTEM_INFO[non_systemd_processes_count]:-0}")")
        ((rem_id++))
    fi
    log_info "Non-systemd process checks complete"

    # No monitoring
    log_info "Checking for monitoring agents..."
    local has_monitoring=false
    set +u
    if [[ ${#MONITORING_AGENTS[@]} -gt 0 ]]; then
        has_monitoring=true
    fi
    set -u
    if [[ "$has_monitoring" == "false" ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"MEDIUM","category":"monitoring","title":"No monitoring agent detected","description":"System not being monitored","impact":"Issues may go undetected","effort":"30 minutes","risk":"Requires monitoring infrastructure"}' $rem_id)")
        ((rem_id++))
    fi
    log_info "Monitoring checks complete"

    local total_rem=0
    set +u
    total_rem=${#REMEDIATION_ITEMS[@]}
    set -u
    log_info "Generated $total_rem remediation recommendations"
    log_info "Remediation function completed successfully"
}

################################################################################
# JSON OUTPUT GENERATION
################################################################################

generate_json_output() {
    log_info "Generating JSON output..."

    local timestamp_iso=$(date -Iseconds)

    # Start JSON
    cat > "$JSON_FILE" << EOF
{
  "assessment_metadata": {
    "version": "$SCRIPT_VERSION",
    "timestamp": "$timestamp_iso",
    "hostname": "${SYSTEM_INFO[hostname]}",
    "assessment_user": "$(whoami)"
  },
  "system_info": {
    "os": {
      "name": "${OS_INFO[name]}",
      "version": "${OS_INFO[version]}",
      "id": "${OS_INFO[id]}",
      "kernel": "${OS_INFO[kernel]}",
      "architecture": "${OS_INFO[architecture]}",
      "eol_date": "${OS_INFO[eol_date]:-unknown}",
      "days_until_eol": ${OS_INFO[days_until_eol]:-0},
      "is_eol": ${OS_INFO[is_eol]:-false}
    },
    "hardware": {
      "cpu_count": ${HARDWARE_INFO[cpu_count]},
      "cpu_model": "${HARDWARE_INFO[cpu_model]}",
      "memory_total_gb": ${HARDWARE_INFO[memory_total_gb]},
      "memory_available_gb": ${HARDWARE_INFO[memory_available_gb]},
      "swap_size_gb": ${HARDWARE_INFO[swap_size_gb]},
      "virtualization": "${HARDWARE_INFO[virtualization]}"
    },
    "uptime": {
      "seconds": ${SYSTEM_INFO[uptime_seconds]},
      "human_readable": "${SYSTEM_INFO[uptime_human]}"
    },
    "load_average": [${SYSTEM_INFO[load_1]}, ${SYSTEM_INFO[load_5]}, ${SYSTEM_INFO[load_15]}],
    "reboot_required": ${SYSTEM_INFO[reboot_required]}
  },
  "storage": {
    "filesystems": [
      $(set +u; IFS=,; echo "${FILESYSTEMS[*]}"; set -u)
    ],
    "lvm_present": ${SYSTEM_INFO[lvm_present]:-false},
    "raid_present": ${SYSTEM_INFO[raid_present]:-false}
  },
  "network": {
    "dns_working": ${NETWORK_INFO[dns_working]:-false},
    "internet_working": ${NETWORK_INFO[internet_working]:-false},
    "gateway_ip": "${NETWORK_INFO[gateway_ip]:-none}",
    "listening_ports": [
      $(set +u; IFS=,; echo "${LISTENING_PORTS[*]}"; set -u)
    ]
  },
  "time_sync": {
    "service": "${TIME_SYNC[service]:-none}",
    "status": "${TIME_SYNC[status]:-inactive}",
    "synchronized": ${TIME_SYNC[synchronized]:-false},
    "timezone": "${TIME_SYNC[timezone]:-unknown}"
  },
  "packages": {
    "total_installed": ${SYSTEM_INFO[total_packages]:-0},
    "updates_available": ${SYSTEM_INFO[updates_available]:-0},
    "security_updates_available": ${SYSTEM_INFO[security_updates_available]:-0},
    "unwanted_packages": [
      $(set +u; IFS=,; echo "${UNWANTED_PACKAGES[*]}"; set -u)
    ]
  },
  "security": {
    "selinux": {
      "current_mode": "${SECURITY_SELINUX[current_mode]:-unknown}",
      "config_mode": "${SECURITY_SELINUX[config_mode]:-unknown}",
      "denials_recent": ${SECURITY_SELINUX[denials_recent]:-0}
    },
    "firewall": {
      "type": "${SECURITY_FIREWALL[type]:-none}",
      "active": ${SECURITY_FIREWALL[active]:-false},
      "default_zone": "${SECURITY_FIREWALL[default_zone]:-unknown}"
    },
    "ssh": {
      "permit_root_login": "${SECURITY_SSH[permit_root_login]:-unknown}",
      "password_authentication": "${SECURITY_SSH[password_authentication]:-unknown}",
      "port": ${SECURITY_SSH[port]:-22},
      "pubkey_authentication": "${SECURITY_SSH[pubkey_authentication]:-unknown}"
    },
    "certificates": [
      $(set +u; IFS=,; echo "${CERTIFICATES[*]}"; set -u)
    ],
    "auditd_running": ${SYSTEM_INFO[auditd_running]:-false},
    "failed_login_count": ${SYSTEM_INFO[failed_login_count]:-0}
  },
  "subscription": {
    "is_rhel": $([ "${OS_INFO[id]}" == "rhel" ] && echo "true" || echo "false"),
    "registered": ${SUBSCRIPTION_INFO[registered]:-false},
    "status": "${SUBSCRIPTION_INFO[status]:-unknown}"
  },
  "systemd": {
    "default_target": "${SYSTEMD_INFO[default_target]:-unknown}",
    "failed_services": [
      $(set +u; IFS=,; echo "${FAILED_SERVICES[*]}"; set -u)
    ],
    "non_systemd_processes": [
      $(set +u; IFS=,; echo "${NON_SYSTEMD_PROCESSES[*]}"; set -u)
    ]
  },
  "applications": {
    "java": [
      $(set +u; IFS=,; echo "${JDK_INSTALLATIONS[*]}"; set -u)
    ],
    "tomcat": [
      $(set +u; IFS=,; echo "${TOMCAT_INSTALLATIONS[*]}"; set -u)
    ],
    "oracle_database": [
      $(set +u; IFS=,; echo "${ORACLE_HOMES[*]}"; set -u)
    ],
    "web_servers": [
      $(set +u; IFS=,; echo "${WEB_SERVERS[*]}"; set -u)
    ],
    "banner_components": [
      $(set +u; IFS=,; echo "${BANNER_COMPONENTS[*]}"; set -u)
    ],
    "monitoring_agents": [
      $(set +u; IFS=,; echo "${MONITORING_AGENTS[*]}"; set -u)
    ]
  },
  "remediation": {
    "summary": {
      "total_recommendations": $(set +u; echo ${#REMEDIATION_ITEMS[@]}; set -u)
    },
    "recommendations": [
      $(set +u; IFS=,; echo "${REMEDIATION_ITEMS[*]}"; set -u)
    ]
  }
}
EOF

    log_info "JSON output written to: $JSON_FILE"
}

################################################################################
# MARKDOWN OUTPUT GENERATION
################################################################################

generate_markdown_output() {
    log_info "Generating Markdown report..."

    # Count priorities
    local total_rems=0
    set +u
    total_rems=${#REMEDIATION_ITEMS[@]}
    set -u
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0

    if [[ $total_rems -gt 0 ]]; then
        set +u
        critical_count=$(printf '%s\n' "${REMEDIATION_ITEMS[@]}" | grep '"priority":"CRITICAL"' | wc -l)
        high_count=$(printf '%s\n' "${REMEDIATION_ITEMS[@]}" | grep '"priority":"HIGH"' | wc -l)
        medium_count=$(printf '%s\n' "${REMEDIATION_ITEMS[@]}" | grep '"priority":"MEDIUM"' | wc -l)
        low_count=$(printf '%s\n' "${REMEDIATION_ITEMS[@]}" | grep '"priority":"LOW"' | wc -l)
        set -u
    fi

    cat > "$MD_FILE" << EOF
# Server Assessment Report

**Server:** ${SYSTEM_INFO[hostname]}
**Assessment Date:** $(date '+%B %d, %Y %H:%M:%S %Z')
**Assessment Version:** $SCRIPT_VERSION

---

## Executive Summary

- **Total Recommendations:** $total_rems ($critical_count Critical, $high_count High, $medium_count Medium, $low_count Low)
- **OS Status:** ${OS_INFO[name]} ${OS_INFO[version]} - $([ "${OS_INFO[is_eol]}" == "true" ] && echo "⚠️ EOL" || echo "✅ Supported")
- **Security Posture:** SELinux: ${SECURITY_SELINUX[current_mode]}, Firewall: $([ "${SECURITY_FIREWALL[active]}" == "true" ] && echo "✅ Active" || echo "⚠️ Inactive")

---

## System Information

### Operating System
- **Distribution:** ${OS_INFO[name]} ${OS_INFO[version]}
- **Kernel:** ${OS_INFO[kernel]}
- **Architecture:** ${OS_INFO[architecture]}
- **EOL Date:** ${OS_INFO[eol_date]:-Unknown} (${OS_INFO[days_until_eol]:-?} days remaining)
- **Package Manager:** ${OS_INFO[pkg_manager]}

### Hardware
- **CPU:** ${HARDWARE_INFO[cpu_count]} x ${HARDWARE_INFO[cpu_model]}
- **Memory:** ${HARDWARE_INFO[memory_total_gb]} GB total, ${HARDWARE_INFO[memory_available_gb]} GB available
- **Swap:** ${HARDWARE_INFO[swap_size_gb]} GB
- **Platform:** ${HARDWARE_INFO[virtualization]}

### System State
- **Uptime:** ${SYSTEM_INFO[uptime_human]}
- **Load Average:** ${SYSTEM_INFO[load_1]}, ${SYSTEM_INFO[load_5]}, ${SYSTEM_INFO[load_15]}
- **Reboot Required:** $([ "${SYSTEM_INFO[reboot_required]}" == "true" ] && echo "⚠️ Yes" || echo "✅ No")

---

## Storage Assessment

| Mount Point | Size | Used | Available | Usage % | Status |
|-------------|------|------|-----------|---------|--------|
EOF

    # Add filesystem rows
    local fs_md_count=0
    set +u
    fs_md_count=${#FILESYSTEMS[@]}
    set -u

    if [[ $fs_md_count -gt 0 ]]; then
        local i
        for ((i=0; i<fs_md_count; i++)); do
            set +u
            local fs_json="${FILESYSTEMS[$i]}"
            set -u
            local mount_point=$(echo "$fs_json" | grep -o '"mount_point":"[^"]*"' | cut -d'"' -f4)
            local size_gb=$(echo "$fs_json" | grep -o '"size_gb":[0-9]*' | cut -d':' -f2)
            local used_gb=$(echo "$fs_json" | grep -o '"used_gb":[0-9]*' | cut -d':' -f2)
            local avail_gb=$(echo "$fs_json" | grep -o '"available_gb":[0-9]*' | cut -d':' -f2)
            local use_pct=$(echo "$fs_json" | grep -o '"use_percent":[0-9]*' | cut -d':' -f2)

            local status="✅ OK"
            [[ $use_pct -ge 80 ]] && status="⚠️ Warning"
            [[ $use_pct -ge 90 ]] && status="🔴 Critical"

            echo "| $mount_point | ${size_gb}GB | ${used_gb}GB | ${avail_gb}GB | ${use_pct}% | $status |" >> "$MD_FILE"
        done
    fi

    cat >> "$MD_FILE" << EOF

---

## Network Assessment

- **DNS Resolution:** $([ "${NETWORK_INFO[dns_working]}" == "true" ] && echo "✅ Working" || echo "⚠️ Failed")
- **Internet Connectivity:** $([ "${NETWORK_INFO[internet_working]}" == "true" ] && echo "✅ Working" || echo "⚠️ Issues")
- **Default Gateway:** ${NETWORK_INFO[gateway_ip]}

### Listening Ports
EOF

    # Add top listening ports
    local port_display_count=0
    local port_total_count=0
    set +u
    port_total_count=${#LISTENING_PORTS[@]}
    set -u

    if [[ $port_total_count -gt 0 ]]; then
        local i
        for ((i=0; i<port_total_count && port_display_count<10; i++)); do
            set +u
            local port_json="${LISTENING_PORTS[$i]}"
            set -u
            local port=$(echo "$port_json" | grep -o '"port":[0-9]*' | cut -d':' -f2)
            local process=$(echo "$port_json" | grep -o '"process":"[^"]*"' | cut -d'"' -f4)
            echo "- TCP $port: $process" >> "$MD_FILE"
            ((port_display_count++))
        done
    fi

    cat >> "$MD_FILE" << EOF

---

## Security Assessment

### SELinux
- **Status:** ${SECURITY_SELINUX[current_mode]} $([ "${SECURITY_SELINUX[current_mode]}" == "Enforcing" ] && echo "✅" || echo "⚠️")
- **Configuration:** ${SECURITY_SELINUX[config_mode]}
- **Recent Denials:** ${SECURITY_SELINUX[denials_recent]:-0}

### Firewall
- **Type:** ${SECURITY_FIREWALL[type]}
- **Status:** $([ "${SECURITY_FIREWALL[active]}" == "true" ] && echo "✅ Active" || echo "⚠️ Inactive")
- **Default Zone:** ${SECURITY_FIREWALL[default_zone]:-N/A}

### SSH Configuration
- **PermitRootLogin:** ${SECURITY_SSH[permit_root_login]} $([ "${SECURITY_SSH[permit_root_login]}" == "no" ] || [ "${SECURITY_SSH[permit_root_login]}" == "prohibit-password" ] && echo "✅" || echo "⚠️")
- **PasswordAuthentication:** ${SECURITY_SSH[password_authentication]} $([ "${SECURITY_SSH[password_authentication]}" == "no" ] && echo "✅" || echo "⚠️")
- **Port:** ${SECURITY_SSH[port]}

### Updates & Patches
- **Security Updates Available:** ${SYSTEM_INFO[security_updates_available]:-0}
- **Total Updates Available:** ${SYSTEM_INFO[updates_available]:-0}

---

## System Management

### Systemd Configuration
- **Default Target:** ${SYSTEMD_INFO[default_target]:-unknown}
- **Failed Services:** ${SYSTEMD_INFO[failed_services_count]:-0}

EOF

    # List failed services if any
    local failed_svc_count=0
    set +u
    failed_svc_count=${#FAILED_SERVICES[@]}
    set -u

    if [[ $failed_svc_count -gt 0 ]]; then
        echo "#### Failed Services:" >> "$MD_FILE"
        echo "" >> "$MD_FILE"
        local i
        for ((i=0; i<failed_svc_count; i++)); do
            set +u
            local svc="${FAILED_SERVICES[$i]}"
            set -u
            echo "- $svc" >> "$MD_FILE"
        done
        echo "" >> "$MD_FILE"
    fi

    cat >> "$MD_FILE" << EOF

### Non-Systemd Managed Processes
- **Count:** ${SYSTEM_INFO[non_systemd_processes_count]:-0}

EOF

    # List non-systemd processes if any
    local non_systemd_count=0
    set +u
    non_systemd_count=${#NON_SYSTEMD_PROCESSES[@]}
    set -u

    if [[ $non_systemd_count -gt 0 ]]; then
        echo "#### Processes Not Managed by Systemd:" >> "$MD_FILE"
        echo "" >> "$MD_FILE"
        local i
        for ((i=0; i<non_systemd_count; i++)); do
            set +u
            local proc="${NON_SYSTEMD_PROCESSES[$i]}"
            set -u
            # Parse JSON to extract details
            local pid=$(echo "$proc" | sed 's/.*"pid":\([0-9]*\).*/\1/')
            local proc_name=$(echo "$proc" | sed 's/.*"name":"\([^"]*\)".*/\1/')
            local user=$(echo "$proc" | sed 's/.*"user":"\([^"]*\)".*/\1/')
            local cmdline=$(echo "$proc" | sed 's/.*"command":"\([^"]*\)".*/\1/')
            local cwd=$(echo "$proc" | sed 's/.*"cwd":"\([^"]*\)".*/\1/')
            local proc_exe=$(echo "$proc" | sed 's/.*"executable":"\([^"]*\)".*/\1/')

            echo "- **$proc_name** (PID: $pid, User: $user)" >> "$MD_FILE"
            echo "  - **Command:** \`$cmdline\`" >> "$MD_FILE"
            echo "  - **CWD:** \`$cwd\`" >> "$MD_FILE"
            echo "  - **Executable:** \`$proc_exe\`" >> "$MD_FILE"
            echo "" >> "$MD_FILE"
        done
        echo "" >> "$MD_FILE"
    else
        echo "All detected processes are managed by systemd ✅" >> "$MD_FILE"
        echo "" >> "$MD_FILE"
    fi

    cat >> "$MD_FILE" << EOF

---

## Application Inventory

### Java Installations
EOF

    local jdk_count=0
    set +u
    jdk_count=${#JDK_INSTALLATIONS[@]}
    set -u
    if [[ $jdk_count -gt 0 ]]; then
        local jdk_num=1
        local i
        for ((i=0; i<jdk_count; i++)); do
            set +u
            local jdk="${JDK_INSTALLATIONS[$i]}"
            set -u
            local path=$(echo "$jdk" | grep -o '"path":"[^"]*"' | cut -d'"' -f4)
            local version=$(echo "$jdk" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            echo "$jdk_num. **Java** - $path" >> "$MD_FILE"
            echo "   - Version: $version" >> "$MD_FILE"
            ((jdk_num++))
        done
    else
        echo "No Java installations detected" >> "$MD_FILE"
    fi

    cat >> "$MD_FILE" << EOF

### Apache Tomcat
EOF

    local tomcat_count=0
    set +u
    tomcat_count=${#TOMCAT_INSTALLATIONS[@]}
    set -u
    if [[ $tomcat_count -gt 0 ]]; then
        local i
        for ((i=0; i<tomcat_count; i++)); do
            set +u
            local tomcat="${TOMCAT_INSTALLATIONS[$i]}"
            set -u
            local path=$(echo "$tomcat" | grep -o '"path":"[^"]*"' | cut -d'"' -f4)
            local version=$(echo "$tomcat" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            local running=$(echo "$tomcat" | grep -o '"running":[^,}]*' | cut -d':' -f2)
            echo "- **Location:** $path" >> "$MD_FILE"
            echo "- **Version:** $version" >> "$MD_FILE"
            echo "- **Status:** $([ "$running" == "true" ] && echo "Running ✅" || echo "Stopped")" >> "$MD_FILE"
        done
    else
        echo "No Tomcat installations detected" >> "$MD_FILE"
    fi

    cat >> "$MD_FILE" << EOF

### Oracle Database
EOF

    local oracle_count=0
    set +u
    oracle_count=${#ORACLE_HOMES[@]}
    set -u
    if [[ $oracle_count -gt 0 ]]; then
        local i
        for ((i=0; i<oracle_count; i++)); do
            set +u
            local oracle="${ORACLE_HOMES[$i]}"
            set -u
            local oracle_home=$(echo "$oracle" | grep -o '"oracle_home":"[^"]*"' | cut -d'"' -f4)
            local version=$(echo "$oracle" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            local sid=$(echo "$oracle" | grep -o '"sid":"[^"]*"' | cut -d'"' -f4)
            local running=$(echo "$oracle" | grep -o '"running":[^,}]*' | cut -d':' -f2)
            echo "- **Oracle Home:** $oracle_home" >> "$MD_FILE"
            echo "- **Version:** $version" >> "$MD_FILE"
            echo "- **Instance:** $sid ($([ "$running" == "true" ] && echo "RUNNING" || echo "STOPPED"))" >> "$MD_FILE"
        done
    else
        echo "No Oracle Database installations detected" >> "$MD_FILE"
    fi

    cat >> "$MD_FILE" << EOF

### Web Servers
EOF

    local web_count=0
    set +u
    web_count=${#WEB_SERVERS[@]}
    set -u
    if [[ $web_count -gt 0 ]]; then
        local i
        for ((i=0; i<web_count; i++)); do
            set +u
            local web="${WEB_SERVERS[$i]}"
            set -u
            local type=$(echo "$web" | grep -o '"type":"[^"]*"' | cut -d'"' -f4)
            local version=$(echo "$web" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            local running=$(echo "$web" | grep -o '"running":[^,}]*' | cut -d':' -f2)
            echo "- **$type:** $version ($([ "$running" == "true" ] && echo "Running ✅" || echo "Stopped"))" >> "$MD_FILE"
        done
    else
        echo "No web servers detected" >> "$MD_FILE"
    fi

    cat >> "$MD_FILE" << EOF

### Ellucian Banner
EOF

    local banner_count=0
    set +u
    banner_count=${#BANNER_COMPONENTS[@]}
    set -u
    if [[ $banner_count -gt 0 ]]; then
        local i
        for ((i=0; i<banner_count; i++)); do
            set +u
            local banner="${BANNER_COMPONENTS[$i]}"
            set -u
            local path=$(echo "$banner" | grep -o '"path":"[^"]*"' | cut -d'"' -f4)
            echo "- Banner installation found: $path" >> "$MD_FILE"
        done
    else
        echo "No Banner components detected" >> "$MD_FILE"
    fi

    cat >> "$MD_FILE" << EOF

---

## Remediation Plan

EOF

    # Sort and output remediation by priority
    for priority in "CRITICAL" "HIGH" "MEDIUM" "LOW"; do
        local priority_icon="🟢"
        [[ "$priority" == "CRITICAL" ]] && priority_icon="🔴"
        [[ "$priority" == "HIGH" ]] && priority_icon="🟠"
        [[ "$priority" == "MEDIUM" ]] && priority_icon="🟡"

        cat >> "$MD_FILE" << EOF
### $priority_icon $priority Priority

EOF

        for rem in "${REMEDIATION_ITEMS[@]}"; do
            if echo "$rem" | grep -q "\"priority\":\"$priority\""; then
                local id=$(echo "$rem" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
                local title=$(echo "$rem" | grep -o '"title":"[^"]*"' | cut -d'"' -f4)
                local description=$(echo "$rem" | grep -o '"description":"[^"]*"' | cut -d'"' -f4)
                local impact=$(echo "$rem" | grep -o '"impact":"[^"]*"' | cut -d'"' -f4)
                local effort=$(echo "$rem" | grep -o '"effort":"[^"]*"' | cut -d'"' -f4)
                local risk=$(echo "$rem" | grep -o '"risk":"[^"]*"' | cut -d'"' -f4)

                cat >> "$MD_FILE" << EOF
#### $id: $title

**Description:** $description

**Impact:** $impact

**Effort:** $effort
**Risk:** $risk

EOF
            fi
        done
    done

    cat >> "$MD_FILE" << EOF

---

**Report Generated by:** RHEL Assessment Script v$SCRIPT_VERSION
**End of Report**
EOF

    log_info "Markdown report written to: $MD_FILE"
}

################################################################################
# CREATE SYMLINKS
################################################################################

create_symlinks() {
    log_info "Creating symlinks to latest assessment..."

    cd "$LOGS_DIR" || return

    ln -sf "$(basename "$LOG_FILE")" "latest-assessment.log"
    ln -sf "$(basename "$JSON_FILE")" "latest-assessment.json"

    log_info "Symlinks created"
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    init_logging
    check_privileges

    log_info "Starting server assessment..."

    # Execute all phases
    phase1_system_identification
    phase2_storage_assessment
    phase3_network_assessment
    phase4_time_and_date
    phase5_os_lifecycle
    phase6_package_management
    phase7_security_assessment
    phase8_system_configuration
    phase9_application_detection
    phase10_process_analysis

    # Generate remediation recommendations
    generate_remediation_recommendations

    # Generate outputs
    log_info "Starting output generation..."
    generate_json_output
    generate_markdown_output
    create_symlinks

    # Final summary
    {
        echo "=================================================="
        echo "Assessment Complete"
        echo "=================================================="
        echo "Log File: $LOG_FILE"
        echo "JSON Report: $JSON_FILE"
        echo "Markdown Report: $MD_FILE"
        echo "=================================================="
        echo "Total Checks Failed: $FAILED_CHECKS"
        echo "Total Remediation Recommendations: ${#REMEDIATION_ITEMS[@]}"
        echo "=================================================="
    } | tee -a "$LOG_FILE"

    log_info "Assessment completed successfully"

    # Display quick summary
    echo ""
    echo "Quick Summary:"
    echo "- OS: ${OS_INFO[name]} ${OS_INFO[version]} (EOL: ${OS_INFO[eol_date]:-Unknown})"
    echo "- Total Packages: ${SYSTEM_INFO[total_packages]:-0}"
    echo "- Updates Available: ${SYSTEM_INFO[updates_available]:-0} (${SYSTEM_INFO[security_updates_available]:-0} security)"
    set +u
    echo "- Remediation Items: ${#REMEDIATION_ITEMS[@]}"
    set -u
    echo ""
    echo "Review the Markdown report for detailed findings:"
    echo "  cat $MD_FILE"
    echo ""
}

# Execute main function
main "$@"
