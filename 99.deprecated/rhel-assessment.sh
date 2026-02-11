#!/bin/bash

################################################################################
# RHEL Server Remediation Script
#
# Purpose: Remediate neglected RHEL servers by updating OS, removing GUI
#          packages, configuring systemd, and creating service units.
#
# Requirements: Must run as root on RHEL 7, 8, or 9
# Usage: ./rhel-remediation.sh [--dry-run]
################################################################################

set -euo pipefail

# Error handler function
error_handler() {
    local line_number=$1
    local command="$2"
    echo ""
    echo "================================================================"
    echo "ERROR: Script failed at line $line_number"
    echo "Command: $command"
    echo "================================================================"
    echo ""
    echo "Stack trace:"
    local frame=0
    while caller $frame; do
        ((frame++))
    done
    echo ""
    echo "Please check the verbose log for more details."
    exit 1
}

# Set up error trap
trap 'error_handler ${LINENO} "$BASH_COMMAND"' ERR

# Script metadata
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SCRIPT_LOG="${SCRIPT_DIR}/remediation-$(date +%Y%m%d-%H%M%S).log"
VERBOSE_LOG="${SCRIPT_DIR}/remediation-verbose-$(date +%Y%m%d-%H%M%S).log"
STATE_FILE="${SCRIPT_DIR}/remediation-state.conf"
ROLLBACK_DOC="${SCRIPT_DIR}/rollback-$(date +%Y%m%d).txt"
BACKUP_DATE=$(date +%Y-%m-%d)

# Script state variables
DRY_RUN=false
ASSESS_ONLY=false
NEEDS_REBOOT=false
PHASE=0

# OS version variables
OS_VERSION=""
OS_MAJOR=""
OS_MINOR=""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Logging Functions
################################################################################

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        INFO)
            echo -e "${BLUE}[INFO]${NC} $message" | tee -a "$SCRIPT_LOG"
            echo "[$timestamp] [INFO] $message" >> "$VERBOSE_LOG"
            ;;
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} $message" | tee -a "$SCRIPT_LOG"
            echo "[$timestamp] [SUCCESS] $message" >> "$VERBOSE_LOG"
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} $message" | tee -a "$SCRIPT_LOG"
            echo "[$timestamp] [WARN] $message" >> "$VERBOSE_LOG"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} $message" | tee -a "$SCRIPT_LOG"
            echo "[$timestamp] [ERROR] $message" >> "$VERBOSE_LOG"
            ;;
        *)
            echo "$message" | tee -a "$SCRIPT_LOG"
            echo "[$timestamp] $message" >> "$VERBOSE_LOG"
            ;;
    esac
}

log_verbose() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $*" >> "$VERBOSE_LOG"
}

log_command() {
    local cmd="$*"
    log_verbose "Executing: $cmd"
    if $DRY_RUN; then
        log INFO "[DRY-RUN] Would execute: $cmd"
        return 0
    fi
    eval "$cmd" 2>&1 | tee -a "$VERBOSE_LOG"
    return ${PIPESTATUS[0]}
}

################################################################################
# State Management Functions
################################################################################

init_state_file() {
    if [[ ! -f "$STATE_FILE" ]]; then
        cat > "$STATE_FILE" <<'EOF'
# RHEL Remediation Script State File
# Format: KEY=VALUE
# Boolean values: true/false
# Updated: TIMESTAMP

# Current phase (0-7)
PHASE=0

# Timestamp of last update
TIMESTAMP=INIT

# Tasks that need to be performed
TASK_SET_RUNLEVEL=false
TASK_CONFIGURE_YUM_GROUPS=false
TASK_REMOVE_GUI_PACKAGES=false
TASK_UPDATE_PACKAGES=false
TASK_OS_UPDATE=false
TASK_CREATE_SYSTEMD_UNITS=false

# User approvals for tasks
APPROVED_SET_RUNLEVEL=false
APPROVED_CONFIGURE_YUM_GROUPS=false
APPROVED_REMOVE_GUI_PACKAGES=false
APPROVED_UPDATE_PACKAGES=false
APPROVED_OS_UPDATE=false
APPROVED_CREATE_SYSTEMD_UNITS=false
APPROVED_REBOOT=false

# Completed tasks
COMPLETED_SET_RUNLEVEL=false
COMPLETED_CONFIGURE_YUM_GROUPS=false
COMPLETED_REMOVE_GUI_PACKAGES=false
COMPLETED_UPDATE_PACKAGES=false
COMPLETED_OS_UPDATE=false
COMPLETED_CREATE_SYSTEMD_UNITS=false

# System state flags
REBOOT_REQUIRED=false
POST_REBOOT_VALIDATION=false
EOF
        update_state_timestamp
    fi
}

read_state() {
    local key="$1"
    if [[ -f "$STATE_FILE" ]]; then
        local value=$(grep "^${key}=" "$STATE_FILE" 2>/dev/null | cut -d= -f2- || true)
        echo "$value"
    else
        echo ""
    fi
}

update_state() {
    local key="$1"
    local value="$2"

    if [[ -f "$STATE_FILE" ]]; then
        # Check if key exists
        if grep -q "^${key}=" "$STATE_FILE"; then
            # Update existing key
            sed -i "s|^${key}=.*|${key}=${value}|" "$STATE_FILE"
        else
            # Add new key
            echo "${key}=${value}" >> "$STATE_FILE"
        fi
        update_state_timestamp
    fi
}

update_state_timestamp() {
    if [[ -f "$STATE_FILE" ]]; then
        local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
        sed -i "s|^TIMESTAMP=.*|TIMESTAMP=${timestamp}|" "$STATE_FILE"
    fi
}

################################################################################
# Utility Functions
################################################################################

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "This script must be run as root"
        exit 1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                log INFO "Running in DRY-RUN mode - no changes will be made"
                ;;
            --assess-only)
                ASSESS_ONLY=true
                log INFO "Running in ASSESSMENT-ONLY mode - only environment assessment will be performed"
                ;;
            -h|--help)
                cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Options:
  --dry-run       Preview changes without executing them
  --assess-only   Only perform environment assessment (no remediation)
  -h, --help      Show this help message

Description:
  Performs remediation tasks on neglected RHEL servers including:
  - OS updates (minor version only)
  - Package updates and cleanup
  - GUI package removal
  - Systemd configuration
  - Service unit creation for Tomcat applications

EOF
                exit 0
                ;;
            *)
                log ERROR "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
    done
}

ask_yes_no() {
    local prompt="$1"
    local response

    while true; do
        echo -ne "${YELLOW}$prompt [Y/N]: ${NC}"
        read -r response
        log_verbose "User response to '$prompt': $response"
        echo "User response: $response" >> "$SCRIPT_LOG"

        case "${response,,}" in
            y|yes)
                return 0
                ;;
            n|no)
                return 1
                ;;
            *)
                echo "Please answer Y or N"
                ;;
        esac
    done
}

################################################################################
# Phase 0: Initialization
################################################################################

phase_0_initialization() {
    log INFO "================================================"
    log INFO "PHASE 0: Initialization"
    log INFO "================================================"

    echo "Script Log: $SCRIPT_LOG"
    echo "Verbose Log: $VERBOSE_LOG"
    echo "State File: $STATE_FILE"

    init_state_file

    # Create rollback document header
    cat > "$ROLLBACK_DOC" <<EOF
RHEL Server Remediation - Rollback Documentation
Generated: $(date)
================================================

This document contains information needed to rollback changes made by the remediation script.

EOF

    log SUCCESS "Initialization complete"
}

################################################################################
# Phase 1: Environment Assessment
################################################################################

check_disk_space() {
    log INFO "Checking disk space..."

    local root_avail=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    local var_avail=$(df -BG /var | awk 'NR==2 {print $4}' | sed 's/G//')

    log INFO "  / partition: ${root_avail}GB available"
    log INFO "  /var partition: ${var_avail}GB available"

    if [[ $root_avail -lt 5 ]]; then
        log ERROR "Insufficient space on / partition (${root_avail}GB < 5GB required)"
        return 1
    fi

    if [[ $var_avail -lt 5 ]]; then
        log ERROR "Insufficient space on /var partition (${var_avail}GB < 5GB required)"
        return 1
    fi

    log SUCCESS "Disk space check passed"
    return 0
}

check_network() {
    log INFO "Checking network connectivity..."

    local repos=("redhat.com" "access.redhat.com" "cdn.redhat.com")

    for repo in "${repos[@]}"; do
        if timeout 5 ping -c 1 "$repo" &>/dev/null; then
            log SUCCESS "  Connection to $repo: OK"
            return 0
        else
            log_verbose "  Connection to $repo: FAILED"
        fi
    done

    log ERROR "Cannot reach any Red Hat repositories"
    return 1
}

detect_os_version() {
    log INFO "Detecting OS version..."

    if [[ ! -f /etc/redhat-release ]]; then
        log ERROR "Not a Red Hat-based system"
        exit 1
    fi

    local os_info=$(cat /etc/redhat-release)
    log INFO "  $os_info"

    # Extract major and minor version
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_VERSION="$VERSION_ID"
        OS_MAJOR="${VERSION_ID%%.*}"
        OS_MINOR="${VERSION_ID#*.}"
        log INFO "  Version: $OS_VERSION (Major: $OS_MAJOR, Minor: $OS_MINOR)"
    else
        log ERROR "Cannot determine OS version"
        exit 1
    fi

    # Check EOL status via endoflife.date API
    check_eol_status
}

check_eol_status() {
    log INFO "Checking EOL status..."

    # The API returns an array of versions, we need to get the right one
    local eol_data=$(curl -s "https://endoflife.date/api/rhel.json" 2>/dev/null || echo "")

    if [[ -n "$eol_data" ]]; then
        # Extract EOL date for the specific version
        local eol_date=$(echo "$eol_data" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    version = '${OS_VERSION}'
    # Try exact match first
    for item in data:
        if str(item.get('cycle', '')) == version or str(item.get('cycle', '')) == '${OS_MAJOR}':
            print(item.get('eol', 'unknown'))
            sys.exit(0)
    print('unknown')
except:
    print('unknown')
" 2>/dev/null || echo "unknown")

        if [[ "$eol_date" != "unknown" ]]; then
            local current_date=$(date +%s)
            local eol_timestamp=$(date -d "$eol_date" +%s 2>/dev/null || echo "0")

            if [[ $eol_timestamp -lt $current_date ]]; then
                log ERROR "  RHEL $OS_VERSION is END OF LIFE (EOL: $eol_date)"
            else
                local days_until_eol=$(( (eol_timestamp - current_date) / 86400 ))
                if [[ $days_until_eol -lt 365 ]]; then
                    log WARN "  RHEL $OS_VERSION approaching EOL (EOL: $eol_date, ${days_until_eol} days remaining)"
                else
                    log SUCCESS "  RHEL $OS_VERSION is supported (EOL: $eol_date)"
                fi
            fi
        else
            log WARN "  Could not determine EOL status for RHEL $OS_VERSION"
        fi
    else
        log WARN "  Could not retrieve EOL information from API"
    fi
}

get_system_stats() {
    log INFO "System Statistics:"
    log INFO "  Uptime: $(uptime -p 2>/dev/null || uptime)"
    log INFO "  Load Average: $(cat /proc/loadavg | awk '{print $1, $2, $3}')"
    log INFO "  Memory: $(free -h | awk 'NR==2 {print $3 " used / " $2 " total"}')"
    log INFO "  CPU Count: $(nproc)"
}

detect_non_system_processes() {
    log INFO "Detecting non-system processes..."

    # Find processes not managed by systemd
    local process_list=$(ps aux | grep -v '\[' | grep -v 'systemd' | awk '{print $11}' | sort -u | grep '^/')

    echo "$process_list" | while read -r proc; do
        if [[ -n "$proc" ]] && [[ -x "$proc" ]]; then
            # Check if managed by systemd
            local pid=$(pgrep -f "$proc" | head -1)
            if [[ -n "$pid" ]]; then
                local systemd_service=$(systemctl status "$pid" 2>/dev/null | grep -o '[^ ]*\.service' | head -1)
                if [[ -z "$systemd_service" ]]; then
                    log INFO "  Not managed by systemd: $proc"
                fi
            fi
        fi
    done
}

detect_tomcat() {
    log INFO "Detecting Tomcat installations..."

    local tomcat_found=false

    # Search common locations and /u* directories
    for search_path in /opt /usr/local /u* /home; do
        if [[ -d "$search_path" ]]; then
            while IFS= read -r catalina; do
                local tomcat_dir=$(dirname "$(dirname "$catalina")")
                log INFO "  Found Tomcat at: $tomcat_dir"

                # Try to get version
                local version=""
                if [[ -f "$tomcat_dir/RELEASE-NOTES" ]]; then
                    version=$(grep -m 1 "Apache Tomcat Version" "$tomcat_dir/RELEASE-NOTES" | awk '{print $4}')
                    log INFO "    Version: $version"
                elif [[ -f "$tomcat_dir/lib/catalina.jar" ]]; then
                    version=$(unzip -p "$tomcat_dir/lib/catalina.jar" org/apache/catalina/util/ServerInfo.properties 2>/dev/null | grep "server.number" | cut -d= -f2)
                    log INFO "    Version: $version"
                fi

                # Check EOL status for this Tomcat version
                if [[ -n "$version" ]]; then
                    check_tomcat_eol_status "$version"
                fi

                tomcat_found=true
            done < <(find "$search_path" -name "catalina.sh" 2>/dev/null)
        fi
    done

    if ! $tomcat_found; then
        log WARN "  No Tomcat installations detected"
    fi
}

check_tomcat_eol_status() {
    local tomcat_version="$1"

    # Extract major version (e.g., "8.0.41" -> "8")
    local major_version="${tomcat_version%%.*}"

    log_verbose "Checking EOL status for Tomcat $tomcat_version..."

    # Query the endoflife.date API for Tomcat
    local eol_data=$(curl -s "https://endoflife.date/api/tomcat.json" 2>/dev/null || echo "")

    if [[ -n "$eol_data" ]]; then
        # Extract EOL date for the specific major version
        local eol_date=$(echo "$eol_data" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    version = '${major_version}'
    # Find matching cycle
    for item in data:
        cycle = str(item.get('cycle', ''))
        if cycle == version:
            eol = item.get('eol')
            if eol == True:
                print('EOL')
            elif eol == False:
                print('SUPPORTED')
            else:
                print(eol)
            sys.exit(0)
    print('unknown')
except:
    print('unknown')
" 2>/dev/null || echo "unknown")

        if [[ "$eol_date" == "unknown" ]]; then
            log_verbose "      Could not determine EOL status for Tomcat $major_version"
        elif [[ "$eol_date" == "EOL" ]]; then
            log ERROR "      Tomcat $major_version is END OF LIFE"
        elif [[ "$eol_date" == "SUPPORTED" ]]; then
            log SUCCESS "      Tomcat $major_version is still supported"
        else
            # eol_date is an actual date
            local current_date=$(date +%s)
            local eol_timestamp=$(date -d "$eol_date" +%s 2>/dev/null || echo "0")

            if [[ $eol_timestamp -lt $current_date ]]; then
                log ERROR "      Tomcat $major_version is END OF LIFE (EOL: $eol_date)"
            else
                local days_until_eol=$(( (eol_timestamp - current_date) / 86400 ))
                if [[ $days_until_eol -lt 365 ]]; then
                    log WARN "      Tomcat $major_version approaching EOL (EOL: $eol_date, ${days_until_eol} days remaining)"
                else
                    log SUCCESS "      Tomcat $major_version is supported (EOL: $eol_date)"
                fi
            fi
        fi
    else
        log_verbose "      Could not retrieve EOL information from API for Tomcat"
    fi
}

detect_java() {
    log INFO "Detecting Java installations..."

    # Check system Java
    if command -v java &>/dev/null; then
        local java_version=$(java -version 2>&1 | head -1)
        log INFO "  System Java: $java_version"
    fi

    # Check for Java in /u* directories
    for search_path in /u*; do
        if [[ -d "$search_path" ]]; then
            while IFS= read -r java_bin; do
                local java_home=$(dirname "$(dirname "$java_bin")")
                log INFO "  Found Java at: $java_home"
                local version=$("$java_bin" -version 2>&1 | head -1)
                log INFO "    Version: $version"
            done < <(find "$search_path" -path "*/bin/java" -type f 2>/dev/null)
        fi
    done
}

check_package_updates() {
    log INFO "Checking for package updates..."

    local updates_available=$(yum check-update 2>/dev/null | grep -v '^$' | grep -v 'Loading' | grep -v 'Loaded plugins' | tail -n +2 | wc -l)

    log INFO "  Updates available: $updates_available packages"

    if [[ $updates_available -gt 0 ]]; then
        update_state "TASK_UPDATE_PACKAGES" "true"
    fi
}

check_systemd_target() {
    log INFO "Checking systemd default target..."

    local current_target=$(systemctl get-default)
    log INFO "  Current target: $current_target"

    if [[ "$current_target" != "multi-user.target" ]]; then
        log WARN "  Target is not multi-user.target"
        update_state "TASK_SET_RUNLEVEL" "true"
    else
        log SUCCESS "  Already set to multi-user.target"
    fi
}

check_yum_groups() {
    log INFO "Checking yum configuration for groups..."

    # Check if yum groups are enabled
    local groups_enabled=true

    if yum group list 2>&1 | grep -q "No groups"; then
        log WARN "  Yum groups not properly configured"
        update_state "TASK_CONFIGURE_YUM_GROUPS" "true"
        groups_enabled=false
    else
        log SUCCESS "  Yum groups are configured"
    fi
}

check_gui_packages() {
    log INFO "Checking for GUI packages..."

    local gui_groups=("GNOME Desktop" "KDE Plasma Workspaces" "Xfce" "Server with GUI" "GNOME" "KDE")
    local gui_packages=("firefox" "pulseaudio" "xorg-x11-server-Xorg" "gnome-shell" "kde-workspace" "thunderbird")
    local gui_found=false

    # Check for GUI package groups
    log_verbose "Checking for GUI package groups..."
    local installed_groups=$(yum group list installed 2>/dev/null)
    for group in "${gui_groups[@]}"; do
        if echo "$installed_groups" | grep -qi "$group"; then
            log INFO "  Found group: $group"
            gui_found=true
        fi
    done

    # Check for individual GUI packages
    log_verbose "Checking for individual GUI packages..."
    for pkg in "${gui_packages[@]}"; do
        local pkg_check=$(yum list installed "$pkg" 2>/dev/null)
        if echo "$pkg_check" | grep -q "^${pkg}\."; then
            log INFO "  Found package: $pkg"
            gui_found=true
        fi
    done

    if $gui_found; then
        update_state "TASK_REMOVE_GUI_PACKAGES" "true"
    else
        log SUCCESS "  No GUI packages detected"
    fi
}

phase_1_environment_assessment() {
    log INFO "================================================"
    log INFO "PHASE 1: Environment Assessment"
    log INFO "================================================"

    # Safety checks - abort if any fail
    if ! check_disk_space; then
        log ERROR "Safety check failed: Insufficient disk space"
        exit 1
    fi

    if ! check_network; then
        log ERROR "Safety check failed: No network connectivity"
        exit 1
    fi

    # OS and system info
    detect_os_version
    get_system_stats

    # Process and application detection
    detect_non_system_processes
    detect_tomcat
    detect_java

    # Package and configuration checks
    check_package_updates
    check_systemd_target
    check_yum_groups
    check_gui_packages

    log SUCCESS "Environment assessment complete"
    update_state "PHASE" "1"
}

################################################################################
# Phase 2: Remediation Plan
################################################################################

phase_2_remediation_plan() {
    log INFO "================================================"
    log INFO "PHASE 2: Remediation Plan"
    log INFO "================================================"

    log INFO "The following tasks will be performed (if approved):"
    echo ""

    local task_count=0

    # Check each task
    local set_runlevel=$(read_state "TASK_SET_RUNLEVEL")
    if [[ "$set_runlevel" == "true" ]]; then
        ((task_count++))
        log INFO "  [$task_count] Set systemd default target to multi-user.target"
    fi

    local configure_yum=$(read_state "TASK_CONFIGURE_YUM_GROUPS")
    if [[ "$configure_yum" == "true" ]]; then
        ((task_count++))
        log INFO "  [$task_count] Configure yum to use package groups"
    fi

    local remove_gui=$(read_state "TASK_REMOVE_GUI_PACKAGES")
    if [[ "$remove_gui" == "true" ]]; then
        ((task_count++))
        log INFO "  [$task_count] Remove GUI and desktop environment packages"
    fi

    local update_pkgs=$(read_state "TASK_UPDATE_PACKAGES")
    if [[ "$update_pkgs" == "true" ]]; then
        ((task_count++))
        log INFO "  [$task_count] Update all packages to latest versions"
    fi

    # Always offer OS update to latest minor version
    ((task_count++))
    log INFO "  [$task_count] Update OS to latest minor version within RHEL $OS_MAJOR"
    update_state "TASK_OS_UPDATE" "true"

    # Always offer to create systemd units for Tomcat
    ((task_count++))
    log INFO "  [$task_count] Create systemd service units for Tomcat instances"
    update_state "TASK_CREATE_SYSTEMD_UNITS" "true"

    echo ""

    if [[ $task_count -eq 0 ]]; then
        log SUCCESS "No remediation tasks required!"
        exit 0
    fi

    log INFO "Total tasks: $task_count"
    log SUCCESS "Remediation plan complete"
    update_state "PHASE" "2"
}

################################################################################
# Phase 3: Request Approval
################################################################################

phase_3_request_approval() {
    log INFO "================================================"
    log INFO "PHASE 3: Request Approval"
    log INFO "================================================"

    if $DRY_RUN; then
        log INFO "[DRY-RUN] Skipping approval requests"
        return 0
    fi

    log INFO "Please approve each remediation task:"
    echo ""

    # Set runlevel
    local set_runlevel=$(read_state "TASK_SET_RUNLEVEL")
    if [[ "$set_runlevel" == "true" ]]; then
        local current_target=$(systemctl get-default)
        if ask_yes_no "Set systemd target from $current_target to multi-user.target?"; then
            update_state "APPROVED_SET_RUNLEVEL" "true"
            NEEDS_REBOOT=true
        fi
    fi

    # Configure yum groups
    local configure_yum=$(read_state "TASK_CONFIGURE_YUM_GROUPS")
    if [[ "$configure_yum" == "true" ]]; then
        if ask_yes_no "Configure yum to use package groups?"; then
            update_state "APPROVED_CONFIGURE_YUM_GROUPS" "true"
        fi
    fi

    # Remove GUI packages
    local remove_gui=$(read_state "TASK_REMOVE_GUI_PACKAGES")
    if [[ "$remove_gui" == "true" ]]; then
        if ask_yes_no "Remove all GUI and desktop environment packages?"; then
            update_state "APPROVED_REMOVE_GUI_PACKAGES" "true"
            NEEDS_REBOOT=true
        fi
    fi

    # Update packages
    local update_pkgs=$(read_state "TASK_UPDATE_PACKAGES")
    if [[ "$update_pkgs" == "true" ]]; then
        if ask_yes_no "Update all installed packages to latest versions?"; then
            update_state "APPROVED_UPDATE_PACKAGES" "true"
            NEEDS_REBOOT=true
        fi
    fi

    # OS update
    if ask_yes_no "Update OS to latest minor version within RHEL $OS_MAJOR?"; then
        update_state "APPROVED_OS_UPDATE" "true"
        NEEDS_REBOOT=true
    fi

    # Create systemd units
    if ask_yes_no "Create systemd service units for Tomcat instances?"; then
        update_state "APPROVED_CREATE_SYSTEMD_UNITS" "true"
    fi

    echo ""
    log SUCCESS "Approval phase complete"
    update_state "PHASE" "3"
}

################################################################################
# Phase 4: Execution
################################################################################

backup_system_state() {
    log INFO "Creating system backup..."

    local backup_dir="${SCRIPT_DIR}/backup-${BACKUP_DATE}"
    mkdir -p "$backup_dir"

    # Backup package list
    log INFO "  Backing up package list..."
    rpm -qa | sort > "${backup_dir}/packages.txt"
    log_verbose "Package list saved to ${backup_dir}/packages.txt"

    # Add to rollback document
    cat >> "$ROLLBACK_DOC" <<EOF

PACKAGE LIST BACKUP
-------------------
Location: ${backup_dir}/packages.txt

To restore packages to this state:
1. Review the package list
2. Use 'yum install <package>' for missing packages
3. Use 'yum remove <package>' for unwanted packages

EOF

    # Backup yum configuration
    if [[ -f /etc/yum.conf ]]; then
        log INFO "  Backing up yum configuration..."
        cp /etc/yum.conf "${backup_dir}/yum.conf.bak-${BACKUP_DATE}"

        cat >> "$ROLLBACK_DOC" <<EOF
YUM CONFIGURATION BACKUP
------------------------
Original: /etc/yum.conf
Backup: ${backup_dir}/yum.conf.bak-${BACKUP_DATE}

To restore: cp ${backup_dir}/yum.conf.bak-${BACKUP_DATE} /etc/yum.conf

EOF
    fi

    # Backup systemd default target
    local current_target=$(systemctl get-default)
    echo "$current_target" > "${backup_dir}/systemd-default-target.txt"

    cat >> "$ROLLBACK_DOC" <<EOF
SYSTEMD DEFAULT TARGET
----------------------
Original: $current_target
Backup: ${backup_dir}/systemd-default-target.txt

To restore: systemctl set-default $current_target

EOF

    log SUCCESS "Backup complete: $backup_dir"
}

execute_set_runlevel() {
    if [[ "$(read_state "APPROVED_SET_RUNLEVEL")" == "true" ]]; then
        log INFO "Setting systemd default target to multi-user.target..."

        if ! $DRY_RUN; then
            systemctl set-default multi-user.target >> "$VERBOSE_LOG" 2>&1
            update_state "COMPLETED_SET_RUNLEVEL" "true"
            log SUCCESS "Systemd target set to multi-user.target"
        else
            log INFO "[DRY-RUN] Would set systemd target to multi-user.target"
        fi
    fi
}

execute_configure_yum_groups() {
    if [[ "$(read_state "APPROVED_CONFIGURE_YUM_GROUPS")" == "true" ]]; then
        log INFO "Configuring yum for package groups..."

        if ! $DRY_RUN; then
            # Ensure group_command is set
            if ! grep -q "^group_command=objects" /etc/yum.conf 2>/dev/null; then
                echo "group_command=objects" >> /etc/yum.conf
            fi

            # Update group metadata
            yum groups mark convert >> "$VERBOSE_LOG" 2>&1 || true

            update_state "COMPLETED_CONFIGURE_YUM_GROUPS" "true"
            log SUCCESS "Yum groups configured"
        else
            log INFO "[DRY-RUN] Would configure yum groups"
        fi
    fi
}

execute_remove_gui() {
    if [[ "$(read_state "APPROVED_REMOVE_GUI_PACKAGES")" == "true" ]]; then
        log INFO "Removing GUI packages..."

        local gui_groups=("gnome-desktop" "kde-desktop" "xfce-desktop" "Server with GUI")
        local gui_packages=("firefox" "pulseaudio" "thunderbird" "evolution")

        if ! $DRY_RUN; then
            # Remove groups
            for group in "${gui_groups[@]}"; do
                if yum group list installed | grep -qi "$group"; then
                    log INFO "  Removing group: $group"
                    yum -y group remove "$group" >> "$VERBOSE_LOG" 2>&1 || true
                fi
            done

            # Remove individual packages
            for pkg in "${gui_packages[@]}"; do
                if yum list installed "$pkg" &>/dev/null; then
                    log INFO "  Removing package: $pkg"
                    yum -y remove "$pkg" >> "$VERBOSE_LOG" 2>&1 || true
                fi
            done

            update_state "COMPLETED_REMOVE_GUI_PACKAGES" "true"
            log SUCCESS "GUI packages removed"
        else
            log INFO "[DRY-RUN] Would remove GUI packages"
        fi
    fi
}

execute_update_packages() {
    if [[ "$(read_state "APPROVED_UPDATE_PACKAGES")" == "true" ]]; then
        log INFO "Updating packages..."

        if ! $DRY_RUN; then
            yum -y update >> "$VERBOSE_LOG" 2>&1
            update_state "COMPLETED_UPDATE_PACKAGES" "true"
            log SUCCESS "Packages updated"
        else
            log INFO "[DRY-RUN] Would update all packages"
        fi
    fi
}

execute_os_update() {
    if [[ "$(read_state "APPROVED_OS_UPDATE")" == "true" ]]; then
        log INFO "Updating OS to latest minor version..."

        if ! $DRY_RUN; then
            # Update to latest minor version within major release
            yum -y update --releasever=${OS_MAJOR} >> "$VERBOSE_LOG" 2>&1
            update_state "COMPLETED_OS_UPDATE" "true"
            log SUCCESS "OS updated to latest minor version"
        else
            log INFO "[DRY-RUN] Would update OS to latest RHEL $OS_MAJOR minor version"
        fi
    fi
}

create_tomcat_systemd_units() {
    if [[ "$(read_state "APPROVED_CREATE_SYSTEMD_UNITS")" == "true" ]]; then
        log INFO "Creating systemd units for Tomcat..."

        local unit_dir="${SCRIPT_DIR}/systemd-units"
        mkdir -p "$unit_dir"

        # Find Tomcat instances
        local tomcat_count=0
        for search_path in /opt /usr/local /u* /home; do
            if [[ -d "$search_path" ]]; then
                while IFS= read -r catalina; do
                    ((tomcat_count++))
                    local tomcat_dir=$(dirname "$(dirname "$catalina")")
                    local service_name="tomcat-$(basename "$tomcat_dir")"
                    local unit_file="${unit_dir}/${service_name}.service"

                    log INFO "  Creating unit for: $tomcat_dir"

                    # Try to find Java home
                    local java_home=""
                    if [[ -f "${tomcat_dir}/setenv.sh" ]] && grep -q "JAVA_HOME" "${tomcat_dir}/setenv.sh"; then
                        java_home=$(grep "JAVA_HOME" "${tomcat_dir}/setenv.sh" | head -1 | cut -d= -f2 | tr -d '"' | tr -d "'")
                    elif command -v java &>/dev/null; then
                        java_home=$(dirname "$(dirname "$(readlink -f "$(which java)")")")
                    fi

                    # Create systemd unit file
                    cat > "$unit_file" <<EOF
[Unit]
Description=Apache Tomcat Web Application Container - ${tomcat_dir}
After=network.target

[Service]
Type=forking
User=root
Group=root

Environment="CATALINA_HOME=${tomcat_dir}"
Environment="CATALINA_BASE=${tomcat_dir}"
${java_home:+Environment="JAVA_HOME=${java_home}"}

ExecStart=${tomcat_dir}/bin/startup.sh
ExecStop=${tomcat_dir}/bin/shutdown.sh

SuccessExitStatus=143
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

                    log SUCCESS "  Created: $unit_file"

                done < <(find "$search_path" -name "catalina.sh" 2>/dev/null)
            fi
        done

        if [[ $tomcat_count -gt 0 ]]; then
            log INFO ""
            log INFO "Created $tomcat_count systemd unit file(s) in: $unit_dir"

            if ! $DRY_RUN; then
                if ask_yes_no "Review and approve moving systemd unit files to /etc/systemd/system/?"; then
                    for unit_file in "$unit_dir"/*.service; do
                        if [[ -f "$unit_file" ]]; then
                            local unit_name=$(basename "$unit_file")
                            cp "$unit_file" "/etc/systemd/system/$unit_name"
                            log SUCCESS "  Installed: $unit_name"
                        fi
                    done

                    systemctl daemon-reload
                    log SUCCESS "Systemd units installed and daemon reloaded"

                    if ask_yes_no "Would you like to edit the systemd unit files before rebooting?"; then
                        log INFO "Unit files are located in /etc/systemd/system/"
                        log INFO "After editing, run: systemctl daemon-reload"
                        log INFO "The script will continue on next boot"

                        # Set script to run on next boot
                        setup_auto_run_on_boot
                        exit 0
                    fi
                else
                    log WARN "Systemd units created but not installed"
                fi
            else
                log INFO "[DRY-RUN] Would install systemd units"
            fi

            update_state "COMPLETED_CREATE_SYSTEMD_UNITS" "true"
        else
            log WARN "No Tomcat instances found"
        fi
    fi
}

setup_auto_run_on_boot() {
    log INFO "Configuring script to run on next boot..."

    local rc_local="/etc/rc.d/rc.local"
    local script_path="$SCRIPT_DIR/$SCRIPT_NAME"

    # Add to rc.local
    if ! grep -q "$script_path" "$rc_local" 2>/dev/null; then
        echo "" >> "$rc_local"
        echo "# Auto-run remediation script" >> "$rc_local"
        echo "$script_path" >> "$rc_local"
        chmod +x "$rc_local"

        log SUCCESS "Script will run automatically after next boot"
    fi
}

remove_auto_run_on_boot() {
    log INFO "Removing auto-run configuration..."

    local rc_local="/etc/rc.d/rc.local"
    local script_path="$SCRIPT_DIR/$SCRIPT_NAME"

    if [[ -f "$rc_local" ]] && grep -q "$script_path" "$rc_local"; then
        sed -i "\|$script_path|d" "$rc_local"
        sed -i '/# Auto-run remediation script/d' "$rc_local"
        log SUCCESS "Auto-run configuration removed"
    fi
}

phase_4_execution() {
    log INFO "================================================"
    log INFO "PHASE 4: Execution"
    log INFO "================================================"

    # Create backup before any changes
    backup_system_state

    # Execute approved tasks
    execute_set_runlevel
    execute_configure_yum_groups
    execute_remove_gui
    execute_update_packages
    execute_os_update
    create_tomcat_systemd_units

    log SUCCESS "Execution phase complete"
    update_state "PHASE" "4"

    if $NEEDS_REBOOT; then
        update_state "REBOOT_REQUIRED" "true"
    fi
}

################################################################################
# Phase 5: Restart
################################################################################

phase_5_restart() {
    log INFO "================================================"
    log INFO "PHASE 5: Restart"
    log INFO "================================================"

    local reboot_required=$(read_state "REBOOT_REQUIRED")

    if [[ "$reboot_required" == "true" ]] || $NEEDS_REBOOT; then
        if $DRY_RUN; then
            log INFO "[DRY-RUN] Would ask for permission to reboot"
            return 0
        fi

        if ask_yes_no "Reboot the server now to apply changes?"; then
            update_state "APPROVED_REBOOT" "true"

            # Set script to run after reboot for validation
            setup_auto_run_on_boot
            update_state "PHASE" "5"

            log INFO "Rebooting server now..."
            sleep 2
            reboot
        else
            log WARN "Reboot declined - server needs to be rebooted manually"
            log WARN "Run this script again after reboot for validation"
            update_state "PHASE" "5"
        fi
    else
        log INFO "No reboot required"
        update_state "PHASE" "5"
    fi
}

################################################################################
# Phase 6: Validate
################################################################################

phase_6_validate() {
    log INFO "================================================"
    log INFO "PHASE 6: Validation"
    log INFO "================================================"

    # Check if this is post-reboot
    local post_reboot=$(read_state "APPROVED_REBOOT")

    if [[ "$post_reboot" != "true" ]]; then
        log INFO "Skipping validation (no reboot performed)"
        return 0
    fi

    # Validate systemd target
    local current_target=$(systemctl get-default)
    if [[ "$current_target" == "multi-user.target" ]]; then
        log SUCCESS "Systemd target: $current_target ?"
    else
        log WARN "Systemd target: $current_target (expected multi-user.target)"
    fi

    # Check for Tomcat systemd units
    log INFO "Checking Tomcat systemd units..."
    local units_found=false
    for unit in /etc/systemd/system/tomcat-*.service; do
        if [[ -f "$unit" ]]; then
            local unit_name=$(basename "$unit")
            local status=$(systemctl is-active "$unit_name" 2>/dev/null || echo "inactive")
            log INFO "  $unit_name: $status"
            units_found=true
        fi
    done

    if ! $units_found; then
        log WARN "No Tomcat systemd units found"
    fi

    # Check for available updates
    local updates=$(yum check-update 2>/dev/null | grep -v '^$' | grep -v 'Loading' | grep -v 'Loaded plugins' | tail -n +2 | wc -l)
    if [[ $updates -eq 0 ]]; then
        log SUCCESS "Package updates: All packages up to date ?"
    else
        log WARN "Package updates: $updates updates still available"
    fi

    update_state "POST_REBOOT_VALIDATION" "true"
    update_state "PHASE" "6"

    log SUCCESS "Validation complete"
}

################################################################################
# Phase 7: Report
################################################################################

phase_7_report() {
    log INFO "================================================"
    log INFO "PHASE 7: Final Report"
    log INFO "================================================"

    # Remove auto-run if configured
    remove_auto_run_on_boot

    echo ""
    log INFO "REMEDIATION SUMMARY"
    log INFO "==================="
    echo ""

    # Report completed tasks
    log INFO "Completed Tasks:"

    if [[ "$(read_state "COMPLETED_SET_RUNLEVEL")" == "true" ]]; then
        log SUCCESS "  ? Set systemd target to multi-user.target"
    fi

    if [[ "$(read_state "COMPLETED_CONFIGURE_YUM_GROUPS")" == "true" ]]; then
        log SUCCESS "  ? Configured yum package groups"
    fi

    if [[ "$(read_state "COMPLETED_REMOVE_GUI_PACKAGES")" == "true" ]]; then
        log SUCCESS "  ? Removed GUI packages"
    fi

    if [[ "$(read_state "COMPLETED_UPDATE_PACKAGES")" == "true" ]]; then
        log SUCCESS "  ? Updated packages"
    fi

    if [[ "$(read_state "COMPLETED_OS_UPDATE")" == "true" ]]; then
        log SUCCESS "  ? Updated OS to latest minor version"
    fi

    if [[ "$(read_state "COMPLETED_CREATE_SYSTEMD_UNITS")" == "true" ]]; then
        log SUCCESS "  ? Created systemd service units"
    fi

    echo ""
    log INFO "Manual Steps Required:"
    echo ""

    # Check for any incomplete tasks
    local manual_steps_needed=false

    if [[ "$(read_state "TASK_CREATE_SYSTEMD_UNITS")" == "true" ]] && \
       [[ "$(read_state "COMPLETED_CREATE_SYSTEMD_UNITS")" != "true" ]]; then
        log WARN "  \Uffffffff Review and install systemd units from ${SCRIPT_DIR}/systemd-units/"
        manual_steps_needed=true
    fi

    if [[ "$(read_state "REBOOT_REQUIRED")" == "true" ]] && \
       [[ "$(read_state "APPROVED_REBOOT")" != "true" ]]; then
        log WARN "  \Uffffffff Reboot the server to apply changes"
        manual_steps_needed=true
    fi

    # Always recommend enabling and starting Tomcat services
    if [[ -d /etc/systemd/system ]] && ls /etc/systemd/system/tomcat-*.service &>/dev/null; then
        echo ""
        log INFO "  \Uffffffff Enable and start Tomcat services:"
        for unit in /etc/systemd/system/tomcat-*.service; do
            local unit_name=$(basename "$unit")
            log INFO "    systemctl enable $unit_name"
            log INFO "    systemctl start $unit_name"
        done
        manual_steps_needed=true
    fi

    if ! $manual_steps_needed; then
        log SUCCESS "  None - all tasks completed!"
    fi

    echo ""
    log INFO "Documentation:"
    log INFO "  Script Log: $SCRIPT_LOG"
    log INFO "  Verbose Log: $VERBOSE_LOG"
    log INFO "  Rollback Document: $ROLLBACK_DOC"
    log INFO "  State File: $STATE_FILE"

    echo ""
    log SUCCESS "========================================="
    log SUCCESS "RHEL Remediation Complete!"
    log SUCCESS "========================================="
}

################################################################################
# Main Execution
################################################################################

main() {
    # Parse arguments
    parse_args "$@"

    # Check requirements
    require_root

    # Always detect OS version (needed for all phases)
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_VERSION="$VERSION_ID"
        OS_MAJOR="${VERSION_ID%%.*}"
        OS_MINOR="${VERSION_ID#*.}"
    fi

    # Determine which phase to run
    if [[ -f "$STATE_FILE" ]]; then
        PHASE=$(read_state "PHASE")
        log INFO "Resuming from phase: $PHASE"
    fi

    # Execute phases
    if [[ $PHASE -lt 1 ]]; then
        phase_0_initialization
        phase_1_environment_assessment

        # Exit early if only doing assessment
        if $ASSESS_ONLY; then
            log SUCCESS "Environment assessment complete. Exiting (--assess-only mode)."
            exit 0
        fi
    fi

    if [[ $PHASE -lt 2 ]]; then
        phase_2_remediation_plan
    fi

    if [[ $PHASE -lt 3 ]]; then
        phase_3_request_approval
    fi

    if [[ $PHASE -lt 4 ]]; then
        phase_4_execution
    fi

    if [[ $PHASE -lt 5 ]]; then
        phase_5_restart
    fi

    if [[ $PHASE -lt 6 ]]; then
        phase_6_validate
    fi

    # Always run report at the end
    phase_7_report
}

# Run main function
main "$@"
