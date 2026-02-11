# 01 Assessment Script

The Assessment script is the first in a remediation suite designed for RHEL and
Rocky Linux servers. The purpose of this script is to gather information about
the server and then to generate a report that includes a remediation plan.

## Script Requirements

### Privileges
- Script MUST check if running with root privileges (UID 0)
- Script SHOULD support execution with sudo (detect via `sudo -n true 2>/dev/null`)
- If neither root nor sudo available, exit with clear error message
- All commands requiring elevated privileges should be prefixed appropriately

### Error Handling
- Use `set -u` to catch undefined variables
- DO NOT use `set -e` (script must continue on individual check failures)
- Each check should handle its own errors gracefully
- Failed checks should log WARNING or ERROR but not halt execution
- Track failed checks for summary reporting

### Bash Implementation Best Practices

**CRITICAL:** The following patterns MUST be followed when implementing in bash to avoid errors with `set -u`:

#### Data Structures
- Use **associative arrays** (`declare -A`) for key-value data (e.g., `OS_INFO`, `HARDWARE_INFO`)
- Use **regular arrays** (`declare -a`) for lists (e.g., `FILESYSTEMS`, `REMEDIATION_ITEMS`)
- Declare ALL arrays at the top of the script BEFORE any functions

#### Array Length Checking with `set -u`
When `set -u` is enabled, checking array lengths requires special handling:

**CORRECT:**
```bash
# For arrays that may have zero elements, check length safely
if [[ ${#MY_ARRAY[@]} -gt 0 ]] 2>/dev/null; then
    # Process array
fi

# OR use a counter stored in an associative array
SYSTEM_INFO[item_count]=0
# ... count items ...
if [[ ${SYSTEM_INFO[item_count]} -gt 0 ]]; then
    # Use the count
fi
```

**INCORRECT (will fail with set -u):**
```bash
# This syntax is INVALID for arrays
local count=${#MY_ARRAY[@]:-0}  # WRONG: Bad substitution error

# This will fail if array is unbound (even if declared)
if [[ ${#MY_ARRAY[@]} -eq 0 ]]; then  # May fail without 2>/dev/null
```

#### Counting Patterns

**CORRECT - Use pipe to wc -l:**
```bash
local count=$(command | grep "pattern" | wc -l)
local count=$(systemctl --failed --no-legend 2>/dev/null | awk '{print $1}' | wc -l)
```

**INCORRECT - Avoid grep -c with ||:**
```bash
# This creates "0\n0" output causing syntax errors
local count=$(command | grep -c "pattern" || echo 0)  # WRONG
```

**Why:** When `grep -c` finds 0 matches, it:
1. Outputs "0" to stdout
2. Returns exit code 1 (failure)
3. Triggers `|| echo 0`, outputting another "0"
4. Result: "0\n0" which causes `[[: 0\n0: syntax error`

**Solution:** Always use `grep | wc -l` instead of `grep -c`

#### Safe Array Iteration

When iterating over arrays that might be empty:

```bash
# Safe iteration - no error if array is empty
for item in "${MY_ARRAY[@]+"${MY_ARRAY[@]}"}"; do
    # Process item
done

# OR check first
if [[ ${#MY_ARRAY[@]} -gt 0 ]] 2>/dev/null; then
    for item in "${MY_ARRAY[@]}"; do
        # Process item
    done
fi
```

#### Storing Counts

For data that needs to be checked in multiple places, store counts in associative arrays:

```bash
# During collection phase
local item_count=0
while IFS= read -r item; do
    MY_ITEMS+=("$item")
    ((item_count++))
done < <(command)
SYSTEM_INFO[my_items_count]=$item_count

# During remediation phase
if [[ ${SYSTEM_INFO[my_items_count]:-0} -gt 0 ]]; then
    # Use the count safely
fi
```

#### Associative Array Access

Associative arrays support default values safely:

```bash
# Safe with default value
if [[ ${SYSTEM_INFO[some_key]:-0} -gt 0 ]]; then
    # This works fine
fi

# Access existing keys
value="${OS_INFO[version]}"
```

#### Variable Substitution

Use parameter expansion for safe defaults on scalar variables:

```bash
# Correct - works with scalars
local value=${SOME_VAR:-default}
local count=${SYSTEM_INFO[items]:-0}

# Incorrect - does NOT work with array lengths
local count=${#ARRAY[@]:-0}  # INVALID SYNTAX
```

#### Command Substitution Safety

```bash
# Good - handle command failures gracefully
local result=$(command 2>/dev/null || echo "unknown")
local count=$(command 2>/dev/null | wc -l)

# Avoid - grep -c with fallback causes double output
local count=$(command | grep -c pattern || echo 0)  # BAD
```

### Logging
- All output must be logged to both stdout and log file simultaneously
- Log file path: `logs/01-assessment-YYYYMMDD-HHMMSS.log`
- Log format: `[YYYY-MM-DD HH:MM:SS] LEVEL: message`
- Log levels: INFO, WARN, ERROR, DEBUG
- Create logs directory if it doesn't exist

## Target Environment

The assessment script is meant especially for RHEL 7, 8, 9 environments but
should also be compatible with Rocky Linux and Oracle Linux versions 7, 8, 9.

The assessment script is meant to be run on servers that provide a critical
service with no redundancy. It is therefore critical that the assessment script
does not change machine state.

The target environements are likely to serve a function of the Ellucian Banner
ERP infrastructure (including Oracle RDBMS and ORDS) but may also serve some
other function.

## Script Behavior

The high level process for the assessment script is to gather environment state,
evaluate current state, develop a remediation plan, generate remediation report.

### Execution Flow
1. Initialize logging and environment
2. Verify privileges (root or sudo)
3. Load previous assessment data (if exists) for comparison
4. Execute all assessment checks (organized in phases)
5. Evaluate collected data against best practices
6. Generate remediation recommendations with priorities
7. Compare with previous assessment and highlight changes
8. Write output files (JSON plan, Markdown report, log file)
9. Display summary and next steps

### Assessment Data Points

The assessment is organized into logical phases. Each phase contains specific checks.

#### Phase 1: System Identification
- **OS Detection**
  - Read `/etc/os-release` for distribution name, version, ID
  - Capture kernel version from `uname -r`
  - Detect package manager (yum, dnf, apt)
  - Determine if system is RHEL, Rocky, Oracle, or CentOS variant
  - Store: `os_name`, `os_version`, `os_id`, `kernel_version`, `pkg_manager`

- **Hardware Information**
  - CPU count and model from `/proc/cpuinfo`
  - Total and available memory from `free -h`
  - Swap configuration and usage
  - System architecture (x86_64, aarch64, etc.)
  - Virtualization platform (VMware, KVM, physical, cloud)
  - Store: `cpu_count`, `cpu_model`, `memory_total`, `memory_available`, `swap_size`, `architecture`, `virt_platform`

- **System State**
  - System uptime from `uptime`
  - Load averages (1, 5, 15 minute)
  - Reboot required flag (check `/var/run/reboot-required` or needs-restarting)
  - Store: `uptime_seconds`, `load_average`, `reboot_required`

#### Phase 2: Storage Assessment
- **Disk Space**
  - All mounted filesystems from `df -h`
  - Focus on: `/`, `/boot`, `/var`, `/tmp`, `/home`, `/opt`, `/u00`, `/u01`, `/u02`
  - Flag filesystems over 80% usage
  - Identify largest directories in filled filesystems (using `du`)
  - Store array: `filesystems[]` with `mount_point`, `size`, `used`, `available`, `use_percent`

- **Storage Devices**
  - List block devices with `lsblk`
  - LVM configuration (VG, LV, PV status)
  - RAID status if applicable (`/proc/mdstat`, `megacli`, etc.)
  - Store: `block_devices[]`, `lvm_config`, `raid_status`

- **Mount Points**
  - Parse `/etc/fstab` for permanent mounts
  - Check for NFS/CIFS remote mounts
  - Flag any failed or missing mounts
  - Store: `fstab_entries[]`, `nfs_mounts[]`, `failed_mounts[]`

#### Phase 3: Network Assessment
- **Network Connectivity**
  - DNS resolution test (nslookup redhat.com)
  - External connectivity test (curl -s -o /dev/null -w '%{http_code}' https://redhat.com)
  - Default gateway presence
  - Store: `dns_working`, `internet_working`, `gateway_ip`

- **Network Configuration**
  - Active network interfaces from `ip addr` or `ifconfig`
  - IP addresses and network configuration
  - Listening ports and associated services from `ss -tlnp` or `netstat -tlnp`
  - Store: `interfaces[]`, `listening_ports[]` with `port`, `protocol`, `process`

- **Hostname and DNS**
  - System hostname from `hostname -f`
  - `/etc/hosts` configuration
  - DNS servers from `/etc/resolv.conf`
  - Store: `hostname`, `dns_servers[]`

#### Phase 4: Time and Date
- **Time Synchronization**
  - Check if chronyd or ntpd is running
  - Sync status from `chronyc tracking` or `ntpq -p`
  - Timezone from `timedatectl`
  - System time drift if measurable
  - Store: `time_sync_service`, `time_sync_status`, `timezone`, `time_drift`

#### Phase 5: OS Support and Lifecycle
- **EOL Status**
  - Hardcode EOL dates for major RHEL/Rocky versions
  - RHEL 7: June 30, 2024 (Extended: June 30, 2028)
  - RHEL 8: May 31, 2029 (Extended: May 31, 2032)
  - RHEL 9: May 31, 2032 (Extended: May 31, 2035)
  - Rocky Linux follows RHEL lifecycle
  - Calculate days until EOL from current date
  - Flag if OS is EOL or within 365 days of EOL
  - Store: `eol_date`, `days_until_eol`, `is_eol`, `extended_support_available`

- **Kernel Status**
  - Currently running kernel version
  - Latest available kernel version from package manager
  - Flag if kernel update available
  - List all installed kernels
  - Store: `current_kernel`, `latest_kernel`, `kernel_update_available`, `installed_kernels[]`

#### Phase 6: Package Management
- **Subscription Status** (RHEL only)
  - Check `subscription-manager status`
  - Extract subscription expiration, SKU, support level
  - Check if repos are enabled
  - Store: `rhel_subscribed`, `subscription_status`, `subscription_expires`, `enabled_repos[]`

- **Package Inventory**
  - Total package count
  - Available updates count (security vs. other)
  - List of security updates available
  - Package groups installed (check for desktop groups)
  - Store: `total_packages`, `updates_available`, `security_updates_available`, `security_updates[]`, `package_groups[]`

- **Unwanted Packages** (for headless servers)
  - Check for GUI packages: gnome-desktop, gnome-session, firefox, thunderbird, libreoffice
  - Check for development tools if not dev server
  - Store: `unwanted_packages[]` with package name and size

- **Repository Configuration**
  - List enabled repositories
  - Flag third-party or custom repos
  - Check for orphaned packages (no repo available)
  - Store: `enabled_repos[]`, `third_party_repos[]`, `orphaned_packages[]`

- **LEAPP Pre-upgrade**
  - Only applicable for RHEL 7 → 8 or RHEL 8 → 9
  - Run `leapp preupgrade` if available
  - Parse report for inhibitors and recommendations
  - Store: `leapp_available`, `leapp_report_path`, `leapp_inhibitors[]`, `leapp_recommendations[]`

#### Phase 7: Security Assessment
- **SELinux**
  - Current mode from `getenforce` (Enforcing/Permissive/Disabled)
  - Configuration from `/etc/selinux/config`
  - Recent denials from `ausearch -m avc -ts recent`
  - Store: `selinux_mode`, `selinux_config_mode`, `selinux_denials_count`

- **Firewall**
  - Detect firewall type (firewalld, iptables, ufw, none)
  - Service status
  - Active zones (firewalld)
  - Open ports and services
  - Store: `firewall_type`, `firewall_active`, `firewall_zones[]`, `firewall_rules[]`

- **SSH Configuration**
  - Parse `/etc/ssh/sshd_config` for:
    - PermitRootLogin (should be 'no' or 'prohibit-password')
    - PasswordAuthentication (preferably 'no')
    - Port (note if non-standard)
    - Protocol (should be 2)
    - PubkeyAuthentication
  - Store: `ssh_permit_root`, `ssh_password_auth`, `ssh_port`, `ssh_protocol`, `ssh_pubkey_auth`

- **Security Updates**
  - Count of available security updates
  - Critical CVEs addressed by pending updates
  - Store: `security_updates[]` with package, current version, new version, CVE (if parseable)

- **SSL/TLS Certificates**
  - Search common locations: `/etc/ssl`, `/etc/pki/tls`, `/etc/httpd/conf`, `/etc/nginx`
  - Parse certificate expiration dates
  - Flag certificates expiring within 90 days
  - Store: `certificates[]` with `path`, `expires`, `days_until_expiry`, `subject`

- **Audit Configuration**
  - Check if `auditd` is running
  - Audit rules loaded
  - Recent audit log size and rotation
  - Store: `auditd_running`, `audit_rules_count`, `audit_log_size`

- **Failed Login Attempts**
  - Check for failed SSH login attempts in logs
  - Parse `/var/log/secure` or `/var/log/auth.log`
  - Store: `failed_login_count`, `failed_login_ips[]`

#### Phase 8: System Configuration
- **Systemd Configuration**
  - Default target from `systemctl get-default`
  - Should be `multi-user.target` for headless servers
  - Failed units from `systemctl --failed`
  - Enabled services list
  - Store: `systemd_default_target`, `failed_services[]`, `enabled_services[]`

- **Boot Configuration**
  - Parse `/etc/default/grub` for boot parameters
  - Check for rescue kernels
  - Note security parameters (e.g., audit=1, selinux=1)
  - Store: `grub_cmdline`, `rescue_kernels[]`

- **System Limits**
  - Check `/etc/security/limits.conf` and `/etc/security/limits.d/`
  - Important ulimits for common users (oracle, tomcat, etc.)
  - File descriptor limits
  - Store: `system_limits[]`, `user_limits[]`

- **Sysctl Parameters**
  - Important kernel parameters from `sysctl -a`
  - Focus on: vm.swappiness, fs.file-max, net.ipv4.ip_forward, kernel.shmmax
  - Store: `sysctl_params{}` as key-value pairs

- **Scheduled Tasks**
  - System cron jobs from `/etc/cron.*`
  - User crontabs from `/var/spool/cron`
  - Systemd timers from `systemctl list-timers`
  - Store: `cron_jobs[]`, `systemd_timers[]`

- **Core Dumps**
  - Check for core dumps in `/var/crash`, `/var/lib/systemd/coredump`, `/var/tmp`
  - Count and size of core dumps
  - Store: `core_dumps[]` with `path`, `size`, `date`

#### Phase 9: Application Detection

- **Java JDK Detection**
  - Check standard locations: `/usr/lib/jvm`, `/usr/java`, `/opt/java`
  - Search /u0* directories for JDK installations
  - For each JDK found, capture version from `java -version`
  - Check which services are using which JDK (via /proc/PID/cmdline)
  - Determine if JDK is in use by running processes
  - Store: `jdk_installations[]` with `path`, `version`, `in_use`, `used_by[]`

- **Tomcat Detection**
  - Search for Tomcat in: `/opt/tomcat*`, `/usr/share/tomcat*`, `/u0*/tomcat*`
  - Detect version from catalina.sh or version.sh
  - Check if running (systemd service or standalone process)
  - Determine Tomcat version EOL status
  - Capture connector ports from server.xml
  - Store: `tomcat_installations[]` with `path`, `version`, `eol_date`, `running`, `ports[]`, `service_name`

- **Oracle Database Detection**
  - Search for Oracle homes in `/u0*/app/oracle/product/*`, `/opt/oracle/*`
  - Check for oratab file at `/etc/oratab`
  - For each Oracle home found:
    - Determine Oracle version from `sqlplus -version` or `$ORACLE_HOME/inventory`
    - List installed patches from `opatch lspatches` or `opatch lsinventory`
    - Check for running instances via `ps -ef | grep pmon`
    - Determine if managed by systemd (look for oracle*.service)
    - Check listener status with `lsnrctl status`
  - Store: `oracle_homes[]` with:
    - `oracle_home_path`
    - `oracle_version`
    - `patches_applied[]`
    - `instances[]` with `sid`, `status`, `process_manager`
    - `listeners[]` with `name`, `status`, `port`

- **Apache/Nginx Web Servers**
  - Check if httpd (Apache) or nginx is installed
  - Version from `httpd -v` or `nginx -v`
  - Configuration paths
  - Running status and ports
  - Virtual hosts configuration
  - Store: `web_servers[]` with `type`, `version`, `running`, `config_path`, `vhosts[]`

- **Oracle HTTP Server / Oracle ORDS**
  - Scan for OHS installations (typically in Oracle home)
  - Check for ORDS installations (standalone or in Tomcat/WebLogic)
  - ORDS version and configuration
  - Store: `ohs_installations[]`, `ords_installations[]`

- **Ellucian Banner Component Detection**
  - Look for Banner-specific directories and files:
    - Banner application server paths (often in /u0*)
    - Banner self-service (SSB) deployments
    - Banner forms installations
    - Banner configuration files (banner_configuration.groovy, etc.)
  - Check for Banner-specific processes
  - Store: `banner_components[]` with `component_type`, `path`, `version`, `status`

- **Database Clients**
  - Check for MySQL/MariaDB client: `mysql --version`
  - Check for PostgreSQL client: `psql --version`
  - Check for MongoDB: `mongod --version`
  - Store: `database_clients[]` with `type`, `version`

- **Container Runtimes**
  - Check for Docker: `docker --version`, `docker ps`
  - Check for Podman: `podman --version`, `podman ps`
  - List running containers
  - Store: `container_runtime`, `containers[]` with `id`, `image`, `name`, `status`

- **Monitoring Agents**
  - Check for Nagios agents (NRPE)
  - Check for Zabbix agent
  - Check for SNMP daemon
  - Check for Prometheus node_exporter
  - Store: `monitoring_agents[]` with `type`, `version`, `running`, `config_path`

- **Backup Software**
  - Look for common backup solutions:
    - Bacula, Amanda, rsnapshot, Borgbackup
    - Custom backup scripts in /usr/local/bin, /opt
    - Oracle Recovery Manager (RMAN) scripts
  - Store: `backup_solutions[]` with `type`, `config_path`, `last_backup`

#### Phase 10: Process Analysis
- **Running Processes**
  - Full process list from `ps aux`
  - Identify non-OS baseline processes
  - Categorize processes by application
  - Flag high CPU/memory consumers
  - Store: `processes[]` with `pid`, `user`, `command`, `cpu_percent`, `mem_percent`, `category`

- **Systemd vs Non-Systemd Processes**
  - Cross-reference running processes with systemd units
  - Identify processes NOT managed by systemd
  - Flag applications requiring manual startup
  - Store: `non_systemd_processes[]` with `pid`, `command`, `parent_pid`

- **Process Resource Usage**
  - Top 10 processes by CPU usage
  - Top 10 processes by memory usage
  - Store: `top_cpu_processes[]`, `top_mem_processes[]`

### Remediation Planning

The Assessment script should use the gathered information to create a remediation
plan. The remediation plan objective is to transition the server from its current
state to whatever is most ideal from a maintenance and security standpoint.

#### Priority Levels
Each remediation recommendation must include a priority level:

- **CRITICAL**: Immediate security risk or system failure imminent
  - Examples: EOL OS, root SSH enabled with password auth, critical security updates
  - Recommended action timeline: Immediate (within 24-48 hours)

- **HIGH**: Significant security risk or stability concern
  - Examples: SELinux disabled, firewall inactive, certificates expiring soon
  - Recommended action timeline: Within 1 week

- **MEDIUM**: Maintenance improvements, non-critical security hardening
  - Examples: Outdated applications, unused packages, missing patches
  - Recommended action timeline: Within 1 month

- **LOW**: Optimization and cleanup tasks
  - Examples: Unused JDK installations, orphaned packages, minor configuration tweaks
  - Recommended action timeline: Next maintenance window

#### Risk Assessment
Each recommendation should include:
- **Impact**: What happens if not addressed (security breach, downtime, degraded performance)
- **Effort**: Estimated time to remediate (minutes, hours, days)
- **Risk**: Potential issues during remediation (requires reboot, service downtime, etc.)
- **Dependencies**: Prerequisites or related tasks that must be completed first

#### Remediation Rules

The script should evaluate collected data and generate recommendations based on these rules:

**Storage:**
- If filesystem > 90% full → CRITICAL: Expand storage or clean up
- If filesystem > 80% full → HIGH: Review and clean up
- If /boot > 70% full → HIGH: Remove old kernels

**Operating System:**
- If OS is EOL → CRITICAL: Plan OS upgrade
- If OS EOL within 180 days → HIGH: Plan OS upgrade
- If kernel update available → MEDIUM: Schedule kernel update and reboot
- If reboot required → MEDIUM: Schedule reboot during maintenance window

**Security:**
- If root SSH with password enabled → CRITICAL: Disable or restrict
- If SELinux disabled → CRITICAL: Enable SELinux (requires planning)
- If firewall inactive → HIGH: Configure and enable firewall
- If security updates available → HIGH: Apply security updates
- If certificates expire < 30 days → CRITICAL: Renew certificates
- If certificates expire < 90 days → HIGH: Plan certificate renewal
- If failed login attempts > 100 → MEDIUM: Review security logs

**Packages:**
- If desktop packages on headless server → MEDIUM: Remove GUI packages
- If orphaned packages exist → LOW: Review and remove
- If RHEL not subscribed → HIGH: Register or plan migration to Rocky

**Applications:**
- If Tomcat EOL → HIGH: Plan Tomcat upgrade
- If Oracle patches missing → MEDIUM: Review and apply patches
- If multiple unused JDK versions → LOW: Clean up unused JDKs
- If non-systemd critical processes → MEDIUM: Create systemd units

**System Configuration:**
- If default target is graphical.target on headless → MEDIUM: Set to multi-user.target
- If failed systemd services → MEDIUM: Investigate and fix
- If swap not configured → LOW: Consider adding swap
- If core dumps present → LOW: Review and clean up

**Time and Networking:**
- If time not synchronized → HIGH: Configure chrony/NTP
- If DNS not working → CRITICAL: Fix DNS configuration
- If internet connectivity issues → MEDIUM: Review firewall/proxy settings

**Monitoring and Backup:**
- If no monitoring agent → MEDIUM: Install monitoring
- If no backup solution detected → HIGH: Implement backup strategy

#### Change Tracking
If a previous assessment exists, compare and report:
- New issues introduced since last assessment
- Issues resolved since last assessment
- Changes in system configuration (new packages, services, etc.)
- Progression of time-sensitive issues (days until EOL, certificate expiry)

The remediation plan output should be in two forms (see output section):
- JSON format for script consumption
- Markdown format for human consumption

### Assessment Console Output

The assessment script should log output to stdout while running. The log output
should include detailed information about which step the script is currently
executing and the finding. Sample output may look like the following:

```bash
[root@PVE01RHEL01 remediation]# cat logs/01-assessment-20260203-180249.log
==================================================
Server Remediation Assessment Script
Version: 1.0.0
==================================================
Execution Time: Tue Feb  3 06:02:49 PM MST 2026
Current User: root
Log File: logs/01-assessment-20260203-180249.log
==================================================
[2026-02-03 18:02:49] INFO: === Phase 1: Environment Assessment ===
[2026-02-03 18:02:49] INFO: Checking if running as root...
[2026-02-03 18:02:49] INFO: Root check: PASSED
[2026-02-03 18:02:49] INFO: Detecting operating system...
[2026-02-03 18:02:49] INFO: Detected OS from /etc/os-release: Red Hat Enterprise Linux 9.7
[2026-02-03 18:02:49] INFO: OS: Red Hat Enterprise Linux 9.7 (Kernel: 5.14.0-611.20.1.el9_7.x86_64)
[2026-02-03 18:02:49] INFO: Package manager: dnf
[2026-02-03 18:02:49] INFO: Determining EOL status...
[2026-02-03 18:02:49] INFO: OS version is supported (2308 days until EOL)
[2026-02-03 18:02:49] INFO: Checking disk space...
[2026-02-03 18:02:49] INFO: Free space in /: 84GB
[2026-02-03 18:02:49] INFO: Free space in /var: 84GB
[2026-02-03 18:02:49] INFO: Disk space check: PASSED
[2026-02-03 18:02:49] INFO: Checking network connectivity...
[2026-02-03 18:02:49] INFO: DNS resolution: OK
[2026-02-03 18:02:49] WARN: External connectivity issues detected
[2026-02-03 18:02:49] INFO: Checking time synchronization...
[2026-02-03 18:02:49] INFO: Time sync (chrony): OK
[2026-02-03 18:02:49] INFO: Collecting system information...
[2026-02-03 18:02:49] INFO: Uptime: 1757 seconds
[2026-02-03 18:02:49] INFO: Memory: 1GB used of 23GB
[2026-02-03 18:02:49] INFO: Swap: /dev/dm-1 partition   4G   0B   -2
[2026-02-03 18:02:49] INFO: CPU: 8 x Intel(R) Xeon(R) Gold 6338N CPU @ 2.20GHz pc-q35-10.1
[2026-02-03 18:02:49] INFO: Load average: 0.00, 0.00, 0.00
[2026-02-03 18:02:49] INFO: System information collected
[2026-02-03 18:02:49] INFO: Checking RHEL subscription status...
[2026-02-03 18:02:49] INFO: Subscription status: Registered
[2026-02-03 18:02:51] INFO: RHEL subscription check complete
[2026-02-03 18:02:51] INFO: Running LEAPP pre-upgrade assessment...
[2026-02-03 18:02:51] INFO: LEAPP assessment not applicable for RHEL 9
[2026-02-03 18:02:51] INFO: Assessing security configuration...
[2026-02-03 18:02:51] INFO: SELinux: Enforcing
[2026-02-03 18:02:51] INFO: Firewall: firewalld active
[2026-02-03 18:02:51] INFO: SSH PermitRootLogin: not set
[2026-02-03 18:02:51] INFO: SSH PasswordAuthentication: not set
[2026-02-03 18:02:53] INFO: Security updates available: 35
[2026-02-03 18:02:53] INFO: SSL certificates found: 2
[2026-02-03 18:02:53] INFO: Security assessment complete
[2026-02-03 18:02:53] INFO: Assessing package management...
[2026-02-03 18:02:53] INFO: Total packages installed: 1222
...
```

### Assessment File Output

Upon completion, the assessment script MUST create three files:

1. **Script-readable remediation plan** (JSON)
2. **Human-readable remediation report** (Markdown)
3. **Assessment execution log** (text)

#### Output File Paths
```
logs/01-assessment-YYYYMMDD-HHMMSS.log
logs/01-assessment-YYYYMMDD-HHMMSS.json
logs/01-assessment-YYYYMMDD-HHMMSS.md
```

Create a symlink for easy access to latest assessment:
```
logs/latest-assessment.log -> 01-assessment-YYYYMMDD-HHMMSS.log
logs/latest-assessment.json -> 01-assessment-YYYYMMDD-HHMMSS.json
logs/latest-assessment.md -> 01-assessment-YYYYMMDD-HHMMSS.md
```

#### JSON Structure (Script-Readable Plan)

The JSON file should have this structure:

```json
{
  "assessment_metadata": {
    "version": "1.0.0",
    "timestamp": "2026-02-10T18:23:45-07:00",
    "execution_time_seconds": 45,
    "hostname": "server.example.com",
    "assessment_user": "root"
  },
  "system_info": {
    "os": {
      "name": "Red Hat Enterprise Linux",
      "version": "9.7",
      "id": "rhel",
      "kernel": "5.14.0-611.20.1.el9_7.x86_64",
      "architecture": "x86_64",
      "eol_date": "2032-05-31",
      "days_until_eol": 2308,
      "is_eol": false
    },
    "hardware": {
      "cpu_count": 8,
      "cpu_model": "Intel(R) Xeon(R) Gold 6338N CPU @ 2.20GHz",
      "memory_total_gb": 24,
      "memory_available_gb": 22,
      "swap_size_gb": 4,
      "virtualization": "kvm"
    },
    "uptime": {
      "seconds": 1757,
      "human_readable": "29 minutes"
    },
    "load_average": [0.00, 0.00, 0.00],
    "reboot_required": false
  },
  "storage": {
    "filesystems": [
      {
        "mount_point": "/",
        "size_gb": 100,
        "used_gb": 16,
        "available_gb": 84,
        "use_percent": 16,
        "warning": false
      }
    ],
    "lvm_present": true,
    "raid_present": false,
    "nfs_mounts": [],
    "failed_mounts": []
  },
  "network": {
    "dns_working": true,
    "internet_working": false,
    "interfaces": [
      {"name": "eth0", "ip": "192.168.1.100", "state": "UP"}
    ],
    "listening_ports": [
      {"port": 22, "protocol": "tcp", "process": "sshd"}
    ]
  },
  "time_sync": {
    "service": "chronyd",
    "status": "active",
    "synchronized": true,
    "timezone": "America/Denver"
  },
  "packages": {
    "total_installed": 1222,
    "updates_available": 45,
    "security_updates_available": 12,
    "security_updates": [
      {"name": "kernel", "current": "5.14.0-611", "available": "5.14.0-613", "cve": ["CVE-2024-1234"]}
    ],
    "unwanted_packages": [
      {"name": "gnome-desktop", "size_mb": 150}
    ],
    "orphaned_packages": [],
    "third_party_repos": []
  },
  "security": {
    "selinux": {
      "current_mode": "Enforcing",
      "config_mode": "Enforcing",
      "denials_recent": 0
    },
    "firewall": {
      "type": "firewalld",
      "active": true,
      "default_zone": "public",
      "open_ports": ["22/tcp"]
    },
    "ssh": {
      "permit_root_login": "prohibit-password",
      "password_authentication": "yes",
      "port": 22,
      "pubkey_authentication": "yes"
    },
    "certificates": [
      {"path": "/etc/pki/tls/certs/localhost.crt", "expires": "2027-01-01", "days_until_expiry": 325}
    ],
    "auditd_running": true,
    "failed_logins": {"count": 5, "unique_ips": 2}
  },
  "subscription": {
    "is_rhel": true,
    "registered": true,
    "status": "Current",
    "expires": "2027-12-31",
    "support_level": "Premium"
  },
  "systemd": {
    "default_target": "multi-user.target",
    "failed_services": [],
    "non_systemd_processes": []
  },
  "applications": {
    "java": [
      {
        "path": "/usr/lib/jvm/java-11-openjdk",
        "version": "11.0.18",
        "in_use": true,
        "used_by": ["tomcat"]
      },
      {
        "path": "/u01/app/java/jdk1.8.0_333",
        "version": "1.8.0_333",
        "in_use": false,
        "used_by": []
      }
    ],
    "tomcat": [
      {
        "path": "/opt/tomcat",
        "version": "9.0.65",
        "eol_date": "2024-03-31",
        "is_eol": true,
        "running": true,
        "ports": [8080, 8443],
        "service_name": "tomcat.service"
      }
    ],
    "oracle_database": [
      {
        "oracle_home": "/u01/app/oracle/product/19.3.0/dbhome_1",
        "version": "19.3.0.0.0",
        "patches": ["32545013", "33515361"],
        "instances": [
          {"sid": "PROD", "status": "RUNNING", "process_manager": "systemd"}
        ],
        "listeners": [
          {"name": "LISTENER", "status": "ONLINE", "port": 1521}
        ]
      }
    ],
    "web_servers": [
      {"type": "nginx", "version": "1.20.1", "running": true}
    ],
    "banner_components": [
      {"type": "banner_appserver", "path": "/u01/banner", "version": "9.17", "status": "running"}
    ],
    "containers": [],
    "monitoring_agents": [
      {"type": "zabbix-agent", "version": "6.0", "running": true}
    ],
    "backup_solutions": []
  },
  "change_tracking": {
    "previous_assessment_date": "2026-02-03T18:02:49-07:00",
    "new_issues": [
      "Tomcat now EOL"
    ],
    "resolved_issues": [
      "Security updates applied"
    ],
    "configuration_changes": [
      "New monitoring agent installed"
    ]
  },
  "remediation": {
    "summary": {
      "total_recommendations": 8,
      "critical": 1,
      "high": 3,
      "medium": 3,
      "low": 1
    },
    "recommendations": [
      {
        "id": "REM-001",
        "priority": "CRITICAL",
        "category": "applications",
        "title": "Upgrade EOL Tomcat Installation",
        "description": "Tomcat 9.0.65 is past EOL (2024-03-31). Current date is 2026-02-10.",
        "impact": "Running EOL software exposes system to unpatched security vulnerabilities",
        "effort": "2-4 hours",
        "risk": "Requires application downtime, testing required",
        "action": "upgrade_tomcat",
        "parameters": {
          "current_path": "/opt/tomcat",
          "current_version": "9.0.65",
          "recommended_version": "10.1.x",
          "requires_reboot": false,
          "requires_service_restart": true
        },
        "dependencies": ["REM-005"]
      },
      {
        "id": "REM-002",
        "priority": "HIGH",
        "category": "security",
        "title": "Apply Security Updates",
        "description": "12 security updates available including kernel patches",
        "impact": "System vulnerable to known CVEs",
        "effort": "30 minutes",
        "risk": "Kernel update requires reboot",
        "action": "apply_security_updates",
        "parameters": {
          "package_count": 12,
          "requires_reboot": true,
          "packages": ["kernel", "openssl", "..."]
        },
        "dependencies": []
      },
      {
        "id": "REM-005",
        "priority": "LOW",
        "category": "cleanup",
        "title": "Remove Unused JDK Installation",
        "description": "JDK 1.8.0_333 at /u01/app/java/jdk1.8.0_333 is not in use",
        "impact": "Wastes disk space, potential confusion",
        "effort": "5 minutes",
        "risk": "Low - verify not used before removal",
        "action": "remove_unused_jdk",
        "parameters": {
          "path": "/u01/app/java/jdk1.8.0_333",
          "size_mb": 350
        },
        "dependencies": []
      }
    ]
  }
}
```

#### Markdown Structure (Human-Readable Report)

The Markdown report should be well-formatted and organized:

```markdown
# Server Assessment Report

**Server:** server.example.com
**Assessment Date:** February 10, 2026 18:23:45 MST
**Assessment Version:** 1.0.0
**Execution Time:** 45 seconds

---

## Executive Summary

- **Total Recommendations:** 8 (1 Critical, 3 High, 3 Medium, 1 Low)
- **OS Status:** RHEL 9.7 - Supported (2308 days until EOL)
- **Security Posture:** Good (SELinux enforcing, firewall active)
- **Primary Concerns:**
  - Tomcat installation is EOL
  - 12 security updates available
  - Password authentication enabled for SSH

---

## System Information

### Operating System
- **Distribution:** Red Hat Enterprise Linux 9.7
- **Kernel:** 5.14.0-611.20.1.el9_7.x86_64
- **Architecture:** x86_64
- **EOL Date:** May 31, 2032 (2308 days remaining)
- **Subscription Status:** ✅ Registered (expires 2027-12-31)

### Hardware
- **CPU:** 8 x Intel(R) Xeon(R) Gold 6338N CPU @ 2.20GHz
- **Memory:** 24 GB total, 22 GB available
- **Swap:** 4 GB
- **Platform:** KVM Virtual Machine

### System State
- **Uptime:** 29 minutes
- **Load Average:** 0.00, 0.00, 0.00
- **Reboot Required:** No

---

## Storage Assessment

| Mount Point | Size | Used | Available | Usage % | Status |
|-------------|------|------|-----------|---------|--------|
| / | 100 GB | 16 GB | 84 GB | 16% | ✅ OK |
| /boot | 1 GB | 200 MB | 800 MB | 20% | ✅ OK |

---

## Network Assessment

- **DNS Resolution:** ✅ Working
- **External Connectivity:** ⚠️ Issues detected
- **Active Interfaces:** eth0 (192.168.1.100)

### Listening Ports
- TCP 22: sshd
- TCP 8080: tomcat
- TCP 1521: oracle listener

---

## Security Assessment

### SELinux
- **Status:** ✅ Enforcing
- **Configuration:** Enforcing
- **Recent Denials:** 0

### Firewall
- **Type:** firewalld
- **Status:** ✅ Active
- **Default Zone:** public
- **Open Ports:** 22/tcp

### SSH Configuration
- **PermitRootLogin:** prohibit-password ✅
- **PasswordAuthentication:** yes ⚠️
- **Port:** 22 (default)
- **PubkeyAuthentication:** yes ✅

### Updates & Patches
- **Security Updates Available:** 12
- **Total Updates Available:** 45
- **Critical Packages:** kernel, openssl

### SSL Certificates
- `/etc/pki/tls/certs/localhost.crt` - Expires in 325 days ✅

---

## Application Inventory

### Java Installations
1. **Java 11** - `/usr/lib/jvm/java-11-openjdk`
   - Version: 11.0.18
   - Status: ✅ In use by Tomcat

2. **Java 8** - `/u01/app/java/jdk1.8.0_333`
   - Version: 1.8.0_333
   - Status: ⚠️ NOT in use (candidate for removal)

### Apache Tomcat
- **Location:** /opt/tomcat
- **Version:** 9.0.65
- **EOL Date:** March 31, 2024 ⚠️ **PAST EOL**
- **Status:** Running (systemd managed)
- **Ports:** 8080, 8443

### Oracle Database
- **Oracle Home:** /u01/app/oracle/product/19.3.0/dbhome_1
- **Version:** 19.3.0.0.0
- **Patches Applied:** 32545013, 33515361
- **Instance:** PROD (RUNNING, systemd managed)
- **Listener:** ONLINE on port 1521

### Ellucian Banner
- **Banner Application Server** - /u01/banner
  - Version: 9.17
  - Status: Running

---

## Change Tracking

### Since Last Assessment (2026-02-03)

**New Issues:**
- Tomcat now past EOL date

**Resolved Issues:**
- Security updates applied since last check

**Configuration Changes:**
- Zabbix monitoring agent installed

---

## Remediation Plan

### 🔴 CRITICAL Priority (Immediate Action Required)

#### REM-001: Upgrade EOL Tomcat Installation

**Description:** Tomcat 9.0.65 is past EOL (March 31, 2024). Current date is February 10, 2026.

**Impact:** Running EOL software exposes system to unpatched security vulnerabilities.

**Recommendation:** Upgrade to Tomcat 10.1.x

**Effort:** 2-4 hours
**Risk:** Requires application downtime and testing
**Dependencies:** Remove unused JDK first (REM-005)

**Action Steps:**
1. Review Tomcat 10.x compatibility with current applications
2. Test upgrade in non-production environment
3. Schedule maintenance window
4. Backup current Tomcat installation
5. Deploy Tomcat 10.1.x
6. Update systemd service configuration
7. Test all applications

---

### 🟠 HIGH Priority (Within 1 Week)

#### REM-002: Apply Security Updates

**Description:** 12 security updates available including kernel patches addressing known CVEs.

**Impact:** System vulnerable to known security issues.

**Recommendation:** Apply all security updates during next maintenance window.

**Effort:** 30 minutes
**Risk:** Kernel update requires system reboot

**Action Steps:**
1. Review update list: kernel, openssl, ...
2. Schedule maintenance window
3. Backup system/snapshots
4. Run: `dnf update --security -y`
5. Reboot system
6. Verify services after reboot

---

### 🟡 MEDIUM Priority (Within 1 Month)

... (additional recommendations)

---

### 🟢 LOW Priority (Next Maintenance Window)

#### REM-005: Remove Unused JDK Installation

**Description:** JDK 1.8.0_333 at /u01/app/java/jdk1.8.0_333 is not in use by any services.

**Impact:** Wastes 350 MB disk space, potential confusion.

**Recommendation:** Remove after verification.

**Effort:** 5 minutes
**Risk:** Low - already verified not in use

**Action Steps:**
1. Final verification: `lsof | grep /u01/app/java/jdk1.8.0_333`
2. Backup or archive if required
3. Remove: `rm -rf /u01/app/java/jdk1.8.0_333`

---

## Next Steps

1. Review this report with system stakeholders
2. Prioritize remediation tasks
3. Schedule maintenance windows for critical/high priority items
4. Execute remediation plan
5. Run assessment again after remediation to verify improvements

---

**Report Generated by:** RHEL Assessment Script v1.0.0
**End of Report**
```

#### Log File Format

The assessment log is console output captured to file during script execution. Format:

```
==================================================
Server Remediation Assessment Script
Version: 1.0.0
==================================================
Execution Time: [timestamp]
Current User: root
Log File: logs/01-assessment-20260210-182345.log
==================================================
[YYYY-MM-DD HH:MM:SS] LEVEL: message
...
==================================================
Assessment Complete
JSON Report: logs/01-assessment-20260210-182345.json
Markdown Report: logs/01-assessment-20260210-182345.md
==================================================
```

## Implementation Guidelines

### Global Variable Declaration

Declare all data structures at the top of the script (after the header, before functions):

```bash
# Associative arrays for key-value data
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

# Regular arrays for lists
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
```

### Data Collection Patterns

#### Populating Associative Arrays

```bash
# Simple key-value pairs
OS_INFO[name]="Red Hat Enterprise Linux"
OS_INFO[version]="9.7"
HARDWARE_INFO[cpu_count]=8
SYSTEM_INFO[reboot_required]="false"
```

#### Populating Regular Arrays with JSON Objects

For complex data, store as JSON strings in arrays:

```bash
# Filesystems
FILESYSTEMS+=("{\"mount_point\":\"/\",\"size_gb\":100,\"used_gb\":16,\"available_gb\":84,\"use_percent\":16}")

# Listening ports
LISTENING_PORTS+=("{\"port\":22,\"protocol\":\"tcp\",\"process\":\"sshd\"}")

# Java installations
JDK_INSTALLATIONS+=("{\"path\":\"/usr/lib/jvm/java-11\",\"version\":\"11.0.18\",\"in_use\":true}")
```

#### Safe Counting Pattern

When collecting items in a loop, track the count separately:

```bash
local item_count=0
while IFS= read -r item; do
    MY_ARRAY+=("\"$item\"")
    ((item_count++))
done < <(command)

# Store count for later use
SYSTEM_INFO[items_count]=$item_count

# Check count safely
if [[ $item_count -eq 0 ]]; then
    log_info "No items found"
fi
```

### JSON Output Generation

Use heredoc with variable expansion for JSON output:

```bash
generate_json_output() {
    local timestamp_iso=$(date -Iseconds)
    
    cat > "$JSON_FILE" << EOF
{
  "assessment_metadata": {
    "version": "$SCRIPT_VERSION",
    "timestamp": "$timestamp_iso",
    "hostname": "${SYSTEM_INFO[hostname]}"
  },
  "system_info": {
    "os": {
      "name": "${OS_INFO[name]}",
      "version": "${OS_INFO[version]}",
      "kernel": "${OS_INFO[kernel]}"
    }
  },
  "filesystems": [
    $(IFS=,; echo "${FILESYSTEMS[*]}")
  ],
  "listening_ports": [
    $(IFS=,; echo "${LISTENING_PORTS[*]}")
  ]
}
EOF
}
```

**Key Points:**
- Arrays of JSON objects: Use `$(IFS=,; echo "${ARRAY[*]}")` to join with commas
- Scalar values: Direct variable substitution `"${VAR}"`
- Boolean/numeric values: No quotes `${SYSTEM_INFO[count]}`
- Handle empty arrays gracefully (they'll produce `[ ]`)

### Markdown Output Generation

Use heredoc for markdown with safe array checks:

```bash
generate_markdown_output() {
    cat > "$MD_FILE" << EOF
# Server Assessment Report

**Server:** ${SYSTEM_INFO[hostname]}
**Assessment Date:** $(date '+%B %d, %Y %H:%M:%S %Z')

---

## System Information

- **OS:** ${OS_INFO[name]} ${OS_INFO[version]}
- **Kernel:** ${OS_INFO[kernel]}
EOF

    # Conditionally add sections based on data presence
    local jdk_count=0
    if [[ ${#JDK_INSTALLATIONS[@]} -gt 0 ]] 2>/dev/null; then
        jdk_count=${#JDK_INSTALLATIONS[@]}
    fi
    
    if [[ $jdk_count -gt 0 ]]; then
        echo "" >> "$MD_FILE"
        echo "### Java Installations" >> "$MD_FILE"
        echo "" >> "$MD_FILE"
        
        local num=1
        for jdk in "${JDK_INSTALLATIONS[@]}"; do
            local path=$(echo "$jdk" | grep -o '"path":"[^"]*"' | cut -d'"' -f4)
            local version=$(echo "$jdk" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            echo "$num. **Java** - $path" >> "$MD_FILE"
            echo "   - Version: $version" >> "$MD_FILE"
            ((num++))
        done
    else
        echo "No Java installations detected" >> "$MD_FILE"
    fi
}
```

### Remediation Generation Pattern

```bash
generate_remediation_recommendations() {
    local rem_id=1
    
    # Check condition and add recommendation
    if [[ ${OS_INFO[is_eol]} == "true" ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"CRITICAL","category":"os","title":"OS is EOL","description":"OS %s is past end of life","impact":"No security updates","effort":"4-8 hours","risk":"Major upgrade required"}' $rem_id "${OS_INFO[name]}")")
        ((rem_id++))
    fi
    
    # Check numeric thresholds
    if [[ ${SYSTEM_INFO[security_updates_available]:-0} -gt 0 ]]; then
        REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"HIGH","category":"security","title":"Security updates available","description":"%d updates pending","impact":"System vulnerable","effort":"30 minutes","risk":"May require reboot"}' $rem_id "${SYSTEM_INFO[security_updates_available]}")")
        ((rem_id++))
    fi
    
    # Iterate over collected items
    for tomcat in "${TOMCAT_INSTALLATIONS[@]}"; do
        local version=$(echo "$tomcat" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
        if [[ "$version" =~ ^9\.0 ]]; then
            REMEDIATION_ITEMS+=("$(printf '{"id":"REM-%03d","priority":"HIGH","category":"applications","title":"Tomcat EOL","description":"Tomcat %s is end of life"}' $rem_id "$version")")
            ((rem_id++))
        fi
    done
}
```

### Privilege Handling

Implement a reusable function for privilege escalation:

```bash
# Global variable
USE_SUDO=""

check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        USE_SUDO=""
        return 0
    fi
    
    if sudo -n true 2>/dev/null; then
        USE_SUDO="sudo"
        return 0
    fi
    
    log_error "Requires root or sudo privileges"
    exit 1
}

run_privileged() {
    if [[ -n "$USE_SUDO" ]]; then
        sudo "$@"
    else
        "$@"
    fi
}

# Usage in script
run_privileged systemctl status service
run_privileged grep "pattern" /var/log/secure
```

### Error Handling in Checks

Each check should be isolated and handle its own errors:

```bash
phase_example() {
    log_info "=== Phase X: Example Phase ==="
    
    # Check 1 - handle missing command
    if command -v some_command &>/dev/null; then
        local result=$(some_command 2>/dev/null || echo "unknown")
        SYSTEM_INFO[some_value]="$result"
    else
        SYSTEM_INFO[some_value]="not available"
        log_warn "some_command not found"
    fi
    
    # Check 2 - handle missing file
    if [[ -f /some/config/file ]]; then
        local value=$(grep "^Setting=" /some/config/file | cut -d= -f2)
        SYSTEM_INFO[setting]="${value:-not set}"
    else
        SYSTEM_INFO[setting]="config not found"
        log_warn "Configuration file not found"
    fi
    
    # Check 3 - handle command failure
    local output=$(complex_command 2>/dev/null)
    if [[ $? -eq 0 ]] && [[ -n "$output" ]]; then
        SYSTEM_INFO[complex_value]="$output"
        log_info "Complex check: OK"
    else
        SYSTEM_INFO[complex_value]="unknown"
        log_error "Complex check: FAILED"
    fi
}
```

### Symlink Creation

Create symlinks to the latest assessment for easy access:

```bash
create_symlinks() {
    cd "$LOGS_DIR" || return
    
    ln -sf "$(basename "$LOG_FILE")" "latest-assessment.log"
    ln -sf "$(basename "$JSON_FILE")" "latest-assessment.json"
    ln -sf "$(basename "$MD_FILE")" "latest-assessment.md"
}
```

### Testing and Validation

Before deploying, test with:

```bash
# Syntax check
bash -n script.sh

# Test with set -u to catch undefined variables
bash -u script.sh

# Test error handling by temporarily breaking commands
# (add false commands, remove files, etc.)
```
