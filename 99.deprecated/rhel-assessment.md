# Initial Environment Remediation Scan

The overall purpose of this script is to perform remediation tasks on servers
that have been serverely neglected and currently have an unknown system state.

It is expected that the OS version is EOL (or nearly EOL), installed packages
are expected to be severely out of date, unnecessary packages (including the
GNOME desktop environment) are installed, certain necessary processes are in an
unknown state due to not being managed by systemd and may have to be manually
started upon server startup.

The expected remediation tasks to perform are as follows:
- backup the current system state such that the server can be reverted if needed
- update the server OS to a supported version minor version of the major version
- update all installed packages to latest versions in the package repositories
- configure the server for running as a headless application server
  - primarily target the systemd run target and removal of unnecessary packages
- configure environment requirements for the specific application service
  - the servers specific role can be found by examining the directories at `/u*`
  - it is expected that each of the servers host a service running on the JVM
  - applications are expected to be WAR files deployed to Tomcat
  - manually unpacked Java installations may exist in these directories
  - detect and list all Tomcat installations with their versions
- convert yum packages to groups for ease of future package management
- create systemd unit files that will add configuration for the application
- report and log work done, work that could not be completed, anything else

## Requirements

- The script must run on RHEL major versions 7, 8, and 9.
- The script output must be logged to console and to a log file.
- The script must backup current system state before making changes.
- The script must not execute changes to the server state without permission.
- The script must support a `--dry-run` mode to preview changes without executing them.
- The script must persist state across reboots using a state file (simple key=value format).
- The script must perform safety checks (disk space, network connectivity) before proceeding.
- OS updates must only update to the latest minor version within the same major version.
- Package backups should save installed package lists and configuration files (.bak-YYYY-MM-DD).
- A rollback document must be generated listing all changes and backup file locations.

## Environment

The script will be run as the root user from a dedicated directory in the root
home directory. For logs and any state management, the script shoudl write files
as siblings in the directory.

## Script Phases

The script executes in multiple phases as described below.

### 0. Initialization

- create `.log` files for both script output and verbose log output
  - the log files should be siblings to the script file in the file system

### 1. Environment Assessment

- perform safety checks and abort if any fail:
  - check available disk space (minimum 5GB free in / and /var)
  - verify network connectivity to package repositories
  - confirm running as root user
- determine operating system name and version
  - indicate the severity of the operating system version based on EOL status
- show and record current server uptime and other current statistics
- determine running processes that are not system processes
  - try to automatically determine the server's role based on running processes
  - list paths to executables that are not managed by systemd
- detect Tomcat installations and list versions
- detect Java installations in `/u*` directories
- status of packages out of date, packages needing update
- query `systemctl` for current run target
- determine current yum package strategy
  - check if yum is configured to use package groups
  - later on the package strategy will have to be converted to yum package groups if not already configured
- determine if GUI, desktop environment, firefox and other similar packages are installed

### 2. Remmediation Plan

The remediation plan should only account for tasks that need to be done. For example,
if the systemctl run target is already multi-user.target then the script should not
ask for permission to change it and the execution shouldn't attempt to change it
either.

- `systemctl` target should be set to `multi-user.target` if not already set
- convert `yum` packages to package groups if necessary
- reboot the server if either the run target was changed or the package strategy was changed
- remove all GUI and non-server packages (GNOME, Firefox, Pulse Audio, etc)
- `yum` package manager update statistics (install count, uninstall count, etc)
  - if pending installable packages then add to remediation plan
- reboot the server if packages were installed, updated, or removed
- add systemd units for running applications not managed by systemd
  - auto-generate systemd unit files for detected Tomcat instances
  - examine bash_history for process startup commands and application locations
  - create systemd unit files and request approval before moving them into place
  - after approval, ask user if they want to edit the unit files before reboot
  - if user chooses to edit, exit script but configure for auto-run after next boot

### 3. Request Approval

Ask for approval for each action that will change the server state in the form
of Y/N questions about whether the work should be performed.

For example:
```
Set Systemd target run level currently <run-level>, set to multi-user.target?
>> [Y/N]:
```

**NOTE:** This step should be used to gain approval for remediation tasks
          without doing the work. Any additional interactivity requirements
          must be gained here so the tasks can be executed without user
          interaction.

### 4. Execution

- backup current system state before making any changes:
  - save installed package list to backup file
  - backup configuration files with .bak-YYYY-MM-DD suffix
  - create rollback document listing all backups and changes
- execute any approved work in sequence and according to the remediation plan
- update state file after each major task completion
- log all script output to the script log
- log all script and additional (yum, etc) output to a verbose log

**NOTE:** This step should be able to run unattended. Any permissions or
          interactivity required for this step should have been obtained in the
          previous step when requesting approval to execute the remediation plan.

### 5. Restart

- ask for permission to restart the server.
  - if yes:
    - set script to automatically run on user login after restart
    - restart the server with no delay
  - if no:
    - Continue to report step, set flag that server still needs to restart

### 6. Validate

- check Systemd run target
- check for running processes for the new Systemd units
- check for any available yum package updates

### 7. Report

- remove script from startup on user login if set in previous step
- show a complete report of all the work that was done noting changes
- show a summary of any work that could not be done automatically
  - make recommendations for manual steps

## External Resources

The script can use the [End Of Life](https://endoflife.date/docs/api/v1/) API
to determine severity indicators.
