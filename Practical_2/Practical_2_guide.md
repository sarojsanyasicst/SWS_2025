# Comprehensive Linux Endpoint Security & Log Analysis Lab Guide

## Unit III: Linux Endpoint, Exploitation & Patching

**Lab Environment:**

- Host OS: [Your Default Installed OS]
- Attacker Machine: Kali Linux 2025.2 (amd64)
- Victim Machine: Ubuntu Desktop 24.04.3 (amd64)
- Log Analysis: Scripts (Bash & Python)

---

## 1: Lab Setup & Network Configuration

### Learning Objectives

- Configure secure virtualized environment
- Understand network isolation concepts
- Establish baseline monitoring

### Theory: Virtualization Security Fundamentals

**Network Configuration Types:**

- **NAT**: Virtual machines share host IP through translation
- **Bridged**: VMs act as physical machines on host network (HIGH RISK)
- **Host-Only**: VMs communicate with host only, no internet access
- **Internal Network**: VMs communicate only with each other (RECOMMENDED)

**Recommended Setup for Security Labs:**
Use **Internal Network** configuration to prevent:

- Malware escape to host network
- Accidental attacks on production systems
- Data exfiltration during exercises

### Practical Lab 1.1: Environment Setup

#### Step 1: Network Configuration

1. **Configure Kali Linux VM:**

   - Settings → Network → Adapter 1 → NAT/Bridged(when required)

2. **Configure Ubuntu VM:**
   - Settings → Network → Adapter 1 → NAT/Bridged(when required)

#### Step 2: Verify Connectivity

```bash
# From Kali Linux
ping [Ubuntu ip]

# From Ubuntu
ping [kali ip]
```

### Assessment Checkpoint 1

- [ ] VMs can communicate with each other
- [ ] VMs cannot access external internet
- [ ] Host can access both VMs

---

## 2: Linux Services & Daemons Deep Dive

### Learning Objectives

- Understand systemd service management
- Identify critical system services
- Recognize service-based attack vectors

### Theory: Linux Service Architecture

**What are Services/Daemons?**

- Background processes that run without user interaction
- Managed by systemd (modern Linux distributions)
- Critical for system functionality and security

**Key Service Types:**

- **Network Services**: SSH, HTTP, DNS
- **System Services**: Logging, Authentication, Cron
- **Security Services**: Firewall, Intrusion Detection

**systemd Unit Types:**

- `.service` - System services
- `.socket` - Network sockets
- `.timer` - Scheduled tasks
- `.target` - System states

### Practical Lab 2.1: Service Enumeration & Analysis

#### On Ubuntu (Victim Machine):

```bash
# List all active services
systemctl list-units --type=service --state=active

# Check service status
systemctl status ssh

#systemctl status apache2
#systemctl status mysql

# View service dependencies
systemctl list-dependencies ssh.service

# Check listening ports
ss -tlnp | grep LISTEN
netstat -tlnp | grep LISTEN
```

#### Key Services to Monitor:

```bash
# SSH Service Analysis
systemctl show ssh.service

grep ssh /var/log/auth.log
sudo tail -n 20 /var/log/auth.log | grep -i ssh
journalctl -u ssh.service --since "1 hour ago"


# Web Services
#systemctl status apache2
#systemctl status nginx

# Database Services
#systemctl status mysql
#systemctl status postgresql
```

### Practical Lab 2.2: Service Configuration Analysis

#### Service File Locations:

```bash
# System service files
ls /lib/systemd/system/
ls /etc/systemd/system/

# View service configuration
cat /lib/systemd/system/ssh.service
```

#### Creating Custom Monitoring Service:

```bash
# Create monitoring script
sudo nano /usr/local/bin/monitor-auth.sh
```

```bash
#!/bin/bash
# Monitor authentication attempts
tail -f /var/log/auth.log | while read line; do
    if echo "$line" | grep -q "Failed password"; then
        echo "[ALERT] $(date): Failed login detected - $line"
    fi
done
```

```bash
# Create systemd service file
sudo nano /etc/systemd/system/auth-monitor.service
```

```ini
[Unit]
Description=Authentication Monitor Service
After=network.target

[Service]
Type=simple
EExecStart=/bin/bash /usr/local/bin/monitor-auth.sh
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable auth-monitor.service
sudo systemctl start auth-monitor.service
```

### Assessment Checkpoint 2

- [ ] Can enumerate all running services
- [ ] Understands service dependencies
- [ ] Can create custom monitoring service

---

## 3: Syslog Framework & Components

### Learning Objectives

- Master syslog architecture and message formats
- Configure centralized logging
- Understand log rotation and retention

### Theory: Syslog Framework Architecture

**Syslog Components:**

1. **Syslog Daemon**: rsyslog, syslog-ng
2. **Log Files**: Structured storage locations (eg.: /var/log)
3. **Log Rotation**: logrotate utility
4. **Remote Logging**: Centralized log collection

**Syslog Message Format (RFC 5424):**

```
<Priority>Version SP-Timestamp Hostname ApplicationName ProcessID MessageID StructuredData MSG
```

**Priority Calculation:**

```
Priority = Facility × 8 + Severity
```

**Facilities (0-23):**

- 0: Kernel messages
- 1: User-level messages
- 2: Mail system
- 3: System daemons
- 4: Security/Auth messages
- 16: Local use facilities (local0-local7)

**Severity Levels (0-7):**

- 0: Emergency - System unusable
- 1: Alert - Action must be taken immediately
- 2: Critical - Critical conditions
- 3: Error - Error conditions
- 4: Warning - Warning conditions
- 5: Notice - Normal but significant condition
- 6: Informational - Informational messages
- 7: Debug - Debug-level messages

### Practical Lab 3.1: Syslog Configuration & Analysis

#### Configure rsyslog on Ubuntu:

```bash
# Main configuration file
sudo nano /etc/rsyslog.conf

# Add custom rules
echo "auth,authpriv.*    /var/log/auth.log" | sudo tee -a /etc/rsyslog.conf
#echo "daemon.*           /var/log/daemon.log" | sudo tee -a /etc/rsyslog.conf

# Restart rsyslog
sudo systemctl restart rsyslog
```

#### Analyze Log Files:

```bash
# Key log file locations
/var/log/syslog          # General system messages
/var/log/auth.log        # Authentication attempts
/var/log/kern.log        # Kernel messages
/var/log/daemon.log      # System daemon messages
/var/log/mail.log        # Mail server logs
/var/log/apache2/        # Web server logs
```

#### Log Analysis Commands:

```bash
# Real-time monitoring
sudo tail -f /var/log/auth.log

# Search and filter
grep "Failed password" /var/log/auth.log
grep "sudo" /var/log/auth.log | tail -20

# Count events
grep -c "Failed password" /var/log/auth.log
grep "$(date +%b\ %d)" /var/log/auth.log | grep "Failed" | wc -l

# Using journalctl (systemd)
journalctl -f                    # Follow logs
journalctl -u ssh.service       # Specific service
journalctl --since "1 hour ago" # Time-based filtering
journalctl -p err               # Priority filtering
```

### Practical Lab 3.2: Advanced Log Analysis

#### Generate Test Events:

```bash
# Generate authentication events
ssh wronguser@localhost  # Failed login
sudo ls                  # Sudo usage
```

#### Parse Syslog Messages:

```bash
sudo nano /tmp/parse_syslog.py
```

```bash
#!/usr/bin/env python3
"""
Robust syslog parser (improved, includes parse_line).
Usage: python3 /tmp/parse_syslog.py /var/log/auth.log --json
       python3 /tmp/parse_syslog.py -    # read from stdin
"""
from __future__ import annotations
import re
import sys
import argparse
import logging
import json
from datetime import datetime
from typing import Optional, Dict, Iterator, TextIO

LOG = logging.getLogger("parse_syslog")

SYSLOG_RE = re.compile(
    r"""
    ^(?:<\d+>\s*)?                                      # optional PRI like <34>
    \s*
    (?P<time>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})?  # e.g. "Aug 12 12:34:56" (optional)
    \s*
    (?P<host>[^\s:]+)?                                  # hostname (allows - . etc.)
    \s*
    (?P<proc>[^\s\[]+)?                                 # process name (no '[')
    (?:\[(?P<pid>\d+)\])?                               # optional [PID]
    \s*:\s*
    (?P<msg>.*)                                         # rest of message
    $""",
    re.VERBOSE,
)


def parse_timestamp(ts_str: str, year: Optional[int] = None) -> Optional[datetime]:
    if not ts_str:
        return None
    if year is None:
        year = datetime.now().year
    for fmt in ("%b %d %H:%M:%S", "%b %e %H:%M:%S"):
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(year=year)
        except ValueError:
            continue
    try:
        cleaned = " ".join(ts_str.split())
        return datetime.strptime(cleaned, "%b %d %H:%M:%S").replace(year=year)
    except Exception:
        LOG.debug("Failed to parse timestamp %r", ts_str, exc_info=True)
        return None


def parse_line(line: str, parse_time: bool = True, year: Optional[int] = None) -> Optional[Dict]:
    """
    Parse a single syslog-style line into a dict; return None if nothing matches usefully.
    """
    m = SYSLOG_RE.match(line.rstrip("\n"))
    if not m:
        return None
    gd = m.groupdict()
    ts_str = gd.get("time")
    parsed_ts = parse_timestamp(ts_str, year=year) if (parse_time and ts_str) else None
    pid = gd.get("pid")
    return {
        "timestamp": parsed_ts.isoformat() if parsed_ts else None,
        "timestamp_raw": ts_str,
        "host": gd.get("host"),
        "process": gd.get("proc"),
        "pid": int(pid) if pid is not None else None,
        "message": gd.get("msg", ""),
    }


def iter_file_lines(f: TextIO) -> Iterator[str]:
    for line in f:
        yield line


def process_stream(stream: TextIO, args) -> Iterator[Dict]:
    for line in iter_file_lines(stream):
        parsed = parse_line(line, parse_time=not args.no_time, year=args.year)
        if not parsed:
            continue
        if args.process and parsed["process"] != args.process:
            continue
        yield parsed


def open_input(path: str):
    if path == "-" or path is None:
        return sys.stdin
    return open(path, "r", encoding="utf-8", errors="replace")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Parse syslog-style lines and print structured output.")
    parser.add_argument("path", nargs="?", default="-", help="Path to log file, or '-' for stdin (default).")
    parser.add_argument("--json", action="store_true", help="Output one JSON object per matched line.")
    parser.add_argument("--no-time", action="store_true", help="Don't attempt to parse timestamps to datetime.")
    parser.add_argument("--year", type=int, help="Year to use when parsing timestamps (defaults to current year).")
    parser.add_argument("--process", help="Only show lines from this process name (exact match).")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (repeat).")
    args = parser.parse_args(argv)

    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    try:
        with open_input(args.path) as fh:
            for obj in process_stream(fh, args):
                if args.json:
                    print(json.dumps(obj, ensure_ascii=False, default=str))
                else:
                    print(f"Time:    {obj['timestamp'] or obj['timestamp_raw']}")
                    print(f"Host:    {obj['host']}")
                    print(f"Process: {obj['process']}")
                    print(f"PID:     {obj['pid'] or '-'}")
                    print(f"Message: {obj['message']}")
                    print("-" * 40)
    except FileNotFoundError:
        LOG.error("File not found: %s", args.path)
        return 2
    except PermissionError:
        LOG.error("Permission denied reading: %s (try sudo?)", args.path)
        return 3
    except BrokenPipeError:
        return 0
    except Exception:
        LOG.exception("Unexpected error")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

### Assessment Checkpoint 3

- [ ] Can configure rsyslog rules
- [ ] Understands syslog message format
- [ ] Can parse and analyze log files

---

## 4: Defensive Analysis & Suspicious Activity Detection

### Learning Objectives

- Implement automated threat detection
- Create alert mechanisms
- Develop investigation workflows

### Theory: Defensive Log Analysis

**Indicators of Compromise (IoCs):**

- Multiple failed login attempts
- Privilege escalation events
- Unusual process executions
- Network anomalies
- File system changes

**Detection Strategies:**

- **Signature-based**: Known attack patterns
- **Anomaly-based**: Deviation from baseline
- **Behavioral**: User/system behavior analysis

### Practical Lab 4.1: Automated Threat Detection Scripts

#### Create Detection Scripts:

```bash
# Brute force detection
sudo nano /usr/local/bin/detect-bruteforce.sh
```

```bash
#!/bin/bash
LOGFILE="/var/log/auth.log"
THRESHOLD=5
TIMEFRAME=300  # 5 minutes in seconds

# Get failed attempts in last 5 minutes
CURRENT_TIME=$(date +%s)
START_TIME=$((CURRENT_TIME - TIMEFRAME))

# Extract recent failed attempts
grep "Failed password" $LOGFILE | tail -100 | while read line; do
    LOG_TIME=$(date -d "$(echo $line | awk '{print $1,$2,$3}')" +%s 2>/dev/null)
    if [[ $LOG_TIME -gt $START_TIME ]]; then
        IP=$(echo $line | grep -oP 'from \K[0-9.]+')
        echo "$IP"
    fi
done | sort | uniq -c | while read count ip; do
    if [[ $count -ge $THRESHOLD ]]; then
        echo "[ALERT] Brute force detected from $ip: $count attempts"
        # Optional: Block IP with iptables
        # iptables -A INPUT -s $ip -j DROP
    fi
done
```

```bash
chmod +x /usr/local/bin/detect-bruteforce.sh
```

```bash
# Privilege escalation detection
sudo nano /usr/local/bin/detect-privesc.sh
```

```bash
#!/bin/bash
LOGFILE="/var/log/auth.log"

# Monitor for sudo usage anomalies
grep "sudo" $LOGFILE | tail -50 | while read line; do
    if echo "$line" | grep -q "COMMAND="; then
        USER=$(echo $line | grep -oP 'sudo:\s+\K\w+')
        COMMAND=$(echo $line | grep -oP 'COMMAND=\K.*')

        # Flag suspicious commands
        if echo "$COMMAND" | grep -qE "(su|passwd|chmod|chown|/bin/bash|/bin/sh)"; then
            echo "[ALERT] Suspicious privilege escalation by $USER: $COMMAND"
        fi
    fi
done
```

```bash
chmod +x /usr/local/bin/detect-privesc.sh
```

#### Create Monitoring Dashboard Script:

```bash
sudo tee /usr/local/bin/security-monitor.sh << 'EOF'
```

```bash
#!/bin/bash

echo "=== Security Monitoring Dashboard ==="
echo "Generated: $(date)"
echo

# Failed login summary
echo "=== Failed Login Summary (Last 24 hours) ==="
grep "Failed password" /var/log/auth.log | grep "$(date +%b\ %d)" | wc -l | xargs echo "Total failed attempts:"

echo
echo "Top 5 IPs with failed attempts:"
grep "Failed password" /var/log/auth.log | grep "$(date +%b\ %d)" | \
grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -nr | head -5

echo
echo "=== Recent Sudo Activity ==="
grep "sudo" /var/log/auth.log | tail -10 | cut -d' ' -f1-3,9-

echo
echo "=== System Service Changes ==="
journalctl --since "24 hours ago" | grep -E "(Started|Stopped|Failed)" | tail -10

echo
echo "=== Network Connections ==="
ss -tuln | grep LISTEN | head -10
EOF
```

```bash
chmod +x /usr/local/bin/security-monitor.sh
```

### Assessment Checkpoint 4

- [ ] Automated threat detection scripts functional
- [ ] Alert mechanisms configured

---

## 5: Privilege Escalation Detection

### Learning Objectives

- Understand privilege escalation techniques
- Implement detection mechanisms
- Use automated enumeration tools

### Theory: Privilege Escalation Fundamentals

**Types of Privilege Escalation:**

**1. Vertical Privilege Escalation:**

- User to root escalation
- Service account to admin

**2. Horizontal Privilege Escalation:**

- Access to other user accounts
- Lateral movement

**Common Techniques:**

- SUID/SGID binary exploitation
- Misconfigured sudo permissions
- Kernel exploits
- Service misconfigurations
- Environment variable manipulation

### Practical Lab 5.1: LinPEAS Implementation

#### Install LinPEAS on Kali Linux:

```bash
# Download LinPEAS
cd /tmp
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
```

```bash
chmod +x linpeas.sh
```

```bash
# Transfer to Ubuntu victim
scp linpeas.sh user@[victim_ip]:/tmp/
```

#### Run LinPEAS on Ubuntu:

```bash
# Execute enumeration
cd /tmp
./linpeas.sh | tee linpeas_output.txt

# Review output sections:
# - System Information
# - Users & Groups
# - Sudo permissions
# - SUID binaries
# - Writable files
# - Running processes
# - Network information
```

### Practical Lab 5.2: Custom Privilege Escalation Detection

#### Create Detection Script:

```bash
sudo nano /usr/local/bin/privesc-detector.sh
```

```bash
#!/bin/bash

echo "=== Privilege Escalation Detection Report ==="
echo "Generated: $(date)"
echo

# Check for unusual SUID files
echo "=== Unusual SUID Files ==="
find / -perm -4000 -type f 2>/dev/null | while read file; do
    if ! command -v $(basename $file) >/dev/null; then
        echo "[WARNING] Unusual SUID binary: $file"
    fi
done

# Check sudo configuration
echo -e "\n=== Sudo Configuration Analysis ==="
if [ -r /etc/sudoers ]; then
    echo "Sudoers file readable by current user - POTENTIAL RISK"
fi

# Check for writable directories in PATH
echo -e "\n=== Writable PATH Directories ==="
echo $PATH | tr ':' '\n' | while read dir; do
    if [ -w "$dir" ]; then
        echo "[WARNING] Writable directory in PATH: $dir"
    fi
done

# Check for world-writable files
echo -e "\n=== World-Writable Files (Sample) ==="
find /etc -perm -002 -type f 2>/dev/null | head -10

# Check running processes as other users
echo -e "\n=== Processes Running as Other Users ==="
ps aux | awk '$1 != "root" && $1 != "daemon" && $1 != "'$(whoami)'" {print $1,$11}' | sort -u | head -10

# Check for interesting capabilities
echo -e "\n=== Files with Capabilities ==="
getcap -r / 2>/dev/null | head -10

echo -e "\n=== Detection Complete ==="
EOF
```

```bash
chmod +x /usr/local/bin/privesc-detector.sh
```

### Practical Lab 5.3: Log-Based Privilege Escalation Detection

#### Monitor Privilege Escalation Events:

```bash
# Create monitoring script for privilege changes
sudo nano /usr/local/bin/monitor-privesc.sh
```

```bash
#!/bin/bash

LOGFILE="/var/log/auth.log"

# Monitor authentication logs for privilege escalation indicators
tail -f $LOGFILE | while read line; do
    # Detect su usage
    if echo "$line" | grep -q "su:"; then
        echo "[PRIVESC] SU command detected: $line"
    fi

    # Detect sudo usage with shell access
    if echo "$line" | grep -qE "sudo.*COMMAND=.*/bin/(bash|sh|zsh)"; then
        echo "[PRIVESC] Sudo shell access: $line"
    fi

    # Detect user addition
    if echo "$line" | grep -qE "(useradd|adduser)"; then
        echo "[PRIVESC] User addition detected: $line"
    fi

    # Detect group modification
    if echo "$line" | grep -qE "(usermod|gpasswd).*sudo"; then
        echo "[PRIVESC] Sudo group modification: $line"
    fi

    # Detect password changes
    if echo "$line" | grep -q "passwd:"; then
        echo "[PRIVESC] Password change detected: $line"
    fi
done
```

```bash
chmod +x /usr/local/bin/monitor-privesc.sh
```

### Assessment Checkpoint 5

- [ ] LinPEAS successfully executed
- [ ] Custom privilege escalation detection scripts working

---

## 6: Log Footprint Detection & Final Assessment

### Learning Objectives

- Understand attacker anti-forensics techniques
- Implement comprehensive log analysis
- Complete final assessment project

### Theory: Log Footprint & Anti-Forensics

**Attacker Log Evasion Techniques:**

- Log file deletion
- Log rotation manipulation
- Timestamp modification
- Remote syslog redirection
- Binary log corruption

**Detection Strategies:**

- Log integrity monitoring
- Centralized logging
- Log backup and retention
- File system monitoring

### Practical Lab 6.1: Advanced Log Analysis

#### Detect Log Tampering:

```bash
# Create log integrity checker
sudo nano /usr/local/bin/log-integrity.sh
```

```bash
#!/bin/bash

LOG_DIR="/var/log"
CHECKSUM_FILE="/var/lib/log-checksums.db"

# Function to calculate checksums
calculate_checksums() {
    find $LOG_DIR -name "*.log" -type f -exec sha256sum {} \; | sort > $CHECKSUM_FILE.new
}

# Function to check integrity
check_integrity() {
    if [ -f $CHECKSUM_FILE ]; then
        calculate_checksums
        if ! diff $CHECKSUM_FILE $CHECKSUM_FILE.new >/dev/null; then
            echo "[ALERT] Log file changes detected:"
            diff $CHECKSUM_FILE $CHECKSUM_FILE.new
        else
            echo "[INFO] Log integrity verified"
        fi
        mv $CHECKSUM_FILE.new $CHECKSUM_FILE
    else
        calculate_checksums
        mv $CHECKSUM_FILE.new $CHECKSUM_FILE
        echo "[INFO] Initial checksum database created"
    fi
}

check_integrity
```

```bash
chmod +x /usr/local/bin/log-integrity.sh
```

#### Advanced Attack Detection Patterns:

```bash
# Create comprehensive attack detection
sudo nano /usr/local/bin/attack-patterns.sh
```

```bash
#!/bin/bash

LOGFILE="/var/log/auth.log"
SYSLOGFILE="/var/log/syslog"

echo "=== Advanced Attack Pattern Detection ==="

# Pattern 1: Rapid login attempts from multiple IPs
echo "=== Distributed Brute Force Detection ==="
grep "Failed password" $LOGFILE | grep "$(date +%b\ %d)" | \
grep -oP 'from \K[0-9.]+' | sort | uniq | wc -l | \
xargs echo "Unique IPs with failed attempts today:"

# Pattern 2: Time-based attack analysis
echo -e "\n=== Time-based Attack Analysis ==="
grep "Failed password" $LOGFILE | grep "$(date +%b\ %d)" | \
awk '{print $3}' | cut -d: -f1 | sort | uniq -c | \
sort -nr | head -5 | while read count hour; do
    echo "Hour $hour: $count failed attempts"
done

# Pattern 3: Service enumeration detection
echo -e "\n=== Service Enumeration Detection ==="
grep "Connection closed" $LOGFILE | grep "$(date +%b\ %d)" | \
grep -oP 'from \K[0-9.]+' | sort | uniq -c | \
sort -nr | head -5 | while read count ip; do
    echo "IP $ip: $count quick disconnections (possible scanning)"
done

# Pattern 4: Privilege escalation chains
echo -e "\n=== Privilege Escalation Chain Detection ==="
grep "sudo" $LOGFILE | grep "$(date +%b\ %d)" | \
while read line; do
    if echo "$line" | grep -qE "su|bash|sh"; then
        echo "[CHAIN] $line"
    fi
done

# Pattern 5: Log gap analysis
echo -e "\n=== Log Gap Analysis ==="
current_hour=$(date +%H)
for hour in $(seq 0 $current_hour); do
    hour_formatted=$(printf "%02d" $hour)
    count=$(grep "$hour_formatted:" $LOGFILE | grep "$(date +%b\ %d)" | wc -l)
    if [ $count -eq 0 ]; then
        echo "[SUSPICIOUS] No logs for hour $hour_formatted - possible log deletion"
    fi
done
```

```bash
chmod +x /usr/local/bin/attack-patterns.sh
```

### Final Assessment Project: Linux Services & Syslogs Comparison

#### Objective

Create a comprehensive comparison report analyzing Linux services and syslog outputs between normal operations and simulated attack scenarios.

#### Requirements:

**1. Baseline Collection (30 minutes normal operation):**

```bash
# Collect baseline data
systemctl list-units --type=service --state=active > baseline_services.txt
cp /var/log/auth.log baseline_auth.log
cp /var/log/syslog baseline_syslog.log
/usr/local/bin/security-monitor.sh > baseline_security_report.txt
```

**2. Attack Simulation (from Kali Linux):**

```bash
# Simulate various attacks
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.20
nmap -sS -O -sV 192.168.100.20
ssh invalid_user@192.168.100.20  # Multiple times
```

**3. Post-Attack Analysis:**

```bash
# Collect post-attack data
systemctl list-units --type=service --state=active > attack_services.txt
cp /var/log/auth.log attack_auth.log
cp /var/log/syslog attack_syslog.log
/usr/local/bin/security-monitor.sh > attack_security_report.txt
```

**4. Comparison Analysis Script:**

```bash
sudo nano /usr/local/bin/compare-logs.sh
```

```bash
#!/bin/bash

echo "=== Linux Services and Syslogs Comparison Report ==="
echo "Generated: $(date)"
echo

# Service comparison
echo "=== Service Status Comparison ==="
echo "Services in baseline but not in attack scenario:"
comm -23 baseline_services.txt attack_services.txt

echo -e "\nServices in attack scenario but not in baseline:"
comm -13 baseline_services.txt attack_services.txt

# Authentication log comparison
echo -e "\n=== Authentication Log Analysis ==="
baseline_failed=$(grep -c "Failed password" baseline_auth.log)
attack_failed=$(grep -c "Failed password" attack_auth.log)
echo "Failed login attempts - Baseline: $baseline_failed, Attack: $attack_failed"

# Syslog comparison
echo -e "\n=== System Log Analysis ==="
baseline_entries=$(wc -l < baseline_syslog.log)
attack_entries=$(wc -l < attack_syslog.log)
echo "Total log entries - Baseline: $baseline_entries, Attack: $attack_entries"

# New IPs in attack scenario
echo -e "\n=== New IP Addresses in Attack Scenario ==="
grep -oP 'from \K[0-9.]+' baseline_auth.log | sort -u > baseline_ips.txt
grep -oP 'from \K[0-9.]+' attack_auth.log | sort -u > attack_ips.txt
comm -13 baseline_ips.txt attack_ips.txt

# Service port changes
echo -e "\n=== Network Service Changes ==="
echo "This analysis would compare listening ports before and after attacks"

echo -e "\n=== Conclusion ==="
echo "Analysis complete. Review above sections for security implications."
```

```bash
chmod +x /usr/local/bin/compare-logs.sh
```

### Final Assessment Deliverable

Students must submit a comprehensive report including:

1. **Executive Summary**: Key findings and security recommendations
2. **Service Analysis**: Comparison of service states and configurations
3. **Log Analysis**: Detailed syslog and authentication log comparison
4. **Attack Detection**: Evidence of attack patterns in logs
5. **Mitigation Recommendations**: Specific security improvements
6. **ELK Dashboard Screenshots**: Visual evidence of analysis

### Assessment Rubric

**Excellent (90-100%):**

- Complete lab implementation
- Comprehensive analysis report
- Advanced detection techniques demonstrated
- Clear security recommendations

**Good (80-89%):**

- Most labs completed successfully
- Adequate analysis with minor gaps
- Basic detection techniques used
- General security recommendations

**Satisfactory (70-79%):**

- Basic lab completion
- Minimal analysis provided
- Limited detection capabilities
- Generic recommendations

**Needs Improvement (<70%):**

- Incomplete lab work
- Missing analysis components
- No evidence of understanding
- No actionable recommendations

---

## Additional Resources

### Recommended Reading

- "The Practice of Network Security Monitoring" by Richard Bejtlich
- "Applied Network Security Monitoring" by Chris Sanders
- "Linux Security Cookbook" by Daniel J. Barrett

### Useful Commands Reference

```bash
# Service Management
systemctl status <service>
systemctl list-units --type=service
journalctl -u <service>

# Log Analysis
tail -f /var/log/auth.log
grep -E "(Failed|Accepted)" /var/log/auth.log
journalctl --since "1 hour ago" -p err

# Network Monitoring
ss -tuln
netstat -tuln
lsof -i

# Process Monitoring
ps aux
top
htop

# File Permissions
find / -perm -4000 -type f 2>/dev/null  # SUID
find / -perm -2000 -type f 2>/dev/null  # SGID
find / -perm -002 -type f 2>/dev/null   # World writable
```

### Security Best Practices

1. **Principle of Least Privilege**: Grant minimal necessary permissions
2. **Defense in Depth**: Multiple layers of security controls
3. **Continuous Monitoring**: Real-time threat detection
4. **Regular Updates**: Keep systems patched and current
5. **Log Retention**: Maintain adequate log history for analysis
6. **Incident Response**: Have procedures for security events

---

## Conclusion

This comprehensive guide provides a structured approach to learning Linux endpoint security, log analysis, and privilege escalation detection. Through hands-on practical exercises combined with solid theoretical foundations, students will develop the skills necessary for effective cybersecurity analysis and defense.

The week-long curriculum progresses from basic service management to advanced threat detection, culminating in a real-world assessment that demonstrates practical cybersecurity skills. The integration of the ELK Stack provides modern, industry-relevant log analysis capabilities that students can immediately apply in professional environments.

Remember: Security is not a destination but a continuous journey of learning, monitoring, and improvement.
