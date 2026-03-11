# Security Toolkit

A suite of security scripts for Windows that checks for vulnerabilities, analyzes logs, detects compromise, and scans for malware.

## Components

### 1. Vulnerability Scanner (`vulnerability_scanner.py`)
Checks for common misconfigurations:
- Weak password policy
- Guest account enabled
- Suspicious autorun/startup entries
- Remote Desktop exposure
- SMBv1 enabled (EternalBlue risk)
- Firewall status
- Windows Update status
- Network shares

### 2. Log Analyzer (`log_analyzer.py`)
Parses logs and flags suspicious activity:
- **Windows Event Log** – Failed logons, account changes, new services, privilege escalation
- **Syslog** – Failed auth, brute force, exploits, malware references

```bash
python log_analyzer.py --windows
python log_analyzer.py --syslog /path/to/syslog
```

### 3. System Compromise Checker (`compromise_checker.py`)
Detects signs of hacking:
- Suspicious processes (mimikatz, miners, RATs, etc.)
- Unusual network listeners
- Suspicious scheduled tasks
- Startup items
- Hosts file hijacking
- Temp folder executables
- Sticky Keys bypass (sethc replacement)

### 4. Virus Scanner (`virus_scanner.py`)
Basic malware detection:
- Known malware hashes (extend as needed)
- Suspicious filenames (double extensions, random hex names)
- Suspicious content (shellcode patterns, crypto miners, PowerShell droppers)
- **Quarantine** or **delete** detected files

```bash
python virus_scanner.py --scan
python virus_scanner.py --quarantine   # Move threats to quarantine
python virus_scanner.py --defender    # Also run Windows Defender
```

## Usage

**Run everything:**
```bash
python main.py
```

**Run individual tools:**
```bash
python main.py vuln        # Vulnerability scan
python main.py logs        # Log analysis
python main.py compromise  # Compromise check
python main.py virus       # Virus scan
```

**Run tools directly:**
```bash
python vulnerability_scanner.py
python log_analyzer.py --windows --hours 48
python compromise_checker.py
python virus_scanner.py --scan --quarantine --defender
```

## Requirements

- **Python 3.6+**
- **Windows** (primary target; some features are Windows-specific)
- **Administrator rights** for full Event Log access and system scans

## Important Notes

1. **Not a replacement for antivirus** – Use Windows Defender or a commercial AV. This toolkit supplements them.
2. **Run as Administrator** – For Event Logs and full system access.
3. **Quarantine before delete** – Virus scanner can quarantine first so you can review.
4. **False positives** – Heuristic detection may flag legitimate software. Review findings before taking action.

## Windows Defender

For a full antivirus scan:
```powershell
Start-MpScan -ScanType FullScan
```

To update definitions:
```powershell
Update-MpSignature
```
