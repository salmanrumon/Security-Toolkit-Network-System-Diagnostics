#!/usr/bin/env python3
"""
Log Analyzer - Parses Windows Event Logs and syslog files, flags suspicious activity.
Run as Administrator for full Windows Event Log access.
"""

import os
import sys
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# Event IDs that indicate suspicious activity (Windows Security events)
SUSPICIOUS_WINDOWS_EVENTS = {
    # Authentication failures
    4625: "Failed logon attempt",
    4648: "Logon attempted with explicit credentials",
    4771: "Kerberos pre-authentication failed",
    4776: "NTLM authentication failed",
    
    # Account changes
    4720: "User account created",
    4722: "User account enabled",
    4724: "Password reset attempted",
    4728: "User added to security-enabled group",
    4732: "User added to security-enabled local group",
    4733: "User removed from security-enabled local group",
    4738: "User account changed",
    4739: "Domain policy changed",
    
    # Suspicious activity
    4688: "New process created",
    4698: "Scheduled task created",
    4699: "Scheduled task deleted",
    4700: "Scheduled task enabled",
    4701: "Scheduled task disabled",
    4719: "System audit policy changed",
    7045: "New service installed",
    4624: "Successful logon (review for off-hours)",
    4672: "Special privileges assigned to new logon",
    4673: "Sensitive privilege use",
    4689: "Process exited",
    4690: "Attempt to duplicate handle to object",
    5140: "Network share object accessed",
    5145: "Network share object checked",
    5156: "Filtering platform connection",
    5157: "Filtering platform connection blocked",
}

# Syslog patterns for suspicious activity
SYSLOG_SUSPICIOUS_PATTERNS = [
    (r'failed password|authentication failure', 'Failed authentication'),
    (r'invalid user|invalid password', 'Invalid login attempt'),
    (r'connection refused|connection reset', 'Connection issues'),
    (r'root login|su:|sudo', 'Privilege escalation attempt'),
    (r'denied|permission denied', 'Access denied'),
    (r'intrusion|intruder', 'Possible intrusion'),
    (r'malware|virus|trojan', 'Malware reference'),
    (r'brute force|brute-force', 'Brute force attempt'),
    (r'port scan|portscan', 'Port scanning'),
    (r'buffer overflow', 'Buffer overflow attempt'),
    (r'sql injection|sqli', 'SQL injection attempt'),
    (r'xss|cross.site', 'XSS attempt'),
    (r'exploit', 'Exploit attempt'),
    (r'out of memory|oom', 'System stress'),
]


class LogAnalyzer:
    def __init__(self):
        self.findings = []
        self.stats = defaultdict(int)
        
    def add_finding(self, source, event_id, message, severity='MEDIUM'):
        self.findings.append({
            'source': source,
            'event_id': event_id,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        })
        self.stats[severity] += 1
        
    def parse_windows_events(self, hours=24):
        """Parse Windows Security Event Log via PowerShell."""
        if sys.platform != 'win32':
            print("[!] Windows Event Log parsing requires Windows")
            return []
        
        try:
            script = f'''
            Get-WinEvent -FilterHashtable @{{
                LogName='Security'
                Id=@(4625,4648,4771,4776,4720,4722,4724,4728,4732,4733,4738,4739,
                    4688,4698,4699,4700,4701,4719,7045,4672,4673,4690,5140,5145,5156,5157)
                StartTime=[datetime]::Now.AddHours(-{hours})
            }} -MaxEvents 500 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message |
            ForEach-Object {{ 
                "$($_.TimeCreated)|$($_.Id)|$($_.Message -replace \"`n\",\" \")" 
            }}
            '''
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', script],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if '|' in line:
                        parts = line.split('|', 2)
                        if len(parts) >= 3:
                            time_str, event_id, message = parts[0], parts[1], parts[2]
                            try:
                                eid = int(event_id)
                                desc = SUSPICIOUS_WINDOWS_EVENTS.get(eid, f"Event {eid}")
                                severity = 'HIGH' if eid in (4625, 4720, 4728, 7045) else 'MEDIUM'
                                self.add_finding('Windows Security', eid, 
                                    f"{desc}: {message[:200]}...", severity)
                            except (ValueError, IndexError):
                                pass
            else:
                if 'Access is denied' in (result.stderr or ''):
                    self.add_finding('Log Analyzer', 0, 
                        'Access denied - run as Administrator for Event Log access', 'HIGH')
                elif result.stderr:
                    self.add_finding('Log Analyzer', 0, f"Error: {result.stderr[:100]}", 'LOW')
                    
        except subprocess.TimeoutExpired:
            self.add_finding('Log Analyzer', 0, 'Event log query timed out', 'LOW')
        except Exception as e:
            self.add_finding('Log Analyzer', 0, str(e), 'LOW')
            
        return self.findings
    
    def parse_syslog_file(self, filepath):
        """Parse a syslog file for suspicious patterns."""
        path = Path(filepath)
        if not path.exists():
            self.add_finding('Log Analyzer', 0, f"File not found: {filepath}", 'LOW')
            return []
            
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line_lower = line.lower()
                    for pattern, desc in SYSLOG_SUSPICIOUS_PATTERNS:
                        if re.search(pattern, line_lower):
                            severity = 'HIGH' if 'failed' in pattern or 'invalid' in pattern else 'MEDIUM'
                            self.add_finding(
                                path.name, line_num,
                                f"{desc}: {line.strip()[:150]}",
                                severity
                            )
                            break
        except PermissionError:
            self.add_finding('Log Analyzer', 0, f"Permission denied: {filepath}", 'HIGH')
        except Exception as e:
            self.add_finding('Log Analyzer', 0, str(e), 'LOW')
            
        return self.findings
    
    def parse_evtx_export(self, csv_path):
        """Parse exported EVTX (as CSV) if available."""
        path = Path(csv_path)
        if not path.exists():
            return []
        # Simplified - real impl would parse CSV
        return []
    
    def print_report(self):
        """Print analysis report."""
        print("\n" + "="*60)
        print("LOG ANALYSIS REPORT - SUSPICIOUS ACTIVITY")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("="*60)
        
        if not self.findings:
            print("\n[OK] No suspicious activity detected in analyzed logs.")
            return
            
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
        low = [f for f in self.findings if f['severity'] == 'LOW']
        
        for finding in high + medium + low:
            print(f"\n[{finding['severity']}] {finding['source']} (ID: {finding['event_id']})")
            print(f"  {finding['message'][:200]}")
            
        print("\n" + "="*60)
        print(f"Total: {len(self.findings)} | HIGH: {len(high)} | MEDIUM: {len(medium)} | LOW: {len(low)}")
        print("="*60)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Log Analyzer - Flag suspicious activity')
    parser.add_argument('--windows', action='store_true', help='Analyze Windows Event Logs')
    parser.add_argument('--syslog', type=str, help='Path to syslog file')
    parser.add_argument('--hours', type=int, default=24, help='Hours of Windows events to analyze')
    args = parser.parse_args()
    
    analyzer = LogAnalyzer()
    
    if args.windows or (not args.syslog and sys.platform == 'win32'):
        print("[*] Analyzing Windows Security Event Log...")
        analyzer.parse_windows_events(hours=args.hours)
        
    if args.syslog:
        print(f"[*] Analyzing syslog: {args.syslog}")
        analyzer.parse_syslog_file(args.syslog)
        
    if not args.windows and not args.syslog and sys.platform != 'win32':
        print("Usage: Specify --windows and/or --syslog <path>")
        return
        
    analyzer.print_report()


if __name__ == '__main__':
    main()
