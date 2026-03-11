#!/usr/bin/env python3
"""
System Compromise Checker - Detects signs of hacking/compromise on Windows.
Run as Administrator for comprehensive checks.
"""

import os
import sys
import subprocess
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Known suspicious process names (common malware/backdoors)
SUSPICIOUS_PROCESSES = [
    'mimikatz', 'pwdump', 'procdump', 'psexec', 'wce',
    'nc.exe', 'ncat', 'netcat', 'reverse_shell',
    'cobaltstrike', 'metasploit', 'meterpreter',
    'keylogger', 'keylog', 'hook', 'inject',
    'cryptolocker', 'wannacry', 'ransomware',
    'miner', 'xmrig', 'cryptonight', 'coinhive',
    'rat', 'remoteadmin', 'darkcomet', 'njrat',
    'empire', 'invoke', 'powersploit',
    'sethc', 'utilman',  # Sticky keys bypass
]

# Suspicious registry persistence locations
PERSISTENCE_PATHS = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "User Run"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
    (r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "Startup"),
]

# Suspicious file extensions often used by malware
SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.vbs', '.js', '.ps1', '.bat', '.scr', '.pif'}

# Double extension trick
DOUBLE_EXT_PATTERN = ['.exe.', '.pdf.exe', '.doc.exe', '.jpg.exe', '.txt.exe']


class CompromiseChecker:
    def __init__(self):
        self.indicators = []
        self.severity_count = defaultdict(int)
        
    def add_indicator(self, category, finding, severity='MEDIUM', remediation=''):
        self.indicators.append({
            'category': category,
            'finding': finding,
            'severity': severity,
            'remediation': remediation or 'Investigate and remediate'
        })
        self.severity_count[severity] += 1
        
    def check_running_processes(self):
        """Check for suspicious running processes."""
        try:
            # Use PowerShell - wmic is deprecated on newer Windows
            script = "Get-Process | Select-Object Name,Path | ConvertTo-Csv -NoTypeInformation"
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', script],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                lines = [l for l in result.stdout.split('\n') if l.strip() and '"Name"' not in l]
                for line in lines:
                    parts = line.split(',', 1)
                    if len(parts) >= 2:
                        # CSV format: "Name","Path"
                        name = parts[0].strip('"').lower()
                        path = (parts[1].strip('"') if len(parts) > 1 else '').lower()
                        for sus in SUSPICIOUS_PROCESSES:
                            if sus in name or (path and sus in path):
                                self.add_indicator('Process',
                                    f"Suspicious process: {name}",
                                    'HIGH', f"Terminate and investigate: {path}")
        except Exception as e:
            self.add_indicator('Process', f"Could not enumerate: {e}", 'LOW')
    
    def check_network_connections(self):
        """Check for suspicious outbound connections."""
        try:
            result = subprocess.run(
                ['netstat', '-ano'],
                capture_output=True, text=True, timeout=15
            )
            # Look for LISTENING on known suspicious/backdoor ports (not ephemeral 49152+)
            suspicious_ports = {4444, 5555, 6666, 1234, 31337, 1337, 9999, 12345, 54321, 27017}
            seen_ports = set()
            for line in result.stdout.split('\n'):
                if 'LISTENING' in line:
                    parts = line.split()
                    for p in parts:
                        if ':' in p:
                            try:
                                port = int(p.split(':')[-1])
                                if port in suspicious_ports and port not in seen_ports:
                                    seen_ports.add(port)
                                    self.add_indicator('Network',
                                        f"Listening on suspicious port {port}: {line.strip()[:80]}",
                                        'MEDIUM', 'Verify this service is legitimate')
                            except (ValueError, IndexError):
                                pass
                            break
        except Exception:
            pass
    
    def check_scheduled_tasks(self):
        """Check for suspicious scheduled tasks."""
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'LIST', '/v'],
                capture_output=True, text=True, timeout=20
            )
            output = result.stdout.lower()
            for sus in ['powershell', 'cmd.exe', 'wscript', 'cscript', 'temp', 'appdata']:
                if sus in output:
                    # Only flag if in task path/action
                    tasks = result.stdout.split('Folder:')
                    for task in tasks[1:]:
                        if sus in task.lower() and 'microsoft' not in task.lower():
                            self.add_indicator('Scheduled Task',
                                f"Task may run script: check schtasks",
                                'MEDIUM', 'Run: schtasks /query /fo LIST /v')
                            break
        except Exception:
            pass
    
    def check_startup_items(self):
        """Check startup folder and registry."""
        startup_paths = [
            os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.join(os.environ.get('PROGRAMDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
        ]
        for path in startup_paths:
            if os.path.exists(path):
                try:
                    for f in os.listdir(path):
                        full = os.path.join(path, f)
                        ext = os.path.splitext(f)[1].lower()
                        if ext in {'.exe', '.vbs', '.js', '.bat', '.ps1'}:
                            self.add_indicator('Startup',
                                f"Startup item: {f}",
                                'MEDIUM', 'Verify this is a trusted application')
                except PermissionError:
                    pass
    
    def check_user_accounts(self):
        """Check for recently created or modified users."""
        try:
            result = subprocess.run(
                ['net', 'user'],
                capture_output=True, text=True, timeout=10
            )
            suspicious_names = ['admin', 'test', 'guest', 'support', 'service', 'backup']
            for line in result.stdout.split('\n'):
                user = line.strip()
                if user and not user.startswith('-') and user.lower() in suspicious_names:
                    self.add_indicator('Accounts',
                        f"Potentially suspicious account: {user}",
                        'MEDIUM', 'Verify account is legitimate')
        except Exception:
            pass
    
    def check_hosts_file(self):
        """Check for hosts file hijacking."""
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        try:
            with open(hosts_path, 'r') as f:
                content = f.read()
            # Legit entries: 127.0.0.1 localhost, ::1 localhost
            lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
            if len(lines) > 2:
                for line in lines:
                    if 'localhost' not in line.lower() and '127.0.0.1' not in line:
                        self.add_indicator('Hosts File',
                            f"Unusual hosts entry: {line}",
                            'HIGH', 'Review and remove if malicious')
        except Exception as e:
            self.add_indicator('Hosts File', f"Cannot read: {e}", 'LOW')
    
    def check_dns_settings(self):
        """Check for rogue DNS servers - skipped (manual review recommended)."""
        pass  # Run 'ipconfig /all' manually to verify DNS
    
    def check_temp_files(self):
        """Scan temp for suspicious executables."""
        temp_paths = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            r'C:\Windows\Temp',
        ]
        found = []
        for temp in temp_paths:
            if temp and os.path.exists(temp):
                try:
                    for f in os.listdir(temp)[:100]:  # Limit
                        if f.lower().endswith(('.exe', '.dll', '.scr')):
                            found.append(os.path.join(temp, f))
                except (PermissionError, OSError):
                    pass
        if found:
            self.add_indicator('Temp Files',
                f"Executables in temp: {len(found)} found - review manually",
                'MEDIUM', 'Do not run unknown executables from Temp')
    
    def check_sticky_keys_bypass(self):
        """Check for sticky keys persistence (common attacker trick)."""
        sethc = r'C:\Windows\System32\sethc.exe'
        if os.path.exists(sethc):
            try:
                # Real sethc.exe is ~31KB. Replaced with cmd.exe is ~100KB+.
                size = os.path.getsize(sethc)
                if size > 80000:  # cmd.exe is ~100KB - likely replaced
                    self.add_indicator('Persistence',
                        f"sethc.exe unusually large ({size} bytes) - may be replaced (Sticky Keys bypass)",
                        'CRITICAL', 'Restore from install media: copy sethc.exe from Windows ISO')
                elif size < 10000:  # Too small - stub/loader
                    self.add_indicator('Persistence',
                        f"sethc.exe unusually small ({size} bytes) - verify integrity",
                        'HIGH', 'Restore from Windows install media if suspicious')
            except OSError:
                pass
    
    def run_all_checks(self):
        """Run all compromise checks."""
        print("[*] System Compromise Check - Starting...")
        print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        checks = [
            self.check_running_processes,
            self.check_network_connections,
            self.check_scheduled_tasks,
            self.check_startup_items,
            self.check_user_accounts,
            self.check_hosts_file,
            self.check_temp_files,
            self.check_sticky_keys_bypass,
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                self.add_indicator('Scanner', str(e), 'LOW')
                
        return self.indicators
    
    def print_report(self):
        """Print compromise check report."""
        print("\n" + "="*60)
        print("SYSTEM COMPROMISE CHECK REPORT")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("="*60)
        
        if not self.indicators:
            print("\n[OK] No obvious compromise indicators found.")
            print("     Note: This does NOT guarantee the system is clean.")
            return
            
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        for sev in severity_order:
            items = [i for i in self.indicators if i['severity'] == sev]
            for item in items:
                print(f"\n[{item['severity']}] {item['category']}")
                print(f"  Finding: {item['finding']}")
                if item['remediation']:
                    print(f"  Action: {item['remediation']}")
        
        print("\n" + "="*60)
        crit = self.severity_count.get('CRITICAL', 0)
        high = self.severity_count.get('HIGH', 0)
        if crit or high:
            print("*** CRITICAL/HIGH indicators - System may be compromised! ***")
            print("    Consider: Full AV scan, disconnect from network, professional help")
        print("="*60)


def main():
    checker = CompromiseChecker()
    checker.run_all_checks()
    checker.print_report()


if __name__ == '__main__':
    main()
