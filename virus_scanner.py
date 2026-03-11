#!/usr/bin/env python3
"""
Basic Virus/Malware Scanner - Scans for common malware indicators and can quarantine/delete.
NOTE: This is NOT a replacement for professional antivirus (Windows Defender, Malwarebytes).
Run as Administrator for full system scan.
"""

import os
import sys
import re
import hashlib
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Known malicious file hashes (MD5) - sample list, expand from threat intel
# In production, use a proper threat intelligence feed
KNOWN_MALWARE_HASHES = set()  # Add hashes from VirusTotal, etc.

# Suspicious strings - specific malware indicators (avoid broad patterns that cause false positives)
SUSPICIOUS_STRINGS = [
    (b'shellcode', 'Shellcode injection'),
    (b'mimikatz', 'Credential theft tool'),
    (b'pwdump', 'Password dumping tool'),
    (b'pass-the-hash', 'Attack tool'),
    (b'powershell -enc', 'Encoded PowerShell (common in malware)'),
    (b'powershell -e ', 'Encoded PowerShell'),
    (b'DownloadString', 'Remote code download'),
    (b'IEX(', 'Invoke-Expression (code execution)'),
    (b'Invoke-Mimikatz', 'Mimikatz invocation'),
    (b'Invoke-Shellcode', 'Shellcode execution'),
    (b'xmrig', 'Cryptominer'),
    (b'coinhive', 'Browser miner'),
    (b'cryptonight', 'Mining algorithm'),
    (b'ransomware', 'Ransomware'),
    (b'wannacry', 'WannaCry ransomware'),
    (b'keylogger', 'Keylogger'),
]

# Suspicious filenames/patterns
SUSPICIOUS_NAMES = [
    r'\.exe\.exe$', r'\.pdf\.exe$', r'\.doc\.exe$', r'\.jpg\.exe$',
    r'^svchost\.exe$', r'^csrss\.exe$',  # In wrong folder
    r'^[a-f0-9]{8}\.exe$',  # Random hex name
    r'cryptolocker', r'wannacry', r'locky',
    r'keylogger', r'miner', r'bitcoin',
]

# Paths to scan (user-writable locations where malware often lands)
SCAN_PATHS = [
    os.environ.get('USERPROFILE', ''),
    os.environ.get('APPDATA', ''),
    os.environ.get('LOCALAPPDATA', ''),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
    r'C:\Windows\Temp',
    os.environ.get('TEMP', ''),
    os.environ.get('TMP', ''),
]


class VirusScanner:
    def __init__(self, quarantine_dir=None):
        self.threats = []
        self.scanned = 0
        self.quarantine_dir = quarantine_dir or os.path.join(
            os.environ.get('PROGRAMDATA', 'C:\\ProgramData'),
            'SecurityToolkit_Quarantine'
        )
        
    def add_threat(self, filepath, reason, severity='HIGH'):
        self.threats.append({
            'path': filepath,
            'reason': reason,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        })
        
    def compute_hash(self, filepath):
        """Compute MD5 of file (first 1MB for speed)."""
        try:
            hasher = hashlib.md5()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    hasher.update(chunk)
                    if f.tell() > 1024 * 1024:  # 1MB
                        break
            return hasher.hexdigest()
        except Exception:
            return None
            
    def scan_file_content(self, filepath):
        """Check file content for suspicious patterns."""
        try:
            with open(filepath, 'rb') as f:
                content = f.read(1024 * 128)  # First 128KB
            for pattern, desc in SUSPICIOUS_STRINGS:
                if pattern in content:
                    return f"Contains {desc}: {pattern.decode('utf-8', errors='ignore')}"
        except (OSError, PermissionError):
            pass
        return None
        
    def scan_file_name(self, filepath):
        """Check filename for suspicious patterns."""
        name = os.path.basename(filepath).lower()
        for pattern in SUSPICIOUS_NAMES:
            if re.search(pattern, name):
                return f"Suspicious filename pattern: {name}"
        return None
        
    def scan_file(self, filepath):
        """Scan a single file."""
        if not os.path.isfile(filepath):
            return
            
        self.scanned += 1
        ext = os.path.splitext(filepath)[1].lower()
        
        # Skip large files and non-executable types for content scan
        scan_extensions = {'.exe', '.dll', '.scr', '.vbs', '.js', '.bat', '.ps1', '.com', '.pif'}
        if ext not in scan_extensions:
            return
            
        # Hash check
        fhash = self.compute_hash(filepath)
        if fhash and fhash in KNOWN_MALWARE_HASHES:
            self.add_threat(filepath, f"Known malware hash: {fhash}", 'CRITICAL')
            return
            
        # Filename check
        name_reason = self.scan_file_name(filepath)
        if name_reason:
            self.add_threat(filepath, name_reason, 'HIGH')
            return
            
        # Content check - only for executables
        if ext in {'.exe', '.dll', '.vbs', '.js', '.ps1', '.bat'}:
            content_reason = self.scan_file_content(filepath)
            if content_reason:
                self.add_threat(filepath, content_reason, 'MEDIUM')
            
    def scan_directory(self, path, max_files=10000):
        """Recursively scan directory."""
        if not path or not os.path.exists(path):
            return
        count = 0
        try:
            for root, dirs, files in os.walk(path):
                # Skip system dirs
                dirs[:] = [d for d in dirs if d.lower() not in 
                    ('windows', 'program files', 'program files (x86)', '$recycle.bin', 'node_modules')]
                for f in files:
                    if count >= max_files:
                        return
                    try:
                        full = os.path.join(root, f)
                        self.scan_file(full)
                        count += 1
                    except (OSError, PermissionError):
                        pass
        except (OSError, PermissionError):
            pass
            
    def quarantine_file(self, filepath):
        """Move file to quarantine folder."""
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            name = os.path.basename(filepath)
            safe_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{name}"
            dest = os.path.join(self.quarantine_dir, safe_name)
            shutil.move(filepath, dest)
            return True, dest
        except Exception as e:
            return False, str(e)
            
    def delete_file(self, filepath):
        """Permanently delete file (use with caution)."""
        try:
            os.remove(filepath)
            return True, None
        except Exception as e:
            return False, str(e)
            
    def run_scan(self, custom_paths=None):
        """Run full scan."""
        paths = custom_paths or SCAN_PATHS
        print("[*] Virus Scanner - Starting scan...")
        print(f"[*] Scanning: {len(paths)} locations")
        print()
        
        for path in paths:
            if path and os.path.exists(path):
                if os.path.isfile(path):
                    self.scan_file(path)
                else:
                    self.scan_directory(path)
                    
        return self.threats
        
    def run_windows_defender(self):
        """Trigger Windows Defender quick scan via PowerShell."""
        if sys.platform != 'win32':
            return False
        try:
            subprocess.run(
                ['powershell', '-Command',
                 'Start-MpScan -ScanType QuickScan'],
                capture_output=True, timeout=600
            )
            return True
        except Exception:
            return False
            
    def print_report(self, auto_quarantine=False, auto_delete=False):
        """Print scan report and optionally quarantine/delete."""
        print("\n" + "="*60)
        print("VIRUS SCAN REPORT")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print(f"Files scanned: {self.scanned}")
        print("="*60)
        
        if not self.threats:
            print("\n[OK] No threats detected by this scanner.")
            print("     Run Windows Defender for comprehensive scan: Start-MpScan -ScanType FullScan")
            return
            
        for t in self.threats:
            print(f"\n[{t['severity']}] {t['path']}")
            print(f"  Reason: {t['reason']}")
            
            if auto_quarantine:
                ok, msg = self.quarantine_file(t['path'])
                if ok:
                    print(f"  -> Quarantined to: {msg}")
                else:
                    print(f"  -> Quarantine failed: {msg}")
            elif auto_delete and t['severity'] in ('CRITICAL', 'HIGH'):
                ok, err = self.delete_file(t['path'])
                if ok:
                    print(f"  -> Deleted")
                else:
                    print(f"  -> Delete failed: {err}")
                    
        print("\n" + "="*60)
        print(f"Threats found: {len(self.threats)}")
        print("Quarantine folder:", self.quarantine_dir)
        print("="*60)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Basic Virus Scanner')
    parser.add_argument('--scan', action='store_true', help='Run scan')
    parser.add_argument('--quarantine', action='store_true', help='Quarantine detected threats')
    parser.add_argument('--delete', action='store_true', help='Delete high-severity threats (DANGEROUS)')
    parser.add_argument('--defender', action='store_true', help='Also run Windows Defender quick scan')
    parser.add_argument('--path', type=str, help='Custom path to scan')
    args = parser.parse_args()
    
    paths = [args.path] if args.path else None
    
    scanner = VirusScanner()
    scanner.run_scan(custom_paths=paths)
    
    if args.defender:
        print("\n[*] Starting Windows Defender Quick Scan...")
        scanner.run_windows_defender()
        
    scanner.print_report(auto_quarantine=args.quarantine, auto_delete=args.delete)


if __name__ == '__main__':
    main()
