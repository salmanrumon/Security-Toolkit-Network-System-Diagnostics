#!/usr/bin/env python3
"""
Security Toolkit - Master script to run all security checks.
Run as Administrator for full functionality.

Usage:
  python main.py              # Run all checks
  python main.py vuln         # Vulnerability scanner only
  python main.py logs         # Log analyzer only
  python main.py compromise   # Compromise checker only
  python main.py virus        # Virus scanner only
"""

import sys
import os

# Add script directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_vulnerability_scan():
    from vulnerability_scanner import VulnerabilityScanner
    scanner = VulnerabilityScanner()
    scanner.run_all_checks()
    scanner.print_report()


def run_log_analyzer():
    from log_analyzer import LogAnalyzer
    analyzer = LogAnalyzer()
    if sys.platform == 'win32':
        analyzer.parse_windows_events(hours=24)
    analyzer.print_report()


def run_compromise_check():
    from compromise_checker import CompromiseChecker
    checker = CompromiseChecker()
    checker.run_all_checks()
    checker.print_report()


def run_virus_scan():
    from virus_scanner import VirusScanner
    scanner = VirusScanner()
    scanner.run_scan()
    scanner.print_report()


def main():
    print("="*60)
    print("       SECURITY TOOLKIT - System Security Check")
    print("="*60)
    
    mode = sys.argv[1].lower() if len(sys.argv) > 1 else 'all'
    
    if mode in ('all', 'vuln', 'vulnerability'):
        run_vulnerability_scan()
        
    if mode in ('all', 'logs', 'log'):
        run_log_analyzer()
        
    if mode in ('all', 'compromise', 'hack'):
        run_compromise_check()
        
    if mode in ('all', 'virus', 'malware'):
        run_virus_scan()
        
    if mode not in ('all', 'vuln', 'vulnerability', 'logs', 'log', 'compromise', 'hack', 'virus', 'malware'):
        print(f"\nUnknown mode: {mode}")
        print("Usage: python main.py [all|vuln|logs|compromise|virus]")
        print("  all        - Run all checks (default)")
        print("  vuln       - Vulnerability scanner")
        print("  logs       - Log analyzer (Windows Event Log)")
        print("  compromise - System compromise checker")
        print("  virus      - Virus/malware scanner")
        return
        
    print("\n[DONE] Security checks complete.")
    print("TIP: Run as Administrator for full Event Log and system access.")
    print("TIP: Use --quarantine with virus_scanner.py to quarantine threats.")
    print("TIP: Run Windows Defender: Start-MpScan -ScanType FullScan")


if __name__ == '__main__':
    main()
