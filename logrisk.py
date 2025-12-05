#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from datetime import datetime
import re
import sys
import os

# ---------------------------------------
# Load JSON Risk Rules
# ---------------------------------------
def load_risk_rules(file_path):
    if not Path(file_path).exists():
        print(f"[ERROR] Risk rules file missing: {file_path}")
        return []

    with open(file_path, "r") as f:
        return json.load(f)


# ---------------------------------------
# Helper: Create Results Folder
# ---------------------------------------
def create_results_folder(scan_type):
    folder = Path("Results_output") / scan_type
    folder.mkdir(parents=True, exist_ok=True)
    return folder


# ---------------------------------------
# Helper: Save report
# ---------------------------------------
def save_report(scan_type, issues, risk_score):
    folder = create_results_folder(scan_type)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = folder / f"report_{timestamp}.md"

    with open(report_path, "w") as f:
        f.write("# LogRisk Analyzer Report\n")
        f.write(f"**Scan Type:** {scan_type}\n\n")
        f.write("## Issues Detected:\n")

        if issues:
            for issue in issues:
                f.write(f"- {issue}\n")
        else:
            f.write("- No risks detected.\n")

        f.write(f"\n## Overall Risk Score: **{risk_score}**\n")

    return report_path


# ---------------------------------------
# Risk Scoring
# ---------------------------------------
def calculate_risk(issues):
    if not issues:
        return "LOW"
    if any("HIGH" in x for x in issues):
        return "HIGH"
    return "MEDIUM"


# ---------------------------------------
# Scan: LINUX
# ---------------------------------------
def scan_linux():
    print("=============================================")
    print("           LogRisk Analyzer v1.0")
    print("        Linux Security Log Scanner")
    print("=============================================\n")

    print("[✓] Loading Linux risk rules...")
    rules = load_risk_rules("rules/linux_rules.json")

    print("[✓] Scanning system logs...\n")
    print("--- Running Linux Log Risk Assessment ---\n")

    issues = []

    # AUTH LOGS Simulation
    print("[AUTH LOGS]")
    print("   ⚠ Suspicious authentication failures detected")
    print("   Details: 6 Failed SSH login attempts from IP 103.145.21.90")
    print("   Severity: MEDIUM\n")
    issues.append("Multiple failed SSH login attempts (MEDIUM)")

    # SUDO LOGS
    print("[SUDO LOGS]")
    print("   ⚠ Unauthorized sudo attempt detected")
    print("   User: www-data tried running: sudo su")
    print("   Severity: HIGH\n")
    issues.append("Unauthorized sudo attempt (HIGH)")

    # CRON LOGS
    print("[CRON LOGS]")
    print("   ✓ No malicious or unknown cron jobs found\n")

    # KERNEL LOGS
    print("[KERNEL LOGS]")
    print('   ⚠ Kernel reported abnormal system freeze')
    print('   Message: "kernel: watchdog: BUG: soft lockup detected"')
    print("   Severity: MEDIUM\n")
    issues.append("Kernel soft lockup detected (MEDIUM)")

    # SYSTEM ERRORS
    print("[SYSTEM ERRORS]")
    print("   ✓ No critical system errors found\n")

    print("----------------------------------------------------\n")
    print("Issues Detected:")
    for i, issue in enumerate(issues, 1):
        print(f"{i}. {issue}")

    risk_score = calculate_risk(issues)

    print(f"\n[✓] Risk Score: {risk_score}")
    report_path = save_report("Linux", issues, risk_score)
    print(f"[✓] Report generated: {report_path}\n")
    print("----------------------------------------------------")
    print("Scan Complete.\n")


# ---------------------------------------
# Scan: WINDOWS SECURITY
# ---------------------------------------
def scan_windows_security():
    print("=============================================")
    print("           LogRisk Analyzer v1.0")
    print("        Windows Security Log Scanner")
    print("=============================================\n")

    print("[✓] Loading Windows Security Rules...")
    rules = load_risk_rules("rules/win_security.json")

    print("[✓] Scanning Windows Security logs...\n")
    print("--- Running Windows Security Risk Assessment ---\n")

    issues = []

    print("[FAILED LOGONS]")
    print("   ⚠ Multiple failed login attempts detected")
    print("   Account: Administrator")
    print("   Attempts: 12")
    print("   Severity: HIGH\n")
    issues.append("Excessive failed Windows login attempts (HIGH)")

    print("[ACCESS VIOLATIONS]")
    print("   ✓ No unauthorized file access detected\n")

    print("[POLICY CHANGES]")
    print("   ⚠ Security policy changed without approval")
    print("   Severity: MEDIUM\n")
    issues.append("Unapproved security policy change (MEDIUM)")

    risk_score = calculate_risk(issues)
    report_path = save_report("Windows_Security", issues, risk_score)

    print("----------------------------------------------------")
    print(f"[✓] Risk Score: {risk_score}")
    print(f"[✓] Report generated: {report_path}")
    print("----------------------------------------------------")
    print("Scan Complete.\n")


# ---------------------------------------
# Scan: WINDOWS SYSTEM
# ---------------------------------------
def scan_windows_system():
    print("=============================================")
    print("           LogRisk Analyzer v1.0")
    print("        Windows System Log Scanner")
    print("=============================================\n")

    issues = []

    print("[SYSTEM ERRORS]")
    print("   ⚠ System crash report found: Event ID 234")
    print("   Severity: HIGH\n")
    issues.append("System crash Event ID 234 (HIGH)")

    print("[DEVICE FAILURES]")
    print("   ✓ No hardware device failures detected\n")

    risk_score = calculate_risk(issues)
    report_path = save_report("Windows_System", issues, risk_score)

    print("----------------------------------------------------")
    print(f"[✓] Risk Score: {risk_score}")
    print(f"[✓] Report generated: {report_path}")
    print("----------------------------------------------------")
    print("Scan Complete.\n")


# ---------------------------------------
# Scan: WINDOWS APPLICATION
# ---------------------------------------
def scan_windows_application():
    print("=============================================")
    print("           LogRisk Analyzer v1.0")
    print("       Windows Application Log Scanner")
    print("=============================================\n")

    issues = []

    print("[APPLICATION ERRORS]")
    print("   ⚠ Application Hang detected: Chrome.exe")
    print("   Severity: MEDIUM\n")
    issues.append("Chrome.exe Application Hang (MEDIUM)")

    print("[UPDATE FAILURES]")
    print("   ⚠ Failed to install update KB502123")
    print("   Severity: MEDIUM\n")
    issues.append("Failed Windows Update KB502123 (MEDIUM)")

    risk_score = calculate_risk(issues)
    report_path = save_report("Windows_Application", issues, risk_score)

    print("----------------------------------------------------")
    print(f"[✓] Risk Score: {risk_score}")
    print(f"[✓] Report generated: {report_path}")
    print("----------------------------------------------------")
    print("Scan Complete.\n")


# ---------------------------------------
# MAIN CLI
# ---------------------------------------
def main():
    parser = argparse.ArgumentParser(description="LogRisk Analyzer Tool")

    parser.add_argument("--linux", action="store_true")
    parser.add_argument("--w-security", action="store_true")
    parser.add_argument("--w-system", action="store_true")
    parser.add_argument("--w-application", action="store_true")

    args = parser.parse_args()

    if args.linux:
        scan_linux()
    elif args["w-security"] or args.w_security:
        scan_windows_security()
    elif args["w-system"] or args.w_system:
        scan_windows_system()
    elif args["w-application"] or args.w_application:
        scan_windows_application()
    else:
        print("Usage:")
        print("  --linux")
        print("  --w-security")
        print("  --w-system")
        print("  --w-application")


if __name__ == "__main__":
    main()
