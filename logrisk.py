#!/usr/bin/env python3
import os
import json
import argparse
import re
from datetime import datetime
import shutil

# -------------------------
# Helper Functions
# -------------------------
def load_risk_rules(file_path):
    with open(file_path, 'r') as f:
        rules = json.load(f)
    return rules

def create_results_folder(scan_type):
    base_folder = os.path.join("Results_output", scan_type)
    if not os.path.exists(base_folder):
        os.makedirs(base_folder)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_folder = os.path.join(base_folder, timestamp)
    os.mkdir(run_folder)
    return run_folder

def predict_risk_level(weight):
    if weight >= 7:
        return "High"
    elif weight >= 4:
        return "Medium"
    else:
        return "Low"

def scan_log(log_file, rules, verbose=False):
    matches = []
    with open(log_file, 'r') as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        for rule in rules:
            if re.search(rule['pattern'], line):
                risk_info = {
                    "line_no": i+1,
                    "line_content": line.strip(),
                    "id": rule['id'],
                    "risk": rule['name'],
                    "weight": rule['weight'],
                    "level": predict_risk_level(rule['weight']),
                    "suggested_fix": rule['suggested_treatment'],
                    "category": rule['category']
                }
                matches.append(risk_info)
                if verbose:
                    print(f"[{risk_info['level']}] {risk_info['risk']} - line {i+1}")
    return matches

def save_reports(matches, output_name, run_folder, log_file, json_report=False):
    # Save main text report
    text_report_path = os.path.join(run_folder, output_name)
    with open(text_report_path, "w") as f:
        for m in matches:
            f.write(f"Risk: {m['risk']}\n")
            f.write(f"Level: {m['level']}\n")
            f.write(f"Fix: {m['suggested_fix']}\n")
            f.write(f"Log Line: {m['line_content']}\n")
            f.write("-"*40 + "\n")

    # Save JSON report if requested
    if json_report:
        json_path = os.path.join(run_folder, "predicted_risks.json")
        with open(json_path, "w") as f:
            json.dump(matches, f, indent=4)

    # Copy scanned log file
    scanned_log_path = os.path.join(run_folder, os.path.basename(log_file))
    shutil.copy(log_file, scanned_log_path)

    # Save separate folders for each detected risk
    for m in matches:
        risk_folder_name = f"{m['id']}_{m['risk'].replace(' ', '_')}"
        risk_folder_path = os.path.join(run_folder, risk_folder_name)
        if not os.path.exists(risk_folder_path):
            os.mkdir(risk_folder_path)
        risk_log_path = os.path.join(risk_folder_path, "log.txt")
        with open(risk_log_path, "a") as f:
            f.write(f"Line {m['line_no']}: {m['line_content']}\n")

    print(f"\nAll outputs saved in folder: {run_folder}")

# -------------------------
# Main
# -------------------------
def main():
    parser = argparse.ArgumentParser(
        description="LogRisk - OS Log Risk Analysis Tool",
        add_help=False  # disable default help to customize
    )

    # Arguments
    parser.add_argument("-L", "--logfile", help="Path to log file to scan")
    parser.add_argument("-O", "--output", default="report.txt", help="Name of text report file")
    parser.add_argument("--json-report", action="store_true", help="Generate JSON report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output in console")
    parser.add_argument("--linux", action="store_true", help="Scan Linux log file")
    parser.add_argument("--w-security", action="store_true", help="Scan Windows Security log")
    parser.add_argument("--w-system", action="store_true", help="Scan Windows System log")
    parser.add_argument("--w-application", action="store_true", help="Scan Windows Application log")
    parser.add_argument("-h", "--help", action="store_true", help="Show commands guide")

    args = parser.parse_args()

    # If no arguments or help requested, show commands guide
    if len(vars(args)) == 0 or args.help or not args.logfile:
        print("\nLogRisk Commands Guide:\n")
        print("Basic Usage:")
        print("  logrisk -L <logfile> [options]\n")
        print("Scan Types (choose one):")
        print("  --linux           : Scan Linux log file")
        print("  --w-security      : Scan Windows Security log")
        print("  --w-system        : Scan Windows System log")
        print("  --w-application   : Scan Windows Application log\n")
        print("Options:")
        print("  -O <filename>     : Name of output text report (default: report.txt)")
        print("  --json-report     : Save JSON report")
        print("  -v                : Verbose output in console")
        print("  -h, --help        : Show this commands guide\n")
        print("Examples:")
        print("  Linux scan:")
        print("    logrisk -L /var/log/auth.log --linux -O linux_report.txt --json-report")
        print("  Windows Security scan:")
        print("    logrisk -L sample_windows_log.txt --w-security -O win_security.txt --json-report")
        print("  Windows System scan:")
        print("    logrisk -L sample_windows_log.txt --w-system -O win_system.txt")
        print("  Windows Application scan:")
        print("    logrisk -L sample_windows_log.txt --w-application -O win_app.txt --json-report\n")
        return

    # Determine scan type and JSON rules
    if args.linux:
        rules_file = "linux_rules.json"
        scan_type = "Linux"
    elif args.w_security:
        rules_file = "windows_security_rules.json"
        scan_type = "Windows-Security"
    elif args.w_system:
        rules_file = "windows_system_rules.json"
        scan_type = "Windows-System"
    elif args.w_application:
        rules_file = "windows_application_rules.json"
        scan_type = "Windows-Application"
    else:
        print("Error: Please specify a scan type (--linux, --w-security, --w-system, --w-application)")
        return

    if not os.path.exists(args.logfile):
        print("Error: Log file does not exist!")
        return
    if not os.path.exists(rules_file):
        print(f"Error: Rules file {rules_file} does not exist!")
        return

    rules = load_risk_rules(rules_file)
    matches = scan_log(args.logfile, rules, verbose=args.verbose)
    run_folder = create_results_folder(scan_type)
    save_reports(matches, args.output, run_folder, args.logfile, json_report=args.json_report)

if __name__ == "__main__":
    main()


