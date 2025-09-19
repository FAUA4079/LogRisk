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

def create_results_folder():
    base_folder = "Results_output"
    if not os.path.exists(base_folder):
        os.mkdir(base_folder)
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
    
    # Save JSON report if enabled
    if json_report:
        json_path = os.path.join(run_folder, "predicted_risks.json")
        with open(json_path, "w") as f:
            json.dump(matches, f, indent=4)
    
    # Copy scanned log file
    scanned_log_path = os.path.join(run_folder, os.path.basename(log_file))
    shutil.copy(log_file, scanned_log_path)

    # Save separate log files for each risk type
    risk_folders = {}
    for m in matches:
        risk_folder_name = f"{m['id']}_{m['risk'].replace(' ', '_')}"
        risk_folder_path = os.path.join(run_folder, risk_folder_name)
        if not os.path.exists(risk_folder_path):
            os.mkdir(risk_folder_path)
        # Save the log line into a separate file
        risk_log_path = os.path.join(risk_folder_path, "log.txt")
        with open(risk_log_path, "a") as f:
            f.write(f"Line {m['line_no']}: {m['line_content']}\n")

    print(f"\nAll outputs saved in folder: {run_folder}")
    print(f"Text report: {text_report_path}")
    if json_report:
        print(f"JSON report: {json_path}")
    print(f"Scanned log file copied: {scanned_log_path}")
    print(f"Separate log files for each risk saved in respective folders.")

# -------------------------
# Main
# -------------------------

def main():
    parser = argparse.ArgumentParser(description="LogSentinel - OS Log Risk Analysis Tool")
    parser.add_argument("-L", "--logfile", required=True, help="Path to log file to scan")
    parser.add_argument("-O", "--output", default="report.txt", help="Name of text report file")
    parser.add_argument("--json-report", action="store_true", help="Generate JSON report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output in console")
    parser.add_argument("-R", "--rules", default="declared_risks.json", help="Path to risk rules JSON")
    args = parser.parse_args()

    if not os.path.exists(args.logfile):
        print("Error: Log file does not exist!")
        return
    if not os.path.exists(args.rules):
        print("Error: Risk rules file does not exist!")
        return

    # Load rules
    rules = load_risk_rules(args.rules)

    # Scan logs
    matches = scan_log(args.logfile, rules, verbose=args.verbose)

    # Create results folder
    run_folder = create_results_folder()

    # Save reports and separate risk logs
    save_reports(matches, args.output, run_folder, args.logfile, json_report=args.json_report)

if __name__ == "__main__":
    main()
