#!/usr/bin/env python3
import os
import json
import argparse
import re
from datetime import datetime
import shutil

# ============================================================
# Existing Helper Functions (No Change)
# ============================================================

def load_risk_rules(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def create_results_folder(scan_type):
    base_folder = os.path.join("Results_output", scan_type)
    os.makedirs(base_folder, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_folder = os.path.join(base_folder, timestamp)
    os.mkdir(run_folder)
    return run_folder

def predict_risk_level(weight):
    if weight >= 7: return "High"
    elif weight >= 4: return "Medium"
    return "Low"

def scan_log(log_file, rules, verbose=False):
    matches = []
    with open(log_file, 'r') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        for rule in rules:
            if re.search(rule['pattern'], line):
                matches.append({
                    "line_no": i+1,
                    "line_content": line.strip(),
                    "id": rule['id'],
                    "risk": rule['name'],
                    "weight": rule['weight'],
                    "level": predict_risk_level(rule['weight']),
                    "suggested_fix": rule['suggested_treatment'],
                    "category": rule['category']
                })
    return matches

def save_reports(matches, output_name, run_folder, log_file, json_report=False):
    report_path = os.path.join(run_folder, output_name)

    with open(report_path, "w") as f:
        for m in matches:
            f.write(f"Risk: {m['risk']}\n")
            f.write(f"Level: {m['level']}\n")
            f.write(f"Fix: {m['suggested_fix']}\n")
            f.write(f"Log Line: {m['line_content']}\n")
            f.write("-"*50 + "\n")

    if json_report:
        json_path = os.path.join(run_folder, "predicted_risks.json")
        with open(json_path, "w") as jf:
            json.dump(matches, jf, indent=4)

    shutil.copy(log_file, os.path.join(run_folder, os.path.basename(log_file)))

# ============================================================
# Interactive Shell (Metasploit Style)
# ============================================================

class LogRiskShell:
    def __init__(self):
        self.module = None
        self.options = {"logfile": None, "json_report": False, "output": "report.txt"}

    def start(self):
        print("\nLogRisk Analyzer Framework v1.0")
        print("Type 'help' for available commands.\n")

        while True:
            cmd = input(f"logrisk{f'({self.module})' if self.module else ''} > ").strip()

            if cmd == "exit":
                print("Exiting LogRisk...")
                break

            elif cmd == "help":
                self.show_help()

            elif cmd.startswith("use "):
                self.select_module(cmd.split(" ")[1])

            elif cmd.startswith("set "):
                self.set_option(cmd)

            elif cmd == "run":
                self.run_scan()

            elif cmd == "back":
                self.module = None

            else:
                print("Unknown command. Type 'help' for available commands.")

    # ---------------------------------------------------------
    def show_help(self):
        print("""
Core Commands:
  help                Show this help menu
  exit                Exit the program
  back                Deselect module

Module Commands:
  use linux           Use Linux log scanner
  use w-security      Use Windows Security scanner
  use w-system        Use Windows System scanner
  use w-application   Use Windows Application scanner

Options:
  set logfile <path>        Set log file to scan
  set output <file>         Set report output file name
  set json_report true/false

Actions:
  run                 Run the scan
""")

    # ---------------------------------------------------------
    def select_module(self, module_name):
        modules = ["linux", "w-security", "w-system", "w-application"]
        if module_name not in modules:
            print("Invalid module.")
            return
        self.module = module_name
        print(f"Module selected: {module_name}")

    # ---------------------------------------------------------
    def set_option(self, cmd):
        try:
            _, key, value = cmd.split(" ", 2)
            if key not in self.options:
                print("Invalid option.")
                return

            if key == "json_report":
                value = value.lower() == "true"

            self.options[key] = value
            print(f"{key} set to: {value}")

        except:
            print("Usage: set <option> <value>")

    # ---------------------------------------------------------
    def run_scan(self):
        if not self.module:
            print("No module selected. Use 'use linux' or others.")
            return

        logfile = self.options["logfile"]
        if not logfile or not os.path.exists(logfile):
            print("Error: logfile not set or does not exist.")
            return

        rule_map = {
            "linux": "linux_rules.json",
            "w-security": "windows_security_rules.json",
            "w-system": "windows_system_rules.json",
            "w-application": "windows_application_rules.json"
        }

        rules_file = rule_map[self.module]
        if not os.path.exists(rules_file):
            print(f"Rules file missing: {rules_file}")
            return

        print(f"[+] Running {self.module} scan...")

        rules = load_risk_rules(rules_file)
        matches = scan_log(logfile, rules)

        run_folder = create_results_folder(self.module.capitalize())
        save_reports(matches, self.options["output"], run_folder, logfile,
                     json_report=self.options["json_report"])

        print(f"[+] Scan complete. Risks found: {len(matches)}")
        print(f"[+] Report saved: {os.path.join(run_folder, self.options['output'])}")


# ============================================================
# Entry Point
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interactive", action="store_true")
    args = parser.parse_args()

    if args.interactive:
        shell = LogRiskShell()
        shell.start()
    else:
        print("Run interactive mode using:\n  logrisk --interactive")

if __name__ == "__main__":
    main()
