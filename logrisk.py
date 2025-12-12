#!/usr/bin/env python3
import os
import json
import argparse
import re
from datetime import datetime
import shutil
import subprocess
import sys
import atexit

# Optional readline for command history (Up/Down navigation)
readline = None
history_file = os.path.expanduser("~/.logrisk_history")
try:
    import readline as rl
    readline = rl
except Exception:
    # Try pyreadline on Windows
    try:
        import pyreadline as rl
        readline = rl
    except Exception:
        readline = None

# ============================================================
# Helper Functions (context extraction, reporting, etc.)
# ============================================================

def load_risk_rules(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def create_results_folder(scan_type):
    base_folder = os.path.join("Results_output", scan_type)
    os.makedirs(base_folder, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_folder = os.path.join(base_folder, timestamp)
    os.mkdir(run_folder)
    return run_folder

def predict_risk_level(weight):
    if weight >= 7:
        return "High."
    elif weight >= 4:
        return "Medium."
    return "Low"

def scan_log(log_file, rules, context_lines=5, verbose=False):
    """
    Scan the given log_file for rule patterns.
    Return matches with context_lines before and after each match.
    """
    matches = []
    with open(log_file, 'r', errors='replace', encoding='utf-8') as f:
        lines = f.readlines()

    total_lines = len(lines)
    for i, line in enumerate(lines):
        for rule in rules:
            try:
                if re.search(rule.get('pattern', ''), line):
                    start = max(0, i - context_lines)
                    end = min(total_lines, i + context_lines + 1)  # exclusive
                    context = []
                    for idx in range(start, end):
                        context.append({
                            "line_no": idx + 1,
                            "line": lines[idx].rstrip("\n")
                        })

                    matches.append({
                        "line_no": i + 1,
                        "line_content": line.strip(),
                        "id": rule.get('id'),
                        "risk": rule.get('name'),
                        "weight": rule.get('weight'),
                        "level": predict_risk_level(rule.get('weight', 0)),
                        "suggested_fix": rule.get('suggested_treatment'),
                        "category": rule.get('category'),
                        "context": context
                    })
            except re.error:
                if verbose:
                    print(f"Invalid regex for rule id {rule.get('id')}: {rule.get('pattern')}")
                continue
    return matches

def save_reports(matches, output_name, run_folder, log_file, json_report=False):
    report_path = os.path.join(run_folder, output_name)

    with open(report_path, "w", encoding='utf-8') as f:
        if not matches:
            f.write("No risks found.\n")
        else:
            for m in matches:
                f.write(f"Risk: {m.get('risk')}\n")
                f.write(f"Level: {m.get('level')}\n")
                f.write(f"Fix: {m.get('suggested_fix')}\n")
                f.write(f"Log Line (#{m.get('line_no')}): {m.get('line_content')}\n")
                f.write("Context (5 lines before and after):\n")
                for c in m.get('context', []):
                    prefix = ">>" if c['line_no'] == m.get('line_no') else "  "
                    f.write(f"{prefix} {c['line_no']:5d}: {c['line']}\n")
                f.write("-" * 70 + "\n")

    if json_report:
        json_path = os.path.join(run_folder, "predicted_risks.json")
        with open(json_path, "w", encoding='utf-8') as jf:
            json.dump(matches, jf, indent=4, ensure_ascii=False)

    # Copy the original log file into results folder for auditing
    try:
        shutil.copy(log_file, os.path.join(run_folder, os.path.basename(log_file)))
    except Exception as e:
        print(f"[!] Warning: could not copy log file to results folder: {e}")

# ============================================================
# Interactive Shell (tools interface optional + history)
# ============================================================

class LogRiskShell:
    def __init__(self, show_tools=True):
        self.module = None
        # core options (these are shown by 'show options')
        self.options = {"logfile": None, "json_report": False, "output": "report.txt"}
        self.show_tools = show_tools

        # module -> rules mapping (useful for show options display)
        self.rule_map = {
            "linux": "linux_rules.json",
            "w-security": "windows_security_rules.json",
            "w-system": "windows_system_rules.json",
            "w-application": "windows_application_rules.json"
        }

        # Setup readline history if available
        if readline:
            try:
                # Load history file if present
                if os.path.exists(history_file):
                    readline.read_history_file(history_file)
                readline.set_history_length(1000)
            except Exception:
                # non-fatal; continue without history persistence
                pass

            # Register save on exit
            def _save_hist():
                try:
                    readline.write_history_file(history_file)
                except Exception:
                    pass
            atexit.register(_save_hist)
        else:
            # If readline not available, notify once
            self._readline_missing_warned = False

    def start(self):
        print("\nLogRisk Analyzer Framework v1.0")
        if self.show_tools:
            print("Tip: type 'tools' to list/enter external tools (msfconsole, nmap, etc.).")
        if not readline:
            print("[!] Note: command history (Up/Down arrows) is not available because 'readline' is missing.")
        print("Type 'help' for available commands.\n")

        while True:
            try:
                cmd = input(f"logrisk{f'({self.module})' if self.module else ''} > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting LogRisk...")
                break

            if not cmd:
                continue

            # Add to history explicitly if readline present (usually already added).
            if readline:
                try:
                    readline.add_history(cmd)
                except Exception:
                    pass

            if cmd == "exit":
                print("Exiting LogRisk...")
                break

            elif cmd == "help":
                self.show_help()

            elif cmd == "show options":
                self.show_options()

            elif cmd.startswith("use "):
                self.select_module(cmd.split(" ", 1)[1].strip())

            elif cmd.startswith("set "):
                self.set_option(cmd)

            elif cmd == "run":
                self.run_scan()

            elif cmd == "back":
                self.module = None

            elif cmd == "tools":
                if not self.show_tools:
                    print("Tools interface is hidden. Restart with tools enabled.")
                else:
                    self.show_tools_list()

            elif cmd.startswith("tools "):
                if not self.show_tools:
                    print("Tools interface is hidden. Restart with tools enabled.")
                else:
                    self.handle_tools_command(cmd.split(" ", 1)[1].strip())

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
  show options        Show current options for the selected module (or global options)

Options:
  set logfile <path>        Set log file to scan
  set output <file>         Set report output file name
  set json_report true/false

Actions:
  run                 Run the scan

Tools (if enabled):
  tools               Show available external tools
  tools use <name>    Launch the named tool (if installed), e.g. 'tools use msf'

""")

    # ---------------------------------------------------------
    def show_options(self):
        """
        Display current options and module-specific info.
        """
        print("\n=== Current Options ===")
        print(f"Selected module: {self.module if self.module else '(none)'}")
        # show path to rules file if module selected
        if self.module:
            rules_file = self.rule_map.get(self.module)
            print(f"Rules file: {rules_file if rules_file else '(unknown)'}")
            print("Module-specific options: (none predefined)")
        else:
            print("No module selected. Use 'use <module>' to select one.")
        print("\nGlobal options:")
        for k, v in self.options.items():
            print(f"  {k:12s} : {v}")
        print("=======================\n")

    # ---------------------------------------------------------
    def select_module(self, module_name):
        modules = list(self.rule_map.keys())
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
                value_bool = value.lower() == "true"
                self.options[key] = value_bool
                print(f"{key} set to: {value_bool}")
                return

            self.options[key] = value
            print(f"{key} set to: {value}")

        except ValueError:
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

        rules_file = self.rule_map.get(self.module)
        if not rules_file or not os.path.exists(rules_file):
            print(f"Rules file missing: {rules_file}")
            return

        print(f"[+] Running {self.module} scan...")

        rules = load_risk_rules(rules_file)
        matches = scan_log(logfile, rules, context_lines=5)

        run_folder = create_results_folder(self.module.capitalize())
        save_reports(matches, self.options["output"], run_folder, logfile,
                     json_report=self.options["json_report"])

        print(f"[+] Scan complete. Risks found: {len(matches)}")
        print(f"[+] Report saved: {os.path.join(run_folder, self.options['output'])}")

    # ---------------------------------------------------------
    # Tools interface
    def show_tools_list(self):
        tools = {
            "msf": {"exe": "msfconsole", "desc": "Metasploit Framework console"},
            "nmap": {"exe": "nmap", "desc": "Network mapper"},
            "tcpdump": {"exe": "tcpdump", "desc": "Network packet capture tool"},
            "netcat": {"exe": "nc", "desc": "Netcat (may be 'nc' or 'ncat')"}
        }
        print("Available tools (attempt will be made to run them):")
        for name, info in tools.items():
            print(f"  {name:6} - {info['desc']} (exe: {info['exe']})")
        print("Use: tools use <name>  e.g.  tools use msf")

    def handle_tools_command(self, subcmd):
        if subcmd.startswith("use "):
            tool = subcmd.split(" ", 1)[1].strip()
            self.launch_tool(tool)
        else:
            print("tools subcommand not recognized. Try 'tools use <name>'.")

    def launch_tool(self, tool_name):
        tool_map = {
            "msf": ["msfconsole"],
            "msfconsole": ["msfconsole"],
            "nmap": ["nmap", "-h"],
            "tcpdump": ["tcpdump", "--help"],
            "netcat": ["nc", "-h"]
        }

        cmd = tool_map.get(tool_name)
        if not cmd:
            print(f"Unknown tool: {tool_name}")
            return

        print(f"[+] Attempting to launch: {' '.join(cmd)}")
        try:
            subprocess.call(cmd)
        except FileNotFoundError:
            print(f"[!] Tool not found on PATH: {cmd[0]}")
        except KeyboardInterrupt:
            print("\n[!] Tool interrupted by user.")
        except Exception as e:
            print(f"[!] Failed to launch tool {tool_name}: {e}")

# ============================================================
# Entry Point
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="LogRisk - interactive log risk scanner."
    )
    parser.add_argument("-i", "--ignore-tools", action="store_true",
                        help="Hide tools interface and enter interactive shell directly")
    args = parser.parse_args()

    # Default behavior: start interactive shell.
    shell = LogRiskShell(show_tools=not args.ignore_tools)
    shell.start()

if __name__ == "__main__":
    main()
