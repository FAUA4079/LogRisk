#!/usr/bin/env python3
"""
LogRisk Analyzer - Interactive Metasploit-style CLI with Project flow

Key new commands:
  project <name>     - create / select a project (creates projects/<name>)
  enter              - enter the selected project (switch working context)
  show augment       - show module-specific arguments (augment = arguments)
Other commands:
  use <module>       - choose module (linux, w-security, w-system, w-application)
  set <OPT> <value>  - set option (LOGFILE, OUTPUT, JSON_REPORT, VERBOSE, RULES_FILE)
  load <path>        - shortcut to set LOGFILE
  run                - execute scan
  show options       - display current options
  show modules       - list available modules
  show rules         - list rules in RULES_FILE
  search <term>      - search rules
  showlast           - show last run summary
  exit / quit
"""
import os
import json
import shlex
import cmd
from pathlib import Path
from datetime import datetime
import re
import shutil
import argparse

# -------------------------
# Module -> default rules mapping
# -------------------------
MODULE_MAP = {
    "linux": "rules/linux_rules.json",
    "w-security": "rules/win_security.json",
    "w-system": "rules/win_system.json",
    "w-application": "rules/win_app.json",
}

# -------------------------
# Utility functions (load rules, scan, save reports)
# -------------------------
def load_risk_rules(file_path):
    try:
        with open(file_path, 'r', errors='ignore') as f:
            return json.load(f)
    except Exception:
        return []

def create_results_folder(scan_type, project_dir=None):
    base = Path("Results_output") / (project_dir or "Global") / scan_type
    base.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_folder = base / timestamp
    run_folder.mkdir()
    return str(run_folder)

def predict_risk_level(weight):
    if weight >= 7:
        return "High"
    elif weight >= 4:
        return "Medium"
    return "Low"

def scan_log(log_file, rules, verbose=False):
    matches = []
    try:
        with open(log_file, 'r', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[!] Unable to read log file: {e}")
        return matches

    for i, line in enumerate(lines):
        for rule in rules:
            patt = rule.get('pattern', '')
            try:
                if patt and re.search(patt, line, flags=re.IGNORECASE):
                    weight = rule.get('weight', 1)
                    risk_info = {
                        "line_no": i+1,
                        "line_content": line.strip(),
                        "id": rule.get('id', 'unknown'),
                        "risk": rule.get('name', 'Unnamed Rule'),
                        "weight": weight,
                        "level": predict_risk_level(weight),
                        "suggested_fix": rule.get('suggested_treatment', ''),
                        "category": rule.get('category', '')
                    }
                    matches.append(risk_info)
                    if verbose:
                        print(f"[{risk_info['level']}] {risk_info['risk']} - line {i+1}")
            except re.error:
                # Skip invalid regex, warn once
                print(f"[!] Invalid regex in rule {rule.get('id','?')}: {patt}")
    return matches

def save_reports(matches, output_name, run_folder, log_file, json_report=False):
    # Write main text report
    text_report_path = os.path.join(run_folder, output_name)
    with open(text_report_path, "w") as f:
        f.write(f"LogRisk Analyzer Report - {datetime.now().isoformat()}\n\n")
        for m in matches:
            f.write(f"Risk: {m['risk']}\n")
            f.write(f"Level: {m['level']}\n")
            f.write(f"Fix: {m['suggested_fix']}\n")
            f.write(f"Log Line: {m['line_content']}\n")
            f.write("-"*40 + "\n")

    # JSON
    if json_report:
        json_path = os.path.join(run_folder, "predicted_risks.json")
        with open(json_path, "w") as f:
            json.dump(matches, f, indent=4)

    # Copy scanned log file into run folder
    try:
        shutil.copy(log_file, os.path.join(run_folder, os.path.basename(log_file)))
    except Exception:
        pass

    # Per-risk folders
    for m in matches:
        safe_name = f"{m['id']}_{m['risk'].replace(' ', '_')}"
        rpath = os.path.join(run_folder, safe_name)
        os.makedirs(rpath, exist_ok=True)
        with open(os.path.join(rpath, "log.txt"), "a") as f:
            f.write(f"Line {m['line_no']}: {m['line_content']}\n")

# -------------------------
# Console
# -------------------------
class LogRiskConsole(cmd.Cmd):
    intro = "Welcome to LogRisk Console. Type help or ? to list commands.\n"
    prompt = "LogRisk> "

    def __init__(self):
        super().__init__()
        # session-level options and state
        self.options = {
            "PROJECT": None,        # project name
            "PROJECT_DIR": None,    # projects/<name>
            "MODULE": None,         # linux, w-security, w-system, w-application
            "RULES_FILE": None,
            "LOGFILE": None,
            "OUTPUT": "report.txt",
            "JSON_REPORT": False,
            "VERBOSE": False,
            "LAST_RUN_FOLDER": None,
            "LAST_MATCHES": []
        }

    # ---- Project commands ----
    def do_project(self, arg):
        """project <name>
Create or select a project workspace under projects/<name>"""
        args = shlex.split(arg)
        if not args:
            print("Usage: project <name>")
            return
        name = args[0]
        proj_dir = Path("projects") / name
        proj_dir.mkdir(parents=True, exist_ok=True)
        # write a small metadata file
        meta = {"name": name, "created": datetime.now().isoformat()}
        with open(proj_dir / ".logrisk_meta.json", "w") as f:
            json.dump(meta, f)
        self.options['PROJECT'] = name
        self.options['PROJECT_DIR'] = str(proj_dir)
        print(f"[+] Project '{name}' created/selected at {proj_dir}")

    def do_enter(self, arg):
        """enter
Enter the previously selected project. When entered, shows available scan types."""
        if not self.options.get('PROJECT_DIR'):
            print("No project selected. Use: project <name>")
            return
        # change current working directory to project dir for session
        try:
            os.chdir(self.options['PROJECT_DIR'])
        except Exception:
            pass
        print(f"[+] Entered project: {self.options['PROJECT']} (cwd: {os.getcwd()})\n")
        # auto-show modules and augment (args)
        self.do_show("modules")
        print("")  # separator
        self.do_show("augment")  # show augment when entering

    # ---- show augment (arguments) ----
    def do_show(self, arg):
        """show options | modules | rules | augment
 - show options : show current session options
 - show modules : list available scanning modules
 - show rules   : display rules summary in RULES_FILE
 - show augment : show recommended module arguments (augment)"""
        args = shlex.split(arg)
        if not args or args[0] == "options":
            print("\nCurrent options:")
            for k, v in self.options.items():
                print(f"  {k:14} : {v}")
            print("")
            return

        cmd = args[0]
        if cmd == "modules":
            print("Available modules:")
            for m, rf in MODULE_MAP.items():
                print(f"  {m:15} -> {rf}")
            return

        if cmd == "rules":
            rf = self.options.get("RULES_FILE")
            if not rf or not Path(rf).exists():
                print("No rules file set or file missing. Use 'use <module>' or 'set RULES_FILE <path>'.")
                return
            rules = load_risk_rules(rf)
            print(f"Loaded {len(rules)} rules from {rf}")
            for r in rules[:50]:
                print(f"  {r.get('id','?'):8} {r.get('name','(no name)')}")
            return

        if cmd == "augment":
            # Augment = arguments you should set before running a scan
            print("\nModule Arguments (augment) - recommended options to set before `run`:\n")
            print("Common options for all modules:")
            print("  LOGFILE      - path to the log file to scan (required)")
            print("  OUTPUT       - name of output text report (default: report.txt)")
            print("  JSON_REPORT  - true/false to save JSON (default: false)")
            print("  VERBOSE      - true/false to print matches while scanning")
            print("  RULES_FILE   - explicit path to JSON rules (overrides module defaults)")
            print("\nModule-specific notes:")
            print("  linux         : default rules -> rules/linux_rules.json  (scan auth/kern/cron)")
            print("  w-security    : default rules -> rules/win_security.json")
            print("  w-system      : default rules -> rules/win_system.json")
            print("  w-application : default rules -> rules/win_app.json\n")
            print("Examples:")
            print("  set LOGFILE /var/log/auth.log")
            print("  set OUTPUT linux_report.txt")
            print("  set JSON_REPORT true")
            print("  run\n")
            return

        print("Usage: show options | modules | rules | augment")

    # ---- module selection ----
    def do_use(self, arg):
        """use <module>  -- select scanning module (linux|w-security|w-system|w-application)"""
        args = shlex.split(arg)
        if not args:
            print("Usage: use <module>")
            return
        mod = args[0]
        if mod not in MODULE_MAP:
            print(f"Unknown module '{mod}'. Available: {', '.join(MODULE_MAP.keys())}")
            return
        self.options['MODULE'] = mod
        # prefill RULES_FILE to default module file (user can override)
        self.options['RULES_FILE'] = MODULE_MAP[mod]
        print(f"[+] Module set to '{mod}' (rules: {self.options['RULES_FILE']})")

    # ---- set options ----
    def do_set(self, arg):
        """set <OPTION> <value>"""
        args = shlex.split(arg)
        if len(args) < 2:
            print("Usage: set <OPTION> <value>")
            return
        opt = args[0].upper()
        val = " ".join(args[1:])
        # allow common options
        if opt not in self.options and opt != "RULES_FILE":
            print(f"Unknown option: {opt}")
            return
        if val.lower() in ("true", "false"):
            val = True if val.lower() == "true" else False
        self.options[opt] = val
        print(f"[+] {opt} => {self.options[opt]}")

    # ---- load logfile shortcut ----
    def do_load(self, arg):
        """load <logfile>  - shortcut to set LOGFILE"""
        args = shlex.split(arg)
        if not args:
            print("Usage: load <logfile>")
            return
        path = args[0]
        if not Path(path).exists():
            print(f"File not found: {path}")
            return
        self.options['LOGFILE'] = path
        print(f"[+] LOGFILE => {path}")

    # ---- search rules ----
    def do_search(self, arg):
        """search <term> - search current RULES_FILE for a term"""
        if not arg:
            print("Usage: search <term>")
            return
        rf = self.options.get("RULES_FILE")
        if not rf or not Path(rf).exists():
            print("No valid RULES_FILE set. Use 'use <module>' or 'set RULES_FILE <path>'.")
            return
        rules = load_risk_rules(rf)
        term = arg.lower()
        found = []
        for r in rules:
            combined = " ".join([str(r.get(k,"")).lower() for k in ('id','name','pattern')])
            if term in combined:
                found.append(r)
        if not found:
            print("No matching rules found.")
            return
        print(f"Found {len(found)} matching rules (showing first 50):")
        for r in found[:50]:
            print(f"  {r.get('id','?'):10} {r.get('name','(no name)')}")

    # ---- run scan ----
    def do_run(self, arg):
        """run  - execute scan with currently set options"""
        rf = self.options.get('RULES_FILE')
        lf = self.options.get('LOGFILE')
        if self.options.get('MODULE') and (not rf or not Path(rf).exists()):
            rf = MODULE_MAP.get(self.options['MODULE'])
            self.options['RULES_FILE'] = rf

        if not rf or not Path(rf).exists():
            print("Error: RULES_FILE missing. Use 'use <module>' or 'set RULES_FILE <path>'.")
            return
        if not lf or not Path(lf).exists():
            print("Error: LOGFILE not set or does not exist. Use 'set LOGFILE <path>' or 'load <path>'.")
            return

        print(f"[+] Loading rules from {rf}")
        rules = load_risk_rules(rf)
        print(f"[+] Scanning {lf} ...")
        matches = scan_log(lf, rules, verbose=self.options.get('VERBOSE', False))

        scan_type = self.options.get('MODULE') or "Manual"
        project_dir = self.options.get('PROJECT')
        run_folder = create_results_folder(scan_type, project_dir=project_dir)
        save_reports(matches, self.options.get('OUTPUT', 'report.txt'), run_folder, lf, json_report=self.options.get('JSON_REPORT', False))

        # session store
        self.options['LAST_RUN_FOLDER'] = run_folder
        self.options['LAST_MATCHES'] = matches

        # print summary
        high = sum(1 for m in matches if m['level'] == 'High')
        med = sum(1 for m in matches if m['level'] == 'Medium')
        low = sum(1 for m in matches if m['level'] == 'Low')
        print(f"\nScan Summary: {len(matches)} findings (High={high}, Medium={med}, Low={low})")
        print(f"[✓] Outputs saved in: {run_folder}\n")

    # ---- showlast ----
    def do_showlast(self, arg):
        """showlast - show last run summary and top findings"""
        matches = self.options.get('LAST_MATCHES', [])
        if not matches:
            print("No last run results.")
            return
        print(f"Last run folder: {self.options.get('LAST_RUN_FOLDER')}")
        for m in matches[:20]:
            print(f"[{m['level']}] {m['risk']} (line {m['line_no']}): {m['line_content'][:200]}")
        print(f"... ({len(matches)} total findings)")

    # ---- exit / help ----
    def do_exit(self, arg):
        print("Exiting LogRisk Console.")
        return True
    def do_quit(self, arg):
        return self.do_exit(arg)
    def do_EOF(self, arg):
        print("")
        return self.do_exit(arg)

    def emptyline(self):
        pass

# -------------------------
# Non-interactive compatibility
# -------------------------
def parse_args_and_run():
    parser = argparse.ArgumentParser(description="LogRisk Analyzer")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive console")
    parser.add_argument("--project", help="Project name (optional, auto-create under projects/)")
    parser.add_argument("--linux", action="store_true")
    parser.add_argument("--w-security", action="store_true")
    parser.add_argument("--w-system", action="store_true")
    parser.add_argument("--w-application", action="store_true")
    parser.add_argument("-L", "--logfile", help="Log file to scan")
    parser.add_argument("-O", "--output", default="report.txt", help="Output filename")
    parser.add_argument("--json-report", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--rules-file", help="Explicit rules json file")
    args = parser.parse_args()

    if args.interactive:
        console = LogRiskConsole()
        # pre-create/assign project if supplied
        if args.project:
            console.do_project(args.project)
        console.cmdloop()
        return

    # non-interactive flow - pick module
    if args.project:
        # create project folder
        Path("projects").mkdir(exist_ok=True)
        proj = Path("projects") / args.project
        proj.mkdir(parents=True, exist_ok=True)

    if args.linux or args.w_security or args.w_system or args.w_application:
        # determine module
        if args.linux:
            mod = "linux"
        elif args.w_security:
            mod = "w-security"
        elif args.w_system:
            mod = "w-system"
        else:
            mod = "w-application"

        rules_file = args.rules_file or MODULE_MAP.get(mod)
        if not Path(rules_file).exists():
            print(f"Rules file not found: {rules_file}")
            return
        if not args.logfile or not Path(args.logfile).exists():
            print("Logfile missing or does not exist. Use -L <logfile>")
            return

        rules = load_risk_rules(rules_file)
        matches = scan_log(args.logfile, rules, verbose=args.verbose)
        run_folder = create_results_folder(mod, project_dir=args.project)
        save_reports(matches, args.output, run_folder, args.logfile, json_report=args.json_report)
        print(f"Scan complete. Outputs in: {run_folder}")
        return

    parser.print_help()

if __name__ == "__main__":
    parse_args_and_run()
