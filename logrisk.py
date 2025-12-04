#!/usr/bin/env python3

import argparse
import json
import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
import sys
from math import ceil

# JSON helpers

def load_json_file(path, default=None):
    """
    Load JSON from Path or string. If missing or parse error, return default.
    """
    if default is None:
        default = []
    try:
        p = Path(path)
    except Exception:
        p = Path(str(path))
    if p.exists():
        try:
            with p.open('r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logging.warning("Failed to load JSON %s: %s", p, e)
            return default
    else:
        return default

def save_json_file(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# Default sample data (used only if controls files missing)

SAMPLE_CONTROLS = [
    {
        "control_id": "CTRL-AC-001",
        "name": "Ensure least privilege for root/administrators",
        "objective": "Prevent unauthorized privilege escalation",
        "owner": "IT Admin",
        "implementation": "Log monitoring for sudo/su and root logins; periodic review of admin group",
        "implementation_evidence": [],
        "status": "Not Implemented",
        "automation": "Partial",
        "control_effectiveness": 3,
        "asset_tag": "servers",
        "asset_value": 5
    },
    {
        "control_id": "CTRL-AUTH-002",
        "name": "MFA for privileged access",
        "objective": "Require multi-factor authentication for privileged accounts",
        "owner": "IAM Team",
        "implementation": "Enforce MFA via IAM policies",
        "implementation_evidence": [],
        "status": "Implemented",
        "automation": "Full",
        "control_effectiveness": 4,
        "asset_tag": "users",
        "asset_value": 3
    }
]

SAMPLE_HYBRID_MAPPING = [
    {"control_id": "CTRL-AC-001", "iso": "A.9", "nist": "PR.AC-1", "cis": "CIS 5"},
    {"control_id": "CTRL-AUTH-002", "iso": "A.9", "nist": "PR.AC-3", "cis": "CIS 6"}
]

# Optional legacy-level loads (if users want to import these at module import time)
CONTROLS_LIBRARY = load_json_file('controls_library.json', SAMPLE_CONTROLS)
HYBRID_MAPPING = load_json_file('hybrid_mapping.json', SAMPLE_HYBRID_MAPPING)

# Utilities

def safe_name(value: str) -> str:
    """Return a filesystem-safe short name for folder names."""
    s = str(value or "")
    # replace problematic characters, limit length
    for ch in ('/', '\\', ':', '*', '?', '"', '<', '>', '|'):
        s = s.replace(ch, '_')
    s = s.replace(' ', '_')
    return s[:80]

def iso_now():
    """Return timezone-aware ISO timestamp."""
    return datetime.now(timezone.utc).astimezone().isoformat()

# Rule compilation and scanning

def compile_rules(rules, ignore_case=False):
    compiled = []
    flags = re.MULTILINE
    if ignore_case:
        flags |= re.IGNORECASE
    for r in rules:
        patt = r.get('pattern', '')
        try:
            cre = re.compile(patt, flags)
        except re.error as e:
            logging.warning("Invalid regex for rule %s: %s. Skipping.", r.get('id'), e)
            continue
        r_copy = dict(r)
        r_copy['_compiled'] = cre
        compiled.append(r_copy)
    return compiled

def scan_log_stream(log_file: Path, compiled_rules, verbose=False, context=0):
    matches = []
    if context > 0:
        from collections import deque
        prev_lines = deque(maxlen=context)
    with log_file.open('r', encoding='utf-8', errors='replace') as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip('\n')
            if context > 0:
                matched = False
                for rule in compiled_rules:
                    if rule['_compiled'].search(line):
                        # capture context
                        snippet = {
                            'before': list(prev_lines),
                            'match_line': line,
                            'after': []
                        }
                        after = []
                        for _ in range(context):
                            nxt = f.readline()
                            if not nxt:
                                break
                            lineno += 1
                            after.append(nxt.rstrip('\n'))
                        snippet['after'] = after
                        match = {
                            'line_no': lineno - len(after),
                            'line_content': line,
                            'id': rule.get('id', ''),
                            'risk': rule.get('name', ''),
                            'weight': rule.get('weight', 0),
                            'level': predict_risk_level(rule.get('weight', 0)),
                            'suggested_fix': rule.get('suggested_treatment', ''),
                            'category': rule.get('category', ''),
                            'rule': rule,
                            'context': snippet
                        }
                        matches.append(match)
                        if verbose:
                            logging.info("[%s] %s - line %d", match['level'], match['risk'], match['line_no'])
                        prev_lines.clear()
                        matched = True
                        break
                if not matched:
                    prev_lines.append(line)
            else:
                for rule in compiled_rules:
                    if rule['_compiled'].search(line):
                        match = {
                            'line_no': lineno,
                            'line_content': line,
                            'id': rule.get('id', ''),
                            'risk': rule.get('name', ''),
                            'weight': rule.get('weight', 0),
                            'level': predict_risk_level(rule.get('weight', 0)),
                            'suggested_fix': rule.get('suggested_treatment', ''),
                            'category': rule.get('category', ''),
                            'rule': rule
                        }
                        matches.append(match)
                        if verbose:
                            logging.info("[%s] %s - line %d", match['level'], match['risk'], match['line_no'])
                        break
    return matches

# Risk & control functions

def predict_risk_level(weight):
    try:
        w = int(weight)
    except Exception:
        w = 0
    if w >= 7:
        return 'High'
    if w >= 4:
        return 'Medium'
    return 'Low'

def find_control_for_rule(rule, controls, hybrid_map):
    # 1) direct mapping by control_id in rule
    if rule.get('control_id'):
        for c in controls:
            if c.get('control_id') == rule.get('control_id'):
                return c
    # 2) hybrid mapping lookup
    for entry in hybrid_map:
        cid = entry.get('control_id')
        for c in controls:
            if c.get('control_id') == cid:
                # quick heuristics
                if rule.get('category') and rule.get('category').lower() in (c.get('name','') or '').lower():
                    return c
                if any(tok.lower() in (c.get('name','') or '').lower() for tok in (rule.get('name','') or '').split()):
                    return c
    # 3) match by asset_tag
    for c in controls:
        if c.get('asset_tag') and c.get('asset_tag') == rule.get('category'):
            return c
    return None

def compute_risk_score_for_match(match, control):
    try:
        weight = int(match.get('weight', 0))
    except Exception:
        weight = 0
    threat_likelihood = max(1, min(5, ceil(weight / 2)))
    asset_value = 3
    control_effectiveness = 3
    if control:
        try:
            asset_value = int(control.get('asset_value', asset_value))
        except Exception:
            asset_value = asset_value
        try:
            control_effectiveness = int(control.get('control_effectiveness', control_effectiveness))
        except Exception:
            control_effectiveness = control_effectiveness
    effectiveness_inverse = max(1, 6 - control_effectiveness)
    risk_score = asset_value * threat_likelihood * effectiveness_inverse
    return risk_score

def update_controls_with_matches(controls, matches, hybrid_map, run_folder: Path):
    for m in matches:
        rule = m.get('rule', {})
        control = find_control_for_rule(rule, controls, hybrid_map)
        if control is None:
            new_id = f"AUTO-{rule.get('id','UNKWN')}"
            control = {
                'control_id': new_id,
                'name': f"Auto-created for {rule.get('name')}",
                'objective': 'Auto-generated control',
                'owner': 'UNKNOWN',
                'implementation_evidence': [],
                'status': 'Partial',
                'automation': 'None',
                'control_effectiveness': 2,
                'asset_tag': rule.get('category','uncategorized'),
                'asset_value': 2
            }
            controls.append(control)
        evidence = {
            'detected_at': iso_now(),
            'log_line_no': m.get('line_no'),
            'log_snippet': m.get('line_content'),
            'rule_id': rule.get('id')
        }
        control.setdefault('implementation_evidence', []).append(evidence)
        if control.get('status') == 'Not Implemented':
            control['status'] = 'Partial'
        safe = safe_name(f"{control.get('control_id')}_{control.get('name')}")
        folder = run_folder / safe
        folder.mkdir(parents=True, exist_ok=True)
        with (folder / 'evidence.json').open('a', encoding='utf-8') as f:
            f.write(json.dumps(evidence, ensure_ascii=False) + '\n')
    return controls

def save_controls_status(controls, run_folder: Path):
    save_json_file(run_folder / 'controls_status.json', controls)

# Reporting

def save_reports(matches, output_name: str, run_folder: Path, log_file: Path, json_report=False):
    # ensure run folder exists
    run_folder.mkdir(parents=True, exist_ok=True)

    # text report
    text_path = run_folder / output_name
    with text_path.open('w', encoding='utf-8') as f:
        if not matches:
            f.write('No risks detected.\n')
        for m in matches:
            f.write(f"Risk: {m.get('risk')}\n")
            f.write(f"ID: {m.get('id')}\n")
            f.write(f"Level: {m.get('level')}\n")
            f.write(f"Fix: {m.get('suggested_fix')}\n")
            f.write(f"Line ({m.get('line_no')}): {m.get('line_content')}\n")
            if 'context' in m:
                f.write('Context (before):\n')
                for ln in m['context']['before']:
                    f.write(f"  {ln}\n")
                f.write('Matched line:\n')
                f.write(f"  {m['context']['match_line']}\n")
                if m['context']['after']:
                    f.write('Context (after):\n')
                    for ln in m['context']['after']:
                        f.write(f"  {ln}\n")
            f.write('-' * 50 + '\n')

    # json report
    if json_report:
        json_path = run_folder / 'predicted_risks.json'
        with json_path.open('w', encoding='utf-8') as f:
            json.dump({
                'generated_at': iso_now(),
                'log_file': str(log_file),
                'num_matches': len(matches),
                'matches': matches
            }, f, ensure_ascii=False, indent=2)

    # copy original log file
    try:
        shutil.copy(log_file, run_folder / log_file.name)
    except Exception:
        logging.warning("Failed to copy log file to run folder")

    logging.info("All outputs saved in folder: %s", run_folder)

# Create timestamp folder

def create_results_folder(base_dir: Path, scan_type: str):
    base_folder = base_dir / scan_type
    base_folder.mkdir(parents=True, exist_ok=True)
    # timestamp safe for filenames (no colons)
    timestamp = datetime.now().strftime("%Y-%m-%d_T%H-%M-%S")
    run_folder = base_folder / timestamp
    # ensure unique run folder; fail if exists to avoid accidental overwrite
    run_folder.mkdir(parents=True, exist_ok=False)
    return run_folder

# Main

def main(argv=None):
    parser = argparse.ArgumentParser(description='LogRisk - OS Log Risk Analysis Tool (timestamped folders)')
    parser.add_argument('-L','--logfile',required=True,help='Path to log file to scan')
    parser.add_argument('-O','--output-name',default='report.txt',help='Name of text report file')
    parser.add_argument('--output-dir',default='Results',help='Base directory for results')
    parser.add_argument('--json-report',action='store_true',help='Generate JSON report')
    parser.add_argument('-v','--verbose',action='store_true',help='Verbose output (info)')
    parser.add_argument('--context',type=int,default=0,help='Number of context lines before/after a match')
    parser.add_argument('--ignore-case',action='store_true',help='Case-insensitive matching')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--linux',action='store_true',help='Scan Linux log file')
    group.add_argument('--w-security',action='store_true',help='Scan Windows Security log')
    group.add_argument('--w-system',action='store_true',help='Scan Windows System log')
    group.add_argument('--w-application',action='store_true',help='Scan Windows Application log')
    parser.add_argument('--rules-file',default=None,help='Optional JSON rules file')
    parser.add_argument('--enable-grc',action='store_true',help='Enable GRC integration')
    parser.add_argument('--controls-dir',default='grc',help='Directory to store controls & mapping')
    args = parser.parse_args(argv)

    level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(format='%(levelname)s: %(message)s', level=level)

    log_path = Path(args.logfile)
    if not log_path.exists():
        logging.error('Log file does not exist: %s', log_path)
        sys.exit(2)

    # Determine rules file
    if args.rules_file:
        rules_file = Path(args.rules_file)
    else:
        if args.linux:
            rules_file = Path('linux_rules.json')
        elif args.w_security:
            rules_file = Path('windows_security_rules.json')
        elif args.w_system:
            rules_file = Path('windows_system_rules.json')
        elif args.w_application:
            rules_file = Path('windows_application_rules.json')
        else:
            rules_file = Path('linux_rules.json')

    if not rules_file.exists():
        logging.error('Rules file not found: %s', rules_file)
        sys.exit(3)

    rules = load_json_file(rules_file, default=[])
    compiled_rules = compile_rules(rules, ignore_case=args.ignore_case)
    if not compiled_rules:
        logging.error('No valid rules compiled. Exiting.')
        sys.exit(4)

    scan_type = ('Linux' if args.linux else
                 'Windows-Security' if args.w_security else
                 'Windows-System' if args.w_system else
                 'Windows-Application' if args.w_application else 'Generic')

    base_out_dir = Path(args.output_dir)
    try:
        run_folder = create_results_folder(base_out_dir, scan_type)
    except FileExistsError:
        # extremely unlikely because timestamp includes seconds; but handle gracefully
        logging.warning("Run folder collision detected; creating a unique fallback.")
        run_folder = base_out_dir / scan_type / (datetime.now().strftime("%Y-%m-%d_T%H-%M-%S_%f"))
        run_folder.mkdir(parents=True, exist_ok=True)

    logging.info('Starting scan of %s using rules from %s', log_path, rules_file)
    matches = scan_log_stream(log_path, compiled_rules, verbose=args.verbose, context=args.context)

    # GRC integration
    controls = []
    hybrid_map = []
    if args.enable_grc:
        controls_dir = Path(args.controls_dir)
        controls_dir.mkdir(parents=True, exist_ok=True)
        controls_file = controls_dir / 'controls_library.json'
        mapping_file = controls_dir / 'hybrid_mapping.json'
        # fallback to root-level files if present
        if not controls_file.exists() and Path('controls_library.json').exists():
            controls_file = Path('controls_library.json')
        if not mapping_file.exists() and Path('hybrid_mapping.json').exists():
            mapping_file = Path('hybrid_mapping.json')
        # create samples in controls_dir if missing
        if not controls_file.exists():
            save_json_file(controls_dir / 'controls_library.json', SAMPLE_CONTROLS)
            controls_file = controls_dir / 'controls_library.json'
        if not mapping_file.exists():
            save_json_file(controls_dir / 'hybrid_mapping.json', SAMPLE_HYBRID_MAPPING)
            mapping_file = controls_dir / 'hybrid_mapping.json'
        controls = load_json_file(controls_file, default=SAMPLE_CONTROLS)
        hybrid_map = load_json_file(mapping_file, default=SAMPLE_HYBRID_MAPPING)
        logging.info("Loaded %d controls and %d hybrid mappings", len(controls), len(hybrid_map))

        # attach matches to controls and write evidence
        controls = update_controls_with_matches(controls, matches, hybrid_map, run_folder)

        # compute risk scores and add control_id in matches
        for m in matches:
            ctrl = find_control_for_rule(m.get('rule', {}), controls, hybrid_map)
            m['risk_score'] = compute_risk_score_for_match(m, ctrl)
            if ctrl:
                m['control_id'] = ctrl.get('control_id')

        # persist controls status and CSV summary
        save_controls_status(controls, run_folder)
        summary_csv = run_folder / 'risk_summary.csv'
        with summary_csv.open('w', encoding='utf-8') as f:
            f.write('control_id,match_id,risk,level,risk_score,line_no\n')
            for m in matches:
                f.write(f"{m.get('control_id','')},{m.get('id')},{m.get('risk')},{m.get('level')},{m.get('risk_score',0)},{m.get('line_no')}\n")

    # Save reports and copy log
    save_reports(matches, args.output_name, run_folder, log_path, json_report=args.json_report)

    print(f"Hello Fuad Hasan sir — Results saved in: {run_folder}")
    if args.enable_grc:
        print(f"Controls status: {run_folder / 'controls_status.json'}")
        print(f"Risk summary CSV: {run_folder / 'risk_summary.csv'}")

if __name__ == '__main__':
    main()
