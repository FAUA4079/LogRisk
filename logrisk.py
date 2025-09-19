#!/usr/bin/env python3
# logrisk - complete OS Log Risk Analysis CLI
# Save as 'logrisk', chmod +x logrisk
# Python 3.8+

import argparse, json, os, re, sys
from collections import defaultdict, Counter
from datetime import datetime

# ----------------- Defaults -----------------
DEFAULT_CONFIG = "declared_risks.json"
PERSIST_DATA = "oslog_declared_data.json"
DEFAULT_JSON_REPORT = "predicted_risks.json"

CATEGORY_REMEDIATION = {
    "authentication": [
        "Review auth logs for this entity and related IPs.",
        "Enforce MFA and consider password resets if compromise suspected.",
        "Throttle or block repeated failed login IPs (fail2ban/iptables)."
    ],
    "privilege-escalation": [
        "Isolate host for forensic capture, preserve logs, collect snapshots.",
        "Rotate privileged credentials and revoke unauthorized keys."
    ],
    "authorization": [
        "Audit sudoers and recent privilege changes; apply least-privilege."
    ],
    "persistence": [
        "Audit cron/systemd timers and startup scripts; remove unexpected binaries."
    ],
    "network": [
        "Block or rate-limit suspicious IPs at firewall; check for lateral movement."
    ],
    "default": [
        "Investigate raw lines and correlate with other logs; tune rules to reduce noise."
    ]
}

# ----------------- Helpers -----------------
def banner():
    print("=== LogRisk CLI ===")
    print("Scan OS logs using declared risk rules, produce predicted_risks.json and a text report.")
    print("Usage example: logrisk -L /var/log/auth.log -O report.txt -C declared_risks.json\n")

def load_config(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Risk config not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    for idx, r in enumerate(cfg):
        patt = r.get("pattern", "")
        r["_compiled"] = re.compile(patt, re.IGNORECASE)
        r.setdefault("id", f"R{idx+1:03d}")
        r.setdefault("name", r.get("id"))
        r.setdefault("weight", 1)
        r.setdefault("suggested_treatment", "")
        r.setdefault("category", "default")
    return cfg

def load_persist():
    if os.path.exists(PERSIST_DATA):
        with open(PERSIST_DATA, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"events": [], "meta": {}}

def save_persist(d):
    with open(PERSIST_DATA, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)

def scan_log(path, cfg, verbose=False):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Log file not found: {path}")
    data = load_persist()
    events = data.get("events", [])
    matches = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for ln in fh:
            line = ln.rstrip("\n")
            for rule in cfg:
                m = rule["_compiled"].search(line)
                if not m:
                    continue
                gd = m.groupdict() if m.groupdict() else {}
                event = {
                    "detected_at": datetime.utcnow().isoformat() + "Z",
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "raw": line,
                    "user": gd.get("user","") or "",
                    "ip": gd.get("ip","") or "",
                    "service": gd.get("service","") or "",
                    "weight": int(rule.get("weight",1)),
                    "category": rule.get("category","default"),
                    "suggested_treatment": rule.get("suggested_treatment","")
                }
                events.append(event)
                matches += 1
                if verbose:
                    print(f"[MATCH] {rule['id']} user={event['user']} ip={event['ip']}  line={line[:140]}")
                # allow multiple rule matches per line
    data["events"] = events
    data["meta"]["last_scan"] = datetime.utcnow().isoformat() + "Z"
    save_persist(data)
    return matches

def analyze_events(verbose=False):
    data = load_persist()
    events = data.get("events", [])
    if not events:
        return None
    by_ip = defaultdict(list)
    by_user = defaultdict(list)
    for e in events:
        ip = e.get("ip") or "unknown"
        user = e.get("user") or "unknown"
        by_ip[ip].append(e)
        by_user[user].append(e)
    def compute(evs):
        total = sum(int(e.get("weight",1)) for e in evs)
        rule_counts = Counter(e["rule_id"] for e in evs)
        rule_names = Counter(e["rule_name"] for e in evs)
        categories = Counter(e.get("category","default") for e in evs)
        return int(total), dict(rule_counts), dict(rule_names), dict(categories)
    ip_scores = { ip: {"score": compute(evs)[0], "rule_counts": compute(evs)[1], "rule_names": compute(evs)[2], "categories": compute(evs)[3], "events": len(evs)} for ip,evs in by_ip.items() }
    user_scores = { u: {"score": compute(evs)[0], "rule_counts": compute(evs)[1], "rule_names": compute(evs)[2], "categories": compute(evs)[3], "events": len(evs)} for u,evs in by_user.items() }
    analysis = {"by_ip": ip_scores, "by_user": user_scores, "generated_at": datetime.utcnow().isoformat() + "Z"}
    data["analysis"] = analysis
    save_persist(data)
    if verbose:
        print(f"[ANALYSIS] IPs={len(ip_scores)} users={len(user_scores)} events_total={len(events)}")
    return analysis

def level_from_score(score):
    if score <= 4: return "Low"
    if score <= 10: return "Medium"
    return "High"

def build_remediation(rule_ids, cfg):
    combined = []
    categories_seen = set()
    rule_map = {r["id"]: r for r in cfg}
    for rid in rule_ids:
        r = rule_map.get(rid)
        if not r: continue
        st = r.get("suggested_treatment","")
        if st and st not in combined: combined.append(st)
        categories_seen.add(r.get("category","default"))
    for cat in categories_seen:
        for step in CATEGORY_REMEDIATION.get(cat, CATEGORY_REMEDIATION["default"]):
            if step not in combined:
                combined.append(step)
    final = "Document findings for audit and tune declared rules to reduce false positives."
    if final not in combined: combined.append(final)
    return combined

def generate_json_report(analysis, cfg, outpath=DEFAULT_JSON_REPORT):
    report = {"generated_at": datetime.utcnow().isoformat() + "Z", "entities": {"by_ip": {}, "by_user": {}}, "meta": {"source": PERSIST_DATA}}
    for ip, info in analysis.get("by_ip", {}).items():
        score = info.get("score", 0)
        level = level_from_score(score)
        remediation = build_remediation(list(info.get("rule_counts", {}).keys()), cfg)
        report["entities"]["by_ip"][ip] = {
            "score": score, "level": level, "events": info.get("events",0),
            "rule_counts": info.get("rule_counts",{}), "rule_names": info.get("rule_names",{}),
            "categories": info.get("categories",{}), "remediation": remediation,
            "suggested_actions": [
                f"Block/throttle IP {ip} at firewall if level is High.",
                f"Search prior logs for {ip} across systems for correlation."
            ] if level=="High" else [f"Monitor IP {ip} and escalate if events increase."]
        }
    for u, info in analysis.get("by_user", {}).items():
        score = info.get("score", 0)
        level = level_from_score(score)
        remediation = build_remediation(list(info.get("rule_counts", {}).keys()), cfg)
        report["entities"]["by_user"][u] = {
            "score": score, "level": level, "events": info.get("events",0),
            "rule_counts": info.get("rule_counts",{}), "rule_names": info.get("rule_names",{}),
            "categories": info.get("categories",{}), "remediation": remediation,
            "suggested_actions": [
                f"Force password reset for user {u} if level is High.",
                f"Review recent sessions and sudo activity for user {u}."
            ] if level=="High" else [f"Notify user {u} and monitor for repeat events."]
        }
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return outpath

def write_text_report(json_report_path, text_out_path):
    with open(json_report_path, "r", encoding="utf-8") as f:
        rep = json.load(f)
    lines = []
    lines.append("=== LogRisk Predicted Risks Report ===")
    lines.append(f"Generated at: {rep.get('generated_at')}")
    lines.append("")
    by_ip = rep.get("entities", {}).get("by_ip", {})
    by_user = rep.get("entities", {}).get("by_user", {})
    lines.append("== Top IPs ==")
    if not by_ip:
        lines.append("No IP entries found.")
    else:
        for ip, info in sorted(by_ip.items(), key=lambda kv: kv[1]["score"], reverse=True)[:50]:
            lines.append(f"IP: {ip}")
            lines.append(f"  Score: {info['score']}  Level: {info['level']}  Events: {info['events']}")
            lines.append(f"  Rule counts: {info.get('rule_counts')}")
            lines.append("  Remediation:")
            for r in info.get("remediation", []):
                lines.append(f"    - {r}")
            lines.append("  Suggested actions:")
            for a in info.get("suggested_actions", []):
                lines.append(f"    - {a}")
            lines.append("")
    lines.append("== Top Users ==")
    if not by_user:
        lines.append("No user entries found.")
    else:
        for u, info in sorted(by_user.items(), key=lambda kv: kv[1]["score"], reverse=True)[:50]:
            lines.append(f"User: {u}")
            lines.append(f"  Score: {info['score']}  Level: {info['level']}  Events: {info['events']}")
            lines.append(f"  Rule counts: {info.get('rule_counts')}")
            lines.append("  Remediation:")
            for r in info.get("remediation", []):
                lines.append(f"    - {r}")
            lines.append("  Suggested actions:")
            for a in info.get("suggested_actions", []):
                lines.append(f"    - {a}")
            lines.append("")
    with open(text_out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return text_out_path

# ----------------- CLI -----------------
def main():
    parser = argparse.ArgumentParser(prog="logrisk", description="OS Log Risk Analysis Tool")
    parser.add_argument("-L", "--logfile", required=False, help="Path to the log file to analyze")
    parser.add_argument("-O", "--output", default="risk_report.txt", help="Human-readable output report path")
    parser.add_argument("-C", "--config", default=DEFAULT_CONFIG, help="Declared risks JSON config (default: declared_risks.json)")
    parser.add_argument("--json-report", default=DEFAULT_JSON_REPORT, help="Machine JSON report output (default: predicted_risks.json)")
    parser.add_argument("--skip-scan", action="store_true", help="Skip scanning (use existing persisted data)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    # If user ran without args (just 'logrisk'), show banner + help
    if len(sys.argv) == 1:
        banner()
        parser.print_help()
        return

    if not args.logfile and not args.skip_scan:
        print("[!] When not using --skip-scan you must provide -L / --logfile")
        return

    try:
        cfg = load_config(args.config)
    except Exception as e:
        print(f"[!] ERROR loading config: {e}")
        return

    try:
        if not args.skip_scan:
            if args.verbose: print("[*] Scanning log file for declared risk patterns...")
            matches = scan_log(args.logfile, cfg, verbose=args.verbose)
            print(f"[+] Scan complete — matched events: {matches}")
        else:
            if args.verbose: print("[*] Using existing persisted events (skip scan).")
        if args.verbose: print("[*] Analyzing events and computing scores...")
        analysis = analyze_events(verbose=args.verbose)
        if not analysis:
            print("[!] No events found. Exiting.")
            return
        print("[+] Analysis complete.")
        if args.verbose: print("[*] Generating JSON report...")
        json_path = generate_json_report(analysis, cfg, outpath=args.json_report)
        print(f"[+] JSON report saved to: {json_path}")
        if args.verbose: print("[*] Writing human-readable report...")
        text_path = write_text_report(json_path, args.output)
        print(f"[+] Text report saved to: {text_path}")
        # short terminal summary
        print("\n=== Executive Summary (top 5 by IP) ===")
        by_ip = analysis.get("by_ip", {})
        top_ips = sorted(by_ip.items(), key=lambda kv: kv[1]["score"], reverse=True)[:5]
        if not top_ips:
            print("No IPs detected.")
        else:
            for ip, info in top_ips:
                lvl = level_from_score(info.get("score", 0))
                print(f"- {ip}: score={info['score']} level={lvl} events={info.get('events')}")
        print("\nDone. Review the report and remediation steps.")
    except Exception as exc:
        print(f"[!] Unexpected error: {exc}")

if __name__ == "__main__":
    main()
