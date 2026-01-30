"""
quick_analyzer_noapi.py

Post-session analyzer for your SSH honeypot that requires NO external API keys.
Reads logs/ssh_audit.csv (CSV written by your honeypot), groups rows by session,
scores behavior, and writes a human-readable report and JSON profile per session.

This version ALWAYS uses a local deterministic augmentation (no network).
"""

import csv
import json
import os
from collections import defaultdict, Counter
from datetime import datetime

CSV_FILE = "ssh_audit.csv"
OUT_REPORT_DIR = "reports"
OUT_PROFILE_DIR = "profiles"

os.makedirs(OUT_REPORT_DIR, exist_ok=True)
os.makedirs(OUT_PROFILE_DIR, exist_ok=True)


# Simple scoring weights (tweak if you want)
WEIGHTS = {
    "RECON": 2,
    "PRIV_ESC": 6,
    "DESTRUCTIVE": 10,
    "TYPOS": 1,
    "MALICIOUS_COMMAND_DETECTED": 8,
    "COMMAND_EXECUTION": 0,
    "UNKNOWN": 0
}

# Useful fallback severity when CSV has no severity column
DEFAULT_SEVERITY = 1


def read_csv(csv_path):
    """
    Read CSV rows into a list of dicts.
    Accepts missing columns gracefully.
    """
    rows = []
    if not os.path.exists(csv_path):
        print(f"[!] CSV not found: {csv_path}")
        return rows

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows


def build_sessions(rows):
    """
    Group rows by session_id. If session_id missing, fallback to client_ip + date.
    Returns dict: session_id -> list(rows)
    """
    sessions = defaultdict(list)
    for r in rows:
        sid = r.get("session_id") or r.get("session") or ""
        if not sid:
            ip = r.get("client_ip") or r.get("client") or r.get("src") or "unknown"
            ts = r.get("timestamp") or r.get("time") or datetime.utcnow().isoformat()
            sid = f"{ip}_{ts.split('T')[0]}"
        sessions[sid].append(r)
    return sessions


def classify_and_score(events):
    """
    events: list of CSV row dicts for a session
    Returns: profile dict with counts, score, inferred intent, skill, confidence
    """
    counts = Counter()
    commands = []
    severity_sum = 0
    event_count = 0

    for e in events:
        event_count += 1
        etype = (e.get("event_type") or e.get("category") or "UNKNOWN").upper()
        counts[etype] += 1

        cmd = (e.get("command") or e.get("details") or "").strip()
        if cmd:
            commands.append(cmd)

        # severity: prefer CSV 'severity' if present, else apply weight
        sev = DEFAULT_SEVERITY
        if e.get("severity"):
            try:
                sev = int(float(e.get("severity")))
            except Exception:
                sev = DEFAULT_SEVERITY
        else:
            sev = WEIGHTS.get(etype, DEFAULT_SEVERITY)
        severity_sum += sev

    # Basic scoring
    score = severity_sum

    # Infer intent
    intent = "Unknown"
    if counts.get("DESTRUCTIVE", 0) > 0 or counts.get("IMMEDIATE_TERMINATION_TRIGGERED", 0) > 0:
        intent = "Destructive (likely trying to damage system)"
    elif counts.get("PRIV_ESC", 0) > 0 or counts.get("SUDO_ATTEMPT", 0) > 0:
        intent = "Privilege escalation attempts"
    elif counts.get("RECON", 0) > 0 or counts.get("MALICIOUS_COMMAND_DETECTED", 0) > 0:
        intent = "Reconnaissance / tool usage"
    elif counts.get("TYPOS", 0) > 0:
        intent = "Low-skill / typos (likely bot or careless user)"

    # Estimate skill
    skill = "Unknown"
    if counts.get("TYPOS", 0) >= 2:
        skill = "Low"
    elif counts.get("PRIV_ESC", 0) and counts.get("RECON", 0):
        skill = "Intermediate to High"
    elif counts.get("DESTRUCTIVE", 0):
        skill = "High"

    # Confidence (scale score to 0-100 simple formula)
    confidence = min(95, int(score * 7))  # conservative cap

    # Build profile
    profile = {
        "first_seen": events[0].get("timestamp") if events else None,
        "event_count": event_count,
        "counts": dict(counts),
        "score": score,
        "intent": intent,
        "skill": skill,
        "confidence": confidence,
        "top_commands": commands[:25],  # first 25 commands for quick view
    }
    return profile


def generate_local_augmentation(profile, session_events):
    """
    Deterministic, local "AI-style" augmentation.
    Produces:
      - short natural-language summary
      - 3 prioritized mitigations / next steps
      - up to 3 evidence strings (IoC-like)
    """
    counts = profile.get("counts", {})
    event_count = profile.get("event_count", 0)
    intent = profile.get("intent", "Unknown")
    confidence = profile.get("confidence", 0)

    # Short summary lines
    summary = []
    summary.append(f"Observed ~{event_count} events. Likely intent: {intent}. Confidence: {confidence}%.")
    top_behaviors = ", ".join(list(counts.keys())[:4]) or "none observed"
    summary.append(f"Top behaviors: {top_behaviors}.")

    # Mitigations (prioritized)
    mitigations = []
    mitigations.append("1) Preserve evidence: copy CSV, JSON profiles and attacker files to an isolated analysis host.")
    if "PRIV_ESC" in counts or "SUDO_ATTEMPT" in counts:
        mitigations.append("2) High priority: block source IP at firewall and rotate any exposed credentials; review sudoers and SSH keys.")
    elif "DESTRUCTIVE" in counts or "IMMEDIATE_TERMINATION_TRIGGERED" in counts:
        mitigations.append("2) Emergency: isolate the host, preserve disk image, notify SOC.")
    else:
        mitigations.append("2) Add detection rules for observed suspicious commands and monitor for repeat connections.")
    mitigations.append("3) Use the command timeline and attacker files to create IoC signatures and tune IDS rules.")

    # IoC / evidence strings
    iocs = []
    # add a few command snippets as evidence
    for s in session_events[:3]:
        snippet = s.replace("\n", " ").strip()
        if snippet:
            iocs.append(f"cmd:{snippet[:120]}")
    # include session first_seen or any IP-like item
    if profile.get("first_seen"):
        iocs.append(f"first_seen:{profile.get('first_seen')}")
    if not iocs:
        iocs = ["none captured"]

    # Build final paragraph
    parts = []
    parts.append("Summary: " + " ".join(summary))
    parts.append("\nMitigations / Next steps:")
    parts.extend(mitigations)
    parts.append("\nEvidence / quick IoCs:")
    for i in iocs:
        parts.append("  - " + i)

    # Keep it compact
    return "\n".join(parts)


def human_report(session_id, client_ip, profile, augmentation_text=None):
    """Return a human-readable text report for the session."""
    lines = []
    lines.append(f"Session: {session_id}")
    lines.append(f"Source IP: {client_ip}")
    lines.append(f"First seen: {profile.get('first_seen')}")
    lines.append(f"Events: {profile.get('event_count')}")
    lines.append(f"Counts: {profile.get('counts')}")
    lines.append(f"Inferred intent: {profile.get('intent')}")
    lines.append(f"Skill estimate: {profile.get('skill')}")
    lines.append(f"Score: {profile.get('score')}  Confidence: {profile.get('confidence')}%")
    lines.append("")
    lines.append("Top observed commands (first 25):")
    for c in profile.get("top_commands", []):
        lines.append(f"  - {c}")
    lines.append("")
    lines.append("Recommended actions:")
    if profile.get("confidence", 0) >= 80 and ("DESTRUCTIVE" in profile.get("counts", {}) or "PRIV_ESC" in profile.get("counts", {})):
        lines.append("  * HIGH: Preserve evidence, block IP, alert SOC.")
    elif profile.get("confidence", 0) >= 50:
        lines.append("  * MEDIUM: Review session, keep evidence, consider blocking.")
    else:
        lines.append("  * LOW: Monitor and tune patterns if false positives observed.")
    if augmentation_text:
        lines.append("\n--- AUGMENTED ANALYST NOTES ---\n")
        lines.append(augmentation_text)
    return "\n".join(lines)


def main():
    rows = read_csv(CSV_FILE)
    if not rows:
        print("[!] No rows found in CSV; exiting.")
        return

    sessions = build_sessions(rows)
    print(f"[+] Found {len(sessions)} sessions in {CSV_FILE}")

    summary = []
    for sid, events in sessions.items():
        # find client ip (best-effort)
        client_ip = events[0].get("client_ip") or events[0].get("client") or "unknown"
        profile = classify_and_score(events)

        # prepare a short list of event strings (commands/details) to include in augmentation
        session_event_cmds = []
        for e in events:
            cmdtxt = (e.get("command") or e.get("details") or "").strip()
            if cmdtxt:
                session_event_cmds.append(cmdtxt)
            if len(session_event_cmds) >= 6:
                break

        # Generate deterministic augmentation (no external API)
        aug_text = generate_local_augmentation(profile, session_event_cmds)

        # save JSON profile (include augmentation)
        profile_out = {
            "session_id": sid,
            "client_ip": client_ip,
            **profile,
            "augmentation": aug_text
        }
        profile_path = os.path.join(OUT_PROFILE_DIR, f"profile_{sid}.json")
        with open(profile_path, "w", encoding="utf-8") as pf:
            json.dump(profile_out, pf, indent=2)

        # save human report (append augmentation)
        report_text = human_report(sid, client_ip, profile, augmentation_text=aug_text)
        report_path = os.path.join(OUT_REPORT_DIR, f"report_{sid}.txt")
        with open(report_path, "w", encoding="utf-8") as rf:
            rf.write(report_text)

        # terminal summary for high-priority items
        if profile.get("confidence", 0) >= 80 and ("DESTRUCTIVE" in profile.get("counts", {}) or "PRIV_ESC" in profile.get("counts", {})):
            print(f"[!!] HIGH priority: {sid} - IP: {client_ip} - confidence={profile.get('confidence')} - score={profile.get('score')}")
            print(f"    report -> {report_path}")
        else:
            summary.append((sid, client_ip, profile.get("confidence")))

    # print short summary of other sessions
    print("\nOther sessions (session_id, client_ip, confidence):")
    for s in sorted(summary, key=lambda x: x[2] or 0, reverse=True)[:30]:
        print("  ", s)

    print(f"\nProfiles saved to: {OUT_PROFILE_DIR}, Reports saved to: {OUT_REPORT_DIR}")


if __name__ == "__main__":
    main()