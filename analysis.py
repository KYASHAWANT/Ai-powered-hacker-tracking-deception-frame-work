import datetime
from collections import Counter

# example severity weights (tweak as needed)
WEIGHTS = {"RECON":2, "PRIV_ESC":6, "DESTRUCTIVE":10, "TYPOS":1}

def analyze_session(events, src_ip=None, geo_info=None, past_history_score=0):
    """
    events: list of dicts: {"timestamp","category","pattern","command","severity"}
    geo_info: optional dict from GeoIP: {"country","asn","provider"}
    returns: (narrative_str, profile_dict)
    """
    # aggregate
    categories = Counter(e["category"] for e in events)
    total_score = sum(e.get("severity", WEIGHTS.get(e["category"],1)) for e in events) + past_history_score

    # determine intent and skill
    intent = "Unknown"
    if categories.get("DESTRUCTIVE"):
        intent = "Destructive - high likelihood of system damage"
    elif categories.get("PRIV_ESC"):
        intent = "Privilege escalation attempt"
    elif categories.get("RECON"):
        intent = "Reconnaissance / scanning"
    else:
        intent = "Low-skill / reconnaissance"

    # skill heuristics
    skill = "unknown"
    if categories.get("TYPOS",0) >= 2:
        skill = "Low-skill (typos; likely automated or careless)"
    elif categories.get("PRIV_ESC") and categories.get("RECON"):
        skill = "Intermediate to advanced (sequenced activity)"
    elif categories.get("DESTRUCTIVE"):
        skill = "Advanced (destructive commands attempted)"
    else:
        skill = "Unknown"

    # confidence (simple sigmoid-ish)
    confidence = min(95, int(total_score * 6))  # scale to 0-95

    # MITRE mapping (very simple)
    mitre = set()
    for e in events:
        c = e["category"]
        if c=="RECON": mitre.add("T1595")   # Active Scanning / Discovery (example)
        if c=="PRIV_ESC": mitre.add("T1053") # Privilege Escalation (placeholder)
        if c=="DESTRUCTIVE": mitre.add("T1485") # Data Destruction (placeholder)

    # narrative
    first_ts = events[0]["timestamp"] if events else datetime.datetime.utcnow().isoformat()
    narrative = (f"Observed session starting {first_ts} from {src_ip or 'unknown'}. "
                 f"Activity summary: {dict(categories)}. Inferred intent: {intent}. "
                 f"Estimated skill: {skill}. Enrichment: {geo_info or 'none'}. "
                 f"Mapped MITRE techniques: {sorted(list(mitre))}. Confidence: {confidence}%.")

    profile = {
        "source_ip": src_ip,
        "first_seen": first_ts,
        "event_count": len(events),
        "categories": dict(categories),
        "score": total_score,
        "intent": intent,
        "skill_estimate": skill,
        "mitre": sorted(list(mitre)),
        "geo": geo_info or {},
        "confidence": confidence,
        "events": events
    }
    return narrative, profile
