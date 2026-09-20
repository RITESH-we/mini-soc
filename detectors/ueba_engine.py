import json
from datetime import datetime, timedelta
from database.models import get_conn

# Risk point weighting matrix (aligned with MITRE ATT&CK & UEBA benchmarks)
RISK_RULES = {
    # Top 5 Critical Attack Use Cases
    "Ransomware Recovery Inhibition": {"points": 50, "category": "Impact / Ransomware"},
    "Shadow Copy": {"points": 50, "category": "Impact / Ransomware"},
    "In-Memory Credential Dumping": {"points": 45, "category": "Credential Access"},
    "Credential Access": {"points": 40, "category": "Credential Access"},
    "Pass the Hash": {"points": 45, "category": "Lateral Movement"},
    "Explicit Credentials": {"points": 45, "category": "Lateral Movement"},
    "Obfuscated PowerShell": {"points": 40, "category": "Living-off-the-Land"},
    "Living-off-the-Land": {"points": 40, "category": "Living-off-the-Land"},
    "Data Staging": {"points": 40, "category": "Collection / Exfiltration"},
    "Malicious C2 Communication": {"points": 45, "category": "Command and Control"},
    "Anomalous Outbound": {"points": 35, "category": "Command and Control"},
    "Windows Audit Log Cleared": {"points": 50, "category": "Defense Tampering"},
    "Scheduled Task Created": {"points": 35, "category": "Persistence"},
    "System Service Installed": {"points": 40, "category": "Persistence"},
    "Member Added to Security Group": {"points": 40, "category": "Privilege Escalation"},
    "User Account Created": {"points": 30, "category": "Persistence"},
    "Suspicious Tool on Remote Endpoint": {"points": 40, "category": "Execution Anomaly"},
    # Baseline rules
    "Failed Logon": {"points": 15, "category": "Authentication Anomaly"},
    "Brute Force Attempt": {"points": 35, "category": "Credential Access"},
    "Suspicious Process Creation": {"points": 35, "category": "Execution Anomaly"},
    "Port Scan Activity": {"points": 25, "category": "Discovery"},
    "Host Isolated": {"points": 10, "category": "Containment Event"}
}

def calculate_entity_risk(entity_id: str, entity_type: str = "HOST") -> dict:
    """
    Computes current risk score (0-100) for a given Host or User based on recent 24-hour activity.
    """
    conn = get_conn()
    since = (datetime.now() - timedelta(hours=24)).isoformat()
    
    # Query recent alerts associated with this entity
    if entity_type.upper() == "HOST":
        alerts = conn.execute("""
            SELECT rule_name, severity, timestamp, mitre_technique
            FROM alerts
            WHERE device_name = ? AND timestamp >= ?
        """, (entity_id, since)).fetchall()
    else:
        alerts = conn.execute("""
            SELECT rule_name, severity, timestamp, mitre_technique
            FROM alerts
            WHERE src_user = ? AND timestamp >= ?
        """, (entity_id, since)).fetchall()
        
    score = 0
    factors = []
    
    # Base scoring on alerts
    for a in alerts:
        rname = a["rule_name"]
        rule_meta = None
        for k, v in RISK_RULES.items():
            if k.lower() in rname.lower():
                rule_meta = v
                break
                
        if rule_meta:
            pts = rule_meta["points"]
            cat = rule_meta["category"]
        else:
            sev = a["severity"]
            pts = 30 if sev == "CRITICAL" else (20 if sev == "HIGH" else (10 if sev == "MEDIUM" else 5))
            cat = "General Anomaly"
            
        score += pts
        factors.append({
            "rule": rname,
            "points": pts,
            "category": cat,
            "time": a["timestamp"]
        })
        
    # Cap score at 100
    score = min(100, score)
    
    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"
        
    now_iso = datetime.now().isoformat()
    
    # Persist or update entity risk table
    conn.execute("""
        INSERT INTO entity_risk_scores (entity_id, entity_type, risk_score, risk_level, factors, last_updated)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_id) DO UPDATE SET
            risk_score = excluded.risk_score,
            risk_level = excluded.risk_level,
            factors = excluded.factors,
            last_updated = excluded.last_updated
    """, (entity_id, entity_type.upper(), score, level, json.dumps(factors[:10]), now_iso))
    
    # If entity is a host, update the endpoints table directly
    if entity_type.upper() == "HOST":
        conn.execute("UPDATE endpoints SET risk_score=? WHERE hostname=?", (score, entity_id))
        
    conn.commit()
    conn.close()
    
    return {
        "entity_id": entity_id,
        "entity_type": entity_type.upper(),
        "risk_score": score,
        "risk_level": level,
        "factors": factors
    }

def get_top_risky_entities(limit: int = 10) -> list:
    """
    Returns highest risk hosts and users for the SOC dashboard.
    """
    conn = get_conn()
    rows = conn.execute("""
        SELECT * FROM entity_risk_scores
        ORDER BY risk_score DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["factors"] = json.loads(d.get("factors") or "[]")
        except Exception:
            d["factors"] = []
        result.append(d)
    return result
