from .entropy import shannon_entropy

def analyze_dns_query(query, record_type="A"):
    q = query.rstrip(".")
    labels = q.split(".")
    longest = max((len(x) for x in labels), default=0)
    first = labels[0] if labels else ""
    ent = shannon_entropy(first)

    reasons = []
    score = 0

    if len(q) >= 60:
        score += 2; reasons.append("Long DNS query")
    if longest >= 35:
        score += 2; reasons.append("Long subdomain")
    if ent >= 3.5 and len(first) >= 12:
        score += 2; reasons.append("High-entropy subdomain")
    if record_type.upper() == "TXT":
        score += 1; reasons.append("TXT record observed")

    if score >= 4:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "NORMAL"

    return {
        "length": len(q),
        "entropy": ent,
        "risk": risk,
        "reason": ", ".join(reasons) if reasons else "No strong anomaly detected"
    }
