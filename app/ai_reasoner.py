"""
ai_reasoner.py
--------------
AI-style reasoning layer for security decisions.
"""

def ai_reason(
    url_risk: float,
    trust_score: float,
    user: str,
    device: str
):
    """
    Returns:
    {
        decision,
        confidence,
        explanation
    }
    """

    adjusted_risk = url_risk * (1 - trust_score / 100)

    explanation = []
    confidence = 0.5

    # --- Reasoning rules ---
    if url_risk > 0.7:
        explanation.append("URL exhibits strong phishing characteristics")
        confidence += 0.2

    if trust_score < 30:
        explanation.append("User has low historical trust score")
        confidence += 0.2

    if device.lower() not in ["trusted", "compliant"]:
        explanation.append("Device posture is unverified")
        confidence += 0.1

    # --- Final decision ---
    if adjusted_risk > 0.5:
        decision = "BLOCK"
        explanation.append("Combined contextual risk exceeds safe limits")
    elif adjusted_risk > 0.3:
        decision = "REVIEW"
        explanation.append("Moderate contextual risk detected")
    else:
        decision = "ALLOW"
        explanation.append("Risk within acceptable bounds")

    confidence = min(confidence, 0.95)

    return {
        "decision": decision,
        "confidence": round(confidence, 2),
        "adjusted_risk": round(adjusted_risk, 2),
        "explanation": "; ".join(explanation)
    }
