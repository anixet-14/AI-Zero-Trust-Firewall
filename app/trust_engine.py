"""
trust_engine.py
---------------
Maintains dynamic trust scores for users/devices based on behavior.
"""

import json
import os

TRUST_FILE = "logs/trust_scores.json"

# Initialize trust storage
if not os.path.exists(TRUST_FILE):
    with open(TRUST_FILE, "w") as f:
        json.dump({}, f)


def get_trust_score(user: str) -> float:
    """Return trust score (0–100). Default = 50"""
    with open(TRUST_FILE, "r") as f:
        data = json.load(f)
    return data.get(user, 50.0)


def update_trust_score(user: str, decision: str):
    """Update trust score based on firewall decision."""
    with open(TRUST_FILE, "r") as f:
        data = json.load(f)

    score = data.get(user, 50.0)

    if decision == "ALLOW":
        score += 2
    elif decision == "REVIEW":
        score -= 2
    elif decision == "BLOCK":
        score -= 5

    # Clamp between 0 and 100
    score = max(0, min(100, score))
    data[user] = score

    with open(TRUST_FILE, "w") as f:
        json.dump(data, f, indent=2)

    return score
