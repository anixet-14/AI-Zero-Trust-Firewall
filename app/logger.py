"""
logger.py
----------
Handles logging of firewall inspection decisions for auditing and debugging.
"""

import os
import json
import time

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "decisions.log")

os.makedirs(LOG_DIR, exist_ok=True)

def log_decision(user, url, risk_score, decision, reason, policy_reason):
    """Logs every inspection decision to a file and console."""
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "user": user,
        "url": url,
        "risk_score": round(risk_score, 2),
        "decision": decision,
        "inspection_reason": reason,
        "policy_reason": policy_reason
    }

    print("\n📜 [FIREWALL LOG]")
    print(f"  🧍 User: {user}")
    print(f"  🌐 URL: {url}")
    print(f"  ⚠️  Risk Score: {risk_score:.2f}")
    print(f"  ✅ Decision: {decision}")
    print(f"  🔍 Reason: {reason}")
    print(f"  🧩 Policy: {policy_reason}\n")

    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"❌ Failed to write log: {e}")
