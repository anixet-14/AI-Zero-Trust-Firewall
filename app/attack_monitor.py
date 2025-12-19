"""
attack_monitor.py
-----------------
Detects phishing attack waves and dynamically adjusts risk thresholds.
"""

import time
from collections import deque

HARD_PHISHING_THRESHOLD = 0.65

# Sliding window of recent high-risk events
ATTACK_WINDOW = deque(maxlen=20)

# Base threshold
BASE_THRESHOLD = 0.6

# Adaptive values
STRICT_THRESHOLD = 0.45
RELAXED_THRESHOLD = 0.75

# Alert mode state
ALERT_MODE = False
ALERT_LAST_TRIGGERED = 0
ALERT_DURATION = 120  # seconds


def record_event(risk_score: float):
    """Record suspicious events"""
    now = time.time()
    if risk_score >= 0.7:
        ATTACK_WINDOW.append(now)


def detect_attack_wave():
    """Detect if multiple phishing events happened recently"""
    now = time.time()
    recent = [t for t in ATTACK_WINDOW if now - t < 60]

    global ALERT_MODE, ALERT_LAST_TRIGGERED

    if len(recent) >= 3:
        ALERT_MODE = True
        ALERT_LAST_TRIGGERED = now

    # Auto-disable alert mode after duration
    if ALERT_MODE and (now - ALERT_LAST_TRIGGERED > ALERT_DURATION):
        ALERT_MODE = False

    return ALERT_MODE


def get_dynamic_threshold(trust_score: float):
    """
    Adaptive threshold logic
    """
    if detect_attack_wave():
        return STRICT_THRESHOLD, "High Alert Mode (attack detected)"

    if trust_score > 80:
        return RELAXED_THRESHOLD, "High trust user"

    return BASE_THRESHOLD, "Normal operating mode"
