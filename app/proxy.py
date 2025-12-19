"""
proxy.py
---------
AI-Driven Zero-Trust Firewall with Adaptive Threshold,
Attack Detection, Trust Engine, and SOC Dashboard.
"""

from flask import Flask, request, Response, jsonify, render_template_string
import requests, os, json

from app.url_inspector import inspect_url
from app.logger import log_decision
from app.trust_engine import get_trust_score, update_trust_score
from app.ai_reasoner import ai_reason
from app.attack_monitor import (
    record_event,
    get_dynamic_threshold,
    ALERT_MODE,
    BASE_THRESHOLD,
    STRICT_THRESHOLD
)

app = Flask(__name__)

# -------------------- COMMON NAVBAR --------------------

NAVBAR = """
<div style="
    background:#222;
    padding:15px;
    border-radius:8px;
    margin-bottom:20px;
">
    <a href="/dashboard" style="color:white;margin-right:15px;">SOC Dashboard</a>
    <a href="/inspect" style="color:white;margin-right:15px;">Inspect URL</a>
    <a href="/trust" style="color:white;margin-right:15px;">Trust Analytics</a>
    <a href="/attacks" style="color:white;margin-right:15px;">Attack Monitor</a>
    <a href="/about" style="color:white;">About</a>
</div>
"""

# -------------------- HOME --------------------

@app.route("/")
def home():
    return jsonify({
        "message": "AI-Driven Zero-Trust Firewall",
        "dashboard": "/dashboard"
    })


# -------------------- CORE FIREWALL LOGIC --------------------

def process_request(url, user, device):
    risk_score, inspection_reason = inspect_url(url)
    trust_score = get_trust_score(user)
    record_event(risk_score)

    dynamic_threshold, threshold_reason = get_dynamic_threshold(trust_score)

    ai_output = ai_reason(
        url_risk=risk_score,
        trust_score=trust_score,
        user=user,
        device=device
    )

    adjusted_risk = ai_output["adjusted_risk"]

    if adjusted_risk > dynamic_threshold:
        decision = "BLOCK"
    elif adjusted_risk > dynamic_threshold * 0.7:
        decision = "REVIEW"
    else:
        decision = "ALLOW"

    new_trust = update_trust_score(user, decision)

    policy_reason = (
        f"{ai_output['explanation']} | "
        f"AdjustedRisk={adjusted_risk:.2f} | "
        f"Threshold={dynamic_threshold:.2f} ({threshold_reason}) | "
        f"Trust={new_trust:.2f}"
    )

    log_decision(
        user,
        url,
        risk_score,
        decision,
        inspection_reason,
        policy_reason
    )

    return decision, risk_score, inspection_reason, policy_reason


# -------------------- DASHBOARD --------------------

def compute_soc_stats(entries):
    stats = {"total": 0, "ALLOW": 0, "BLOCK": 0, "REVIEW": 0, "high_risk": 0}

    for e in entries:
        stats["total"] += 1
        stats[e["decision"]] += 1
        if e["risk_score"] >= 0.7:
            stats["high_risk"] += 1

    return stats


@app.route("/dashboard")
def dashboard():
    log_file = "logs/decisions.log"
    entries = []

    if os.path.exists(log_file):
        with open(log_file) as f:
            for line in f:
                try:
                    entries.append(json.loads(line))
                except:
                    pass

    stats = compute_soc_stats(entries)
    alert_text = "🔴 HIGH ALERT MODE" if ALERT_MODE else "🟢 NORMAL MODE"
    alert_color = "#f8d7da" if ALERT_MODE else "#d4edda"
    threshold = STRICT_THRESHOLD if ALERT_MODE else BASE_THRESHOLD

    # ---- Chart data preparation ----

    decision_counts = {
        "ALLOW": stats["ALLOW"],
        "BLOCK": stats["BLOCK"],
        "REVIEW": stats["REVIEW"]
    }

    risk_buckets = {
        "Low (<0.3)": 0,
        "Medium (0.3–0.6)": 0,
        "High (>0.6)": 0
    }

    attack_timeline = {}

    for e in entries:
        # Risk buckets
        if e["risk_score"] < 0.3:
            risk_buckets["Low (<0.3)"] += 1
        elif e["risk_score"] < 0.6:
            risk_buckets["Medium (0.3–0.6)"] += 1
        else:
            risk_buckets["High (>0.6)"] += 1

        # Timeline (group by minute)
        time_key = e["timestamp"][:16]
        attack_timeline[time_key] = attack_timeline.get(time_key, 0) + (
            1 if e["decision"] == "BLOCK" else 0
        )






    html = """
    <html>
    <head>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family:Arial; background:#f4f6f8; margin:30px; }
        .banner { padding:15px; background:{{ alert_color }}; border-radius:10px; }
        .cards { display:flex; gap:15px; margin-top:20px; }
        .card { background:white; padding:15px; flex:1; border-radius:10px; text-align:center; }
        table { width:100%; background:white; margin-top:30px; border-collapse:collapse; }
        th,td { padding:10px; border:1px solid #ddd; }
        th { background:#333; color:white; }
        .ALLOW { background:#d4edda; }
        .BLOCK { background:#f8d7da; }
        .REVIEW { background:#fff3cd; }
    </style>
    </head>
    <body>

    """ + NAVBAR + """

    <h1>🛡️ AI Security Operations Center</h1>

    <div style="background:white;padding:20px;border-radius:10px;margin-top:20px;">
        <h2>🔎 Inspect URL (Live Test)</h2>
        <form action="/inspect" method="get">
            URL: <input name="url" required style="width:60%;padding:8px;"><br><br>
            User: <input name="user" placeholder="aniket"><br><br>
            Device:
            <select name="device">
                <option value="trusted">Trusted</option>
                <option value="unknown">Unknown</option>
            </select><br><br>
            <button type="submit">Inspect</button>
        </form>
    </div>

    <div class="banner"><b>Status:</b> {{ alert_text }}</div>

    <div class="cards">
        <div class="card">Total<br>{{ stats.total }}</div>
        <div class="card">Allowed<br>{{ stats.ALLOW }}</div>
        <div class="card">Blocked<br>{{ stats.BLOCK }}</div>
        <div class="card">Review<br>{{ stats.REVIEW }}</div>
        <div class="card">High Risk<br>{{ stats.high_risk }}</div>
    </div>

    <div style="display:flex; gap:30px; margin-top:30px; flex-wrap:wrap;">
        <div style="width:300px;">
            <h3>Decision Distribution</h3>
            <canvas id="decisionChart"></canvas>
        </div>

        <div style="width:350px;">
            <h3>Risk Score Distribution</h3>
            <canvas id="riskChart"></canvas>
        </div>

        <div style="width:100%;">
            <h3>Attack Timeline</h3>
            <canvas id="timelineChart"></canvas>
        </div>
    </div>



    <h2>📜 Logs</h2>
    <table>
    <tr><th>Time</th><th>User</th><th>URL</th><th>Risk</th><th>Decision</th><th>Reason</th></tr>
    {% for l in entries[::-1][:50] %}
    <tr class="{{ l.decision }}">
        <td>{{ l.timestamp }}</td>
        <td>{{ l.user }}</td>
        <td>{{ l.url }}</td>
        <td>{{ l.risk_score }}</td>
        <td>{{ l.decision }}</td>
        <td>{{ l.policy_reason }}</td>
    </tr>
    {% endfor %}
    </table>
    <script>
    const decisionData = {{ decision_counts | tojson }};
    const riskData = {{ risk_buckets | tojson }};
    const timelineData = {{ attack_timeline | tojson }};

    // Pie chart - decisions
    new Chart(document.getElementById('decisionChart'), {
        type: 'pie',
        data: {
            labels: Object.keys(decisionData),
            datasets: [{
                data: Object.values(decisionData)
            }]
        }
    });

    // Bar chart - risk
    new Chart(document.getElementById('riskChart'), {
        type: 'bar',
        data: {
            labels: Object.keys(riskData),
            datasets: [{
                label: 'URLs',
                data: Object.values(riskData)
            }]
        }
    });

    // Line chart - attack timeline
    new Chart(document.getElementById('timelineChart'), {
        type: 'line',
        data: {
            labels: Object.keys(timelineData),
            datasets: [{
                label: 'Blocked Requests',
                data: Object.values(timelineData),
                fill: false
            }]
        }
    });
    </script>

    

    </body></html>
    """

    return render_template_string(
        html,
        entries=entries,
        stats=stats,
        alert_text=alert_text,
        alert_color=alert_color,
        threshold=f"{threshold:.2f}",
        decision_counts=decision_counts,
        risk_buckets=risk_buckets,
        attack_timeline=attack_timeline
    )



# -------------------- TRUST ANALYTICS --------------------

@app.route("/trust")
def trust_dashboard():
    trust_file = "logs/trust_scores.json"
    trust_data = {}

    if os.path.exists(trust_file):
        with open(trust_file) as f:
            trust_data = json.load(f)

    html = """
    <html><body style="font-family:Arial;margin:30px;">
    """ + NAVBAR + """

    <h1>🧍 User Trust Analytics</h1>

    <table border="1" cellpadding="10">
        <tr><th>User</th><th>Trust Score</th><th>Status</th></tr>
        {% for user, score in trust_data.items() %}
        <tr>
            <td>{{ user }}</td>
            <td>{{ score }}</td>
            <td>
                {% if score >= 70 %}🟢 Trusted
                {% elif score >= 40 %}🟡 Medium
                {% else %}🔴 Risky
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>

    </body></html>
    """
    return render_template_string(html, trust_data=trust_data)


# -------------------- ATTACK MONITOR --------------------

@app.route("/attacks")
def attack_monitor_page():
    log_file = "logs/decisions.log"
    attacks = []

    if os.path.exists(log_file):
        with open(log_file) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if entry["risk_score"] >= 0.65:
                        attacks.append(entry)
                except:
                    pass

    html = """
    <html><body style="font-family:Arial;margin:30px;">
    """ + NAVBAR + """

    <h1>🚨 Attack Monitor</h1>

    {% if attacks %}
    <table border="1" cellpadding="10">
        <tr><th>Time</th><th>User</th><th>URL</th><th>Risk</th><th>Decision</th></tr>
        {% for a in attacks[::-1] %}
        <tr style="background:#f8d7da;">
            <td>{{ a.timestamp }}</td>
            <td>{{ a.user }}</td>
            <td>{{ a.url }}</td>
            <td>{{ a.risk_score }}</td>
            <td>{{ a.decision }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
        <p>No attacks detected.</p>
    {% endif %}

    </body></html>
    """
    return render_template_string(html, attacks=attacks)


# -------------------- ABOUT --------------------

@app.route("/about")
def about():
    return f"""
    <html><body style="font-family:Arial;margin:30px;">
    {NAVBAR}

    <h1>📘 About This Project</h1>

    <p><b>Title:</b> AI-Driven Adaptive Zero-Trust Firewall</p>

    <h2>Key Features</h2>
    <ul>
        <li>Hybrid ML + Heuristic Phishing Detection</li>
        <li>AI Reasoning Engine with Explainability</li>
        <li>Behavioral Trust Scoring</li>
        <li>Adaptive Threshold & Attack Detection</li>
        <li>SOC Dashboard</li>
    </ul>

    <h2>Novelty</h2>
    <p>
        Traditional firewalls rely on static rules.
        This system adapts decisions dynamically using AI reasoning,
        behavioral trust, and real-time attack awareness.
    </p>

    <h2>Architecture</h2>
    <p>
        URL → ML Detection → Trust Engine → AI Reasoning →
        Adaptive Policy → SOC Visualization
    </p>

    </body></html>
    """


# -------------------- INSPECT --------------------
@app.route("/inspect")
def inspect():
    url = request.args.get("url")
    user = request.args.get("user", "anonymous")
    device = request.args.get("device", "unknown")

    # 🟢 MODE 1: No URL → Show form
    if not url:
        return f"""
        <html><body style="font-family:Arial;margin:30px;">
        {NAVBAR}

        <h1>🔎 Inspect URL</h1>

        <form method="get">
            <label><b>URL:</b></label><br>
            <input type="text" name="url" required style="width:60%;padding:8px;"><br><br>

            <label><b>User:</b></label><br>
            <input type="text" name="user" placeholder="aniket"><br><br>

            <label><b>Device Posture:</b></label><br>
            <select name="device">
                <option value="trusted">Trusted</option>
                <option value="unknown">Unknown</option>
            </select><br><br>

            <button type="submit">Inspect</button>
        </form>

        </body></html>
        """

    # 🔴 MODE 2: URL present → Run firewall
    decision, risk_score, _, policy_reason = process_request(url, user, device)

    color = "#d4edda" if decision == "ALLOW" else "#f8d7da" if decision == "BLOCK" else "#fff3cd"

    return f"""
    <html><body style="background:{color};padding:30px;">
    {NAVBAR}
    <h1>Decision: {decision}</h1>
    <p><b>URL:</b> {url}</p>
    <p><b>Risk:</b> {risk_score:.2f}</p>
    <p><b>Reason:</b> {policy_reason}</p>
    </body></html>
    """



# -------------------- RUN --------------------

# if __name__ == "__main__":
#     app.run(host="127.0.0.1", port=5000, debug=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

