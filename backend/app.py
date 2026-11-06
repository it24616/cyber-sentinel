
from flask import Flask, request, jsonify
from flask_cors import CORS
import re

from database import (
    initialize_database,
    save_alert,
    get_all_alerts,
    update_alert,
    delete_alert
)

app = Flask(__name__)
CORS(app)

# Initialize SQLite Database
initialize_database()


# =====================================
# Risk Assessment Function
# =====================================

def assess_risk(event_data):

    text = event_data.lower()

    score = 0
    detected_threats = []

    # SQL Injection Detection
    sql_pattern = (
        r"union\s+select|"
        r"select.+from|"
        r"'\s*or\s+['\"]?1['\"]?\s*="
    )

    if re.search(sql_pattern, text):
        score += 40
        detected_threats.append("Possible SQL Injection")

    # XSS Detection
    xss_pattern = (
        r"<\s*script\b|"
        r"javascript\s*:|"
        r"onerror\s*=|"
        r"onload\s*="
    )

    if re.search(xss_pattern, text):
        score += 40
        detected_threats.append("Possible XSS Attack")

    # Brute Force Detection
    brute_pattern = (
        r"failed login|"
        r"multiple failed attempts|"
        r"authentication failure|"
        r"brute force"
    )

    if re.search(brute_pattern, text):
        score += 30
        detected_threats.append("Possible Brute Force")

    # Maximum Risk Score
    score = min(score, 100)

    # Risk Level Assessment
    if score >= 80:
        risk_level = "CRITICAL"
        recommendation = (
            "Investigate immediately and review security logs."
        )

    elif score >= 60:
        risk_level = "HIGH"
        recommendation = (
            "Investigate the suspicious activity and apply security controls."
        )

    elif score >= 30:
        risk_level = "MEDIUM"
        recommendation = (
            "Review the event and monitor for repeated activity."
        )

    else:
        risk_level = "LOW"
        recommendation = (
            "No known threat pattern detected. Continue monitoring."
        )

    if not detected_threats:
        detected_threats.append("No Known Threat Pattern")

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "detected_threats": detected_threats,
        "recommendation": recommendation
    }


# =====================================
# Home API
# =====================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "success": True,
        "message": "CyberGuard Risk Assessment API is running."
    })


# =====================================
# Risk Assessment API
# =====================================

@app.route("/api/assess-risk", methods=["POST"])
def risk_assessment():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON data."
        }), 400

    event_data = data.get("event_data")

    if not isinstance(event_data, str) or not event_data.strip():
        return jsonify({
            "success": False,
            "error": "Please provide valid event data."
        }), 400

    if len(event_data) > 10000:
        return jsonify({
            "success": False,
            "error": "Input is too long."
        }), 400

    # Analyze Security Event
    result = assess_risk(event_data)

    # Save Detected Threats into Database
    if result["risk_score"] > 0:
        save_alert(event_data, result)

    return jsonify({
        "success": True,
        "message": "Risk assessment completed.",
        "result": result
    })


# =====================================
# Get All Security Alerts API
# =====================================

@app.route("/api/alerts", methods=["GET"])
def get_alerts():

    alerts = get_all_alerts()

    return jsonify({
        "success": True,
        "alerts": alerts
    })


# =====================================
# Update Security Alert API
# =====================================

@app.route("/api/alerts/<int:alert_id>", methods=["PATCH"])
def update_alert_status(alert_id):

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON data."
        }), 400

    status = data.get("status")
    is_read = data.get("is_read")

    if status is not None and status not in ["Open", "Resolved"]:
        return jsonify({
            "success": False,
            "error": "Invalid status."
        }), 400

    if is_read is not None and not isinstance(is_read, bool):
        return jsonify({
            "success": False,
            "error": "is_read must be true or false."
        }), 400

    if status is None and is_read is None:
        return jsonify({
            "success": False,
            "error": "No update provided."
        }), 400

    updated = update_alert(
        alert_id,
        status=status,
        is_read=is_read
    )

    if not updated:
        return jsonify({
            "success": False,
            "error": "Alert not found."
        }), 404

    return jsonify({
        "success": True,
        "message": "Alert updated successfully."
    })


# =====================================
# Delete Security Alert API
# =====================================

@app.route("/api/alerts/<int:alert_id>", methods=["DELETE"])
def remove_alert(alert_id):

    deleted = delete_alert(alert_id)

    if not deleted:
        return jsonify({
            "success": False,
            "error": "Alert not found."
        }), 404

    return jsonify({
        "success": True,
        "message": "Alert deleted successfully."
    })


# =====================================
# Run Flask Application
# =====================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
