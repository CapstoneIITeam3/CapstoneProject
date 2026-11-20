
from flask import Flask, request, jsonify
from datetime import datetime, timezone

from ml.predict import predict
from db import traffic_logs, alerts, check_database_connection

app = Flask(__name__)


# Convert ML prediction labels into severity levels
def get_severity(label):
    severity_map = {
        "Normal": "Low",
        "Suspicious": "Medium",
        "Malicious": "High"
    }
    return severity_map.get(label, "Unknown")


# Home endpoint
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "AI-Based Intrusion Detection System API",
        "status": "running"
    }), 200


# Health and MongoDB connection endpoint
@app.route("/api/health", methods=["GET"])
def health():
    try:
        check_database_connection()
        db_status = "connected"
        status_code = 200
    except Exception:
        app.logger.exception("MongoDB connection failed")
        db_status = "disconnected"
        status_code = 503

    return jsonify({
        "status": "healthy" if db_status == "connected" else "unhealthy",
        "service": "AI-IDS Backend",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), status_code


# ML prediction endpoint
@app.route("/api/predict", methods=["POST"])
def predict_traffic():
    try:
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "success": False,
                "error": "Request body must be a JSON object"
            }), 400

        traffic = data.get("traffic", data)

        if not isinstance(traffic, dict):
            return jsonify({
                "success": False,
                "error": "Traffic data must be a JSON object"
            }), 400

        # Get prediction from Adwitiya's trained ML model
        result = predict(traffic)

        label = result["label"]
        score = result["score"]
        severity = get_severity(label)
        timestamp = datetime.now(timezone.utc)

        # Save traffic prediction in MongoDB
        log_document = {
            "traffic": traffic,
            "prediction": label,
            "score": score,
            "severity": severity,
            "timestamp": timestamp
        }

        log_result = traffic_logs.insert_one(log_document)

        response = {
            "success": True,
            "prediction": {
                "label": label,
                "score": score,
                "severity": severity
            },
            "log_id": str(log_result.inserted_id),
            "timestamp": timestamp.isoformat()
        }

        # Generate alert for suspicious or malicious traffic
        if label in ["Suspicious", "Malicious"]:
            alert_document = {
                "log_id": str(log_result.inserted_id),
                "prediction": label,
                "severity": severity,
                "score": score,
                "message": f"{label} network traffic detected",
                "status": "New",
                "timestamp": timestamp
            }

            alert_result = alerts.insert_one(alert_document)

            response["alert"] = {
                "alert_id": str(alert_result.inserted_id),
                "status": "created"
            }
        else:
            response["alert"] = None

        return jsonify(response), 200

    except Exception:
        app.logger.exception("Prediction or database operation failed")
        return jsonify({
            "success": False,
            "error": "Unable to process and save traffic prediction"
        }), 500


# Retrieve traffic logs
@app.route("/api/logs", methods=["GET"])
def get_logs():
    try:
        limit = min(max(request.args.get("limit", 50, type=int), 1), 200)

        documents = list(
            traffic_logs.find().sort("timestamp", -1).limit(limit)
        )

        for document in documents:
            document["_id"] = str(document["_id"])
            if isinstance(document.get("timestamp"), datetime):
                document["timestamp"] = document["timestamp"].isoformat()

        return jsonify({
            "success": True,
            "count": len(documents),
            "logs": documents
        }), 200

    except Exception:
        app.logger.exception("Unable to fetch traffic logs")
        return jsonify({
            "success": False,
            "error": "Unable to retrieve traffic logs"
        }), 500


# Retrieve generated alerts
@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    try:
        limit = min(max(request.args.get("limit", 50, type=int), 1), 200)

        documents = list(
            alerts.find().sort("timestamp", -1).limit(limit)
        )

        for document in documents:
            document["_id"] = str(document["_id"])
            if isinstance(document.get("timestamp"), datetime):
                document["timestamp"] = document["timestamp"].isoformat()

        return jsonify({
            "success": True,
            "count": len(documents),
            "alerts": documents
        }), 200

    except Exception:
        app.logger.exception("Unable to fetch alerts")
        return jsonify({
            "success": False,
            "error": "Unable to retrieve alerts"
        }), 500


if __name__ == "__main__":
    # Disable automatic reloader to avoid Windows socket issues
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )
