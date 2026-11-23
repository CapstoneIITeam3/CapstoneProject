
from flask import Flask, request, jsonify
from datetime import datetime, timezone
from flasgger import Swagger
from bson import ObjectId

from ml.predict import predict
from db import traffic_logs, alerts, check_database_connection

app = Flask(__name__)

# Swagger configuration
app.config["SWAGGER"] = {
    "title": "AI-Based Intrusion Detection System API",
    "uiversion": 3
}

swagger = Swagger(app)


# Standard API error responses
@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": "Bad request",
        "message": str(error.description)
    }), 400


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "API endpoint not found"
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "error": "HTTP method not allowed"
    }), 405


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.exception("Internal server error")
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500


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
    """
    Check backend and MongoDB connection
    ---
    tags:
      - System
    responses:
      200:
        description: Backend and database are healthy
      503:
        description: MongoDB connection failed
    """
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
    """
    Detect malicious network traffic using the ML model
    ---
    tags:
      - Intrusion Detection
    consumes:
      - application/json
    parameters:
      - in: body
        name: traffic
        required: true
        schema:
          type: object
          properties:
            traffic:
              type: object
              description: Network traffic containing NSL-KDD features
              additionalProperties: true
        description: Send traffic data either inside a traffic object or directly as a JSON object
    responses:
      200:
        description: Traffic prediction successfully processed and saved
      400:
        description: Invalid JSON request
      500:
        description: Prediction or database operation failed
    """
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

        # Validate traffic input
        if not traffic:
            return jsonify({
                "success": False,
                "error": "Traffic data cannot be empty"
            }), 400

        if not all(isinstance(key, str) for key in traffic):
            return jsonify({
                "success": False,
                "error": "All traffic feature names must be strings"
            }), 400

        # Get prediction from trained ML model
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
    """
    Retrieve stored network traffic logs
    ---
    tags:
      - Traffic Logs
    parameters:
      - name: limit
        in: query
        type: integer
        required: false
        default: 50
        description: Number of logs to retrieve (1 to 200)
    responses:
      200:
        description: Traffic logs successfully retrieved
      500:
        description: Unable to retrieve traffic logs
    """
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
    """
    Retrieve generated security alerts
    ---
    tags:
      - Security Alerts
    parameters:
      - name: limit
        in: query
        type: integer
        required: false
        default: 50
        description: Number of alerts to retrieve (1 to 200)
    responses:
      200:
        description: Security alerts successfully retrieved
      500:
        description: Unable to retrieve alerts
    """
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


# Update security alert status
@app.route("/api/alerts/<alert_id>", methods=["PATCH"])
def update_alert_status(alert_id):
    """
    Update the status of a security alert
    ---
    tags:
      - Security Alerts
    parameters:
      - name: alert_id
        in: path
        type: string
        required: true
        description: MongoDB alert ID
      - in: body
        name: status
        required: true
        schema:
          type: object
          properties:
            status:
              type: string
              enum:
                - New
                - In Progress
                - Resolved
    responses:
      200:
        description: Alert status updated successfully
      400:
        description: Invalid status or request body
      404:
        description: Alert not found
      500:
        description: Database update failed
    """
    try:
        data = request.get_json(silent=True)

        if not isinstance(data, dict) or not isinstance(data.get("status"), str):
            return jsonify({
                "success": False,
                "error": "A valid status is required"
            }), 400

        status = data["status"].strip().title()
        allowed_statuses = ["New", "In Progress", "Resolved"]

        if status not in allowed_statuses:
            return jsonify({
                "success": False,
                "error": "Status must be New, In Progress, or Resolved"
            }), 400

        query = {"_id": alert_id}

        if ObjectId.is_valid(alert_id):
            query = {"_id": ObjectId(alert_id)}

        result = alerts.update_one(
            query,
            {
                "$set": {
                    "status": status,
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )

        if result.matched_count == 0:
            return jsonify({
                "success": False,
                "error": "Alert not found"
            }), 404

        return jsonify({
            "success": True,
            "message": "Alert status updated successfully",
            "alert_id": alert_id,
            "status": status
        }), 200

    except Exception:
        app.logger.exception("Unable to update alert status")
        return jsonify({
            "success": False,
            "error": "Unable to update alert status"
        }), 500


if __name__ == "__main__":
    # Disable automatic reloader to avoid Windows socket issues
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )
