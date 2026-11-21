import os
import logging
from pymongo import MongoClient, ASCENDING, DESCENDING
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/ai_ids_db")
DB_NAME = os.getenv("MONGO_DB_NAME", "ai_ids_db")

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000
)

db = client[DB_NAME]

# Primary MongoDB Collections
users_col = db["users"]
log_records_col = db["log_records"]
alerts_col = db["alerts"]
settings_col = db["settings"]
audit_logs_col = db["audit_logs"]
password_resets_col = db["password_resets"]
counters_col = db["counters"]

# Aliases for backward compatibility with existing backend scripts
traffic_logs = log_records_col
alerts = alerts_col


def init_db_indexes():
    """Ensure indexes are created idempotently on startup."""
    try:
        users_col.create_index("username", unique=True)
        users_col.create_index("email", unique=True, sparse=True)
        log_records_col.create_index([("timestamp", DESCENDING)])
        log_records_col.create_index([("id", DESCENDING)], unique=True, sparse=True)
        log_records_col.create_index("result.tier")
        log_records_col.create_index("result.threat_score")
        log_records_col.create_index("src_ip")
        log_records_col.create_index("service")
        alerts_col.create_index([("created_at", DESCENDING)])
        alerts_col.create_index([("id", DESCENDING)], unique=True, sparse=True)
        alerts_col.create_index("status")
        alerts_col.create_index("severity")
        settings_col.create_index("key", unique=True)
        audit_logs_col.create_index([("timestamp", DESCENDING)])
        password_resets_col.create_index("token", unique=True)
        password_resets_col.create_index("created_at", expireAfterSeconds=3600)
    except Exception as e:
        log.warning("Index initialization notice: %s", e)


def check_database_connection():
    """Verify MongoDB connectivity."""
    client.admin.command("ping")
    return True
