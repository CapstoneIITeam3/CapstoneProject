
import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("MONGO_URI is missing from .env")

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=10000
)

db = client["ai_ids_db"]

traffic_logs = db["traffic_logs"]
alerts = db["alerts"]


def check_database_connection():
    client.admin.command("ping")
    return True
