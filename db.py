
import os
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Read MongoDB connection string
MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("MONGO_URI is missing from .env")

# Establish MongoDB connection
client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=10000
)

# Select database
db = client["ai_ids_db"]

# Select collections
traffic_logs = db["traffic_logs"]
alerts = db["alerts"]

# Create indexes for faster retrieval of recent records
traffic_logs.create_index([("timestamp", -1)])
alerts.create_index([("timestamp", -1)])


# Check MongoDB connection
def check_database_connection():
    client.admin.command("ping")
    return True
