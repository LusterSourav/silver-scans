#!/usr/bin/env python3
"""
Test MongoDB connection using environment variables.
Usage: MONGO_TEST_URI=mongodb://user:pass@host:port python test_mongo.py
"""

import os
import sys
from pymongo import MongoClient

# Get URI from environment variable
uri = os.environ.get("MONGO_TEST_URI")
if not uri:
    print("ERROR: MONGO_TEST_URI environment variable is required")
    print("Example: export MONGO_TEST_URI='mongodb://<user>:<pass>@<host>:<port>/<db>'")
    sys.exit(1)

client = MongoClient(uri)
try:
    client.admin.command("ping")
    print("Connected successfully")
    db = client["forensics"]
    db.scans.create_index("job_id", unique=True)
    db.scans.create_index("created_at")
    print("Indexes created")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
finally:
    client.close()