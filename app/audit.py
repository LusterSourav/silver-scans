from app.config import settings
from pymongo import MongoClient
from datetime import datetime
import structlog
import hashlib

logger = structlog.get_logger()

mongo_client = MongoClient(settings.mongo_url)
db = mongo_client[settings.mongo_db]

async def get_user_log_count(user_id: str) -> int:
    """Get log count for a user"""
    return db.audit_logs.count_documents({"user_id": user_id})

async def anonymize_user_logs(user_id: str) -> int:
    """Anonymize logs for a user (replace user_id with hash)"""
    import hashlib
    anon_id = hashlib.sha256(user_id.encode()).hexdigest()[:16]
    result = db.audit_logs.update_many(
        {"user_id": user_id},
        {"$set": {"user_id": f"anon_{anon_id}", "anonymized": True, "anonymized_at": datetime.utcnow()}}
    )
    return result.modified_count

async def log_deletion(deletion_log: dict):
    """Log deletion for audit trail"""
    db.deletion_logs.insert_one(deletion_log)

async def get_user_log_count(user_id: str) -> int:
    """Get log count for a user"""
    return db.audit_logs.count_documents({"user_id": user_id})