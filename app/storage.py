import os
import shutil

UPLOAD_DIR = "/data/uploads"

async def get_user_file_count(user_id: str) -> int:
    """Get file count for a user"""
    if not os.path.exists(UPLOAD_DIR):
        return 0
    count = 0
    for f in os.listdir(UPLOAD_DIR):
        if f.startswith(user_id + "_") or f"_{user_id}_" in f:
            count += 1
    return count

async def delete_user_files(user_id: str) -> int:
    """Delete all uploaded files for a user"""
    if not os.path.exists(UPLOAD_DIR):
        return 0
    deleted = 0
    for f in os.listdir(UPLOAD_DIR):
        if f.startswith(user_id + "_") or f"_{user_id}_" in f:
            file_path = os.path.join(UPLOAD_DIR, f)
            try:
                os.remove(file_path)
                deleted += 1
            except Exception:
                pass
    return deleted