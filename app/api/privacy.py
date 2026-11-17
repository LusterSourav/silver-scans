from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import json

router = APIRouter(prefix="/privacy", tags=["privacy"])

class DataExportRequest(BaseModel):
    user_id: str
    include_scans: bool = True
    include_logs: bool = False

class DataDeletionRequest(BaseModel):
    user_id: str
    confirm: bool = False
    reason: Optional[str] = None

class DataExportResponse(BaseModel):
    user_id: str
    exported_at: str
    scan_count: int
    file_count: int
    log_entries: int

@router.post("/export", response_model=DataExportResponse)
async def export_user_data(request: DataExportRequest):
    """GDPR Article 20 - Right to Data Portability"""
    from app.tasks import get_user_scans
    from app.storage import get_user_file_count
    from app.audit import get_user_log_count
    
    scans = await get_user_scans(request.user_id) if request.include_scans else []
    file_count = await get_user_file_count(request.user_id)
    log_count = await get_user_log_count(request.user_id) if request.include_logs else 0
    
    export_data = {
        "user_id": request.user_id,
        "exported_at": datetime.utcnow().isoformat(),
        "scans": scans,
        "summary": {
            "scan_count": len(scans),
            "file_count": file_count,
            "log_entries": log_count
        }
    }
    
    from fastapi.responses import JSONResponse
    return JSONResponse(
        content=export_data,
        headers={
            "Content-Disposition": f'attachment; filename="user_data_{request.user_id}.json"'
        }
    )

@router.post("/delete")
async def delete_user_data(request: DataDeletionRequest):
    """GDPR Article 17 - Right to Erasure"""
    if not request.confirm:
        raise HTTPException(400, "Confirmation required")
    
    deletion_log = {
        "user_id": request.user_id,
        "requested_at": datetime.utcnow().isoformat(),
        "reason": request.reason,
        "deleted_items": []
    }
    
    from app.tasks import delete_user_scans
    from app.storage import delete_user_files
    from app.audit import anonymize_user_logs
    from living_intel.platform import delete_user_intel
    from app.audit import log_deletion
    
    deleted = await delete_user_scans(request.user_id)
    deletion_log["deleted_items"].append({"type": "scans", "count": deleted})
    
    deleted = await delete_user_files(request.user_id)
    deletion_log["deleted_items"].append({"type": "files", "count": deleted})
    
    await anonymize_user_logs(request.user_id)
    deletion_log["deleted_items"].append({"type": "logs", "action": "anonymized"})
    
    await delete_user_intel(request.user_id)
    deletion_log["deleted_items"].append({"type": "threat_intel", "action": "deleted"})
    
    await log_deletion(deletion_log)
    
    return {"status": "completed", "details": deletion_log}

@router.get("/inventory/{user_id}")
async def get_data_inventory(user_id: str):
    """Show what data we hold for a user"""
    from app.tasks import get_scan_count
    from app.storage import get_user_file_count
    from app.audit import get_user_log_count
    
    return {
        "user_id": user_id,
        "scan_count": await get_scan_count(user_id),
        "file_count": await get_user_file_count(user_id),
        "log_entries": await get_user_log_count(user_id),
        "retention_policy": "Scans: 90 days, Logs: 1 year, Files: deleted after scan"
    }