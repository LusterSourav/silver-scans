from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import uuid
import structlog

from app.celery_app import celery_app
from app.tasks import scan_file_task
from app.api import privacy

logger = structlog.get_logger()

app = FastAPI(title="Mobile Forensics Scanner")

app.include_router(privacy.router)

class ScanRequest(BaseModel):
    file_id: str
    filename: str
    content_type: str

class ScanResponse(BaseModel):
    job_id: str
    status: str
    message: str

@app.post("/scan/upload", response_model=ScanResponse)
async def upload_and_scan(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    file_id = str(uuid.uuid4())
    content = await file.read()
    
    import aiofiles
    import os
    os.makedirs("/data/uploads", exist_ok=True)
    file_path = f"/data/uploads/{file_id}_{file.filename}"
    async with aiofiles.open(file_path, "wb") as f:
        await f.write(content)
    
    task = scan_file_task.delay(file_id, file_path, file.filename, file.content_type or "application/octet-stream")
    
    return ScanResponse(job_id=task.id, status="queued", message="Scan queued")

@app.get("/scan/{job_id}")
async def get_scan_status(job_id: str):
    result = celery_app.AsyncResult(job_id)
    return {
        "job_id": job_id,
        "status": result.status,
        "result": result.result if result.ready() else None
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)