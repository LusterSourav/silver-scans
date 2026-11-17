from celery import shared_task
from app.celery_app import celery_app
from app.config import settings
import structlog
import asyncio
from pymongo import MongoClient
import os
import hashlib
import subprocess
import json
from datetime import datetime
import httpx

from app.living_intel_integration import enrich_scan_with_threat_intel, check_ioc_threat_intel

logger = structlog.get_logger()

mongo_client = MongoClient(settings.mongo_url)
db = mongo_client[settings.mongo_db]

def save_result(job_id: str, result: dict):
    db.scans.update_one(
        {"job_id": job_id},
        {"$set": {**result, "updated_at": datetime.utcnow()}},
        upsert=True
    )

@shared_task(bind=True, max_retries=3)
def scan_file_task(self, file_id: str, file_path: str, filename: str, content_type: str):
    job_id = self.request.id
    logger.info("scan_started", job_id=job_id, file_id=file_id, filename=filename)
    
    try:
        result = asyncio.run(_run_scans(file_id, file_path, filename, content_type, job_id))
        save_result(job_id, {"job_id": job_id, "status": "completed", "result": result})
        return result
    except Exception as exc:
        logger.error("scan_failed", job_id=job_id, error=str(exc))
        save_result(job_id, {"job_id": job_id, "status": "failed", "error": str(exc)})
        raise self.retry(exc=exc, countdown=60)

async def _run_scans(file_id: str, file_path: str, filename: str, content_type: str, job_id: str):
    results = {
        "file_id": file_id,
        "filename": filename,
        "content_type": content_type,
        "sha256": _sha256(file_path),
        "size": os.path.getsize(file_path),
        "scans": {}
    }
    
    results["scans"]["static"] = await _static_analysis(file_path, filename)
    results["scans"]["mvt"] = await _mvt_scan(file_path)
    results["scans"]["yara"] = await _yara_scan(file_path)
    results["scans"]["virustotal"] = await _virustotal_scan(file_path)
    results["scans"]["mobsf"] = await _mobsf_scan(file_path)
    results["scans"]["ghidra"] = await _ghidra_scan(file_path)
    
    results["risk_score"] = _calculate_risk(results["scans"])
    results["completed_at"] = datetime.utcnow().isoformat()
    
    # Enrich with Living Threat Intelligence
    try:
        results = await enrich_scan_with_threat_intel(results)
    except Exception as e:
        logger.warning("threat_intel_enrichment_failed", error=str(e))
    
    return results

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

async def _static_analysis(file_path: str, filename: str):
    if not filename.endswith(".apk"):
        return {"skipped": "not an apk"}
    try:
        result = subprocess.run(
            ["apktool", "d", "-f", "-o", f"/tmp/apktool_{os.path.basename(file_path)}", file_path],
            capture_output=True, text=True, timeout=300
        )
        base_result = {"success": result.returncode == 0, "output": result.stdout[:5000]}
        
        if result.returncode == 0:
            flutter_info = await _flutter_analysis(file_path)
            base_result["flutter"] = flutter_info
        
        jadx_result = await _jadx_analysis(file_path)
        base_result["jadx"] = jadx_result
        
        return base_result
    except Exception as e:
        return {"error": str(e)}

async def _jadx_analysis(file_path: str):
    try:
        output_dir = f"/tmp/jadx_{os.path.basename(file_path)}"
        env = os.environ.copy()
        env["JAVA_HOME"] = "/usr/lib/jvm/java-21-openjdk-arm64"
        env["PATH"] = "/usr/lib/jvm/java-21-openjdk-arm64/bin:" + env.get("PATH", "")
        result = subprocess.run(
            ["jadx", "-d", output_dir, "--no-res", "--no-debug-info", file_path],
            capture_output=True, text=True, timeout=300, env=env
        )
        if result.returncode == 0:
            return {"success": True, "output_dir": output_dir, "classes_decompiled": True}
        return {"error": result.stderr[:2000] if result.stderr else "decompilation failed"}
    except Exception as e:
        return {"error": str(e)}

async def _flutter_analysis(file_path: str):
    try:
        import zipfile
        flutter_info = {"detected": False, "dart_snapshot": None, "assets": [], "libflutter": None}
        
        with zipfile.ZipFile(file_path, 'r') as apk:
            file_list = apk.namelist()
            
            flutter_info["detected"] = any(
                "flutter" in f.lower() or "dart" in f.lower() 
                for f in file_list
            )
            
            if flutter_info["detected"]:
                for f in file_list:
                    if f.endswith(".so") and ("flutter" in f or "dart" in f):
                        flutter_info["libflutter"] = f
                    elif f.endswith("kernel_blob.bin") or f.endswith("app.dill") or f.endswith("app.so"):
                        flutter_info["dart_snapshot"] = f
                    elif f.startswith("assets/") or f.startswith("flutter_assets/"):
                        flutter_info["assets"].append(f)
        
        if flutter_info["detected"]:
            try:
                out_dir = f"/tmp/flutter_re_{os.path.basename(file_path)}"
                os.makedirs(out_dir, exist_ok=True)
                result = subprocess.run(
                    ["unzip", "-q", "-o", file_path, "-d", out_dir],
                    capture_output=True, timeout=60
                )
                if result.returncode == 0:
                    flutter_info["extracted_path"] = out_dir
            except Exception:
                pass
        
        return flutter_info
    except Exception as e:
        return {"error": str(e)}

async def _mvt_scan(file_path: str):
    try:
        from mvt.android.modules.backup.base import BackupExtraction
        
        if file_path.endswith(".ab") or "android" in file_path:
            backup = BackupExtraction(file_path=file_path)
        elif file_path.endswith(".plist") or "ios" in file_path:
            return {"skipped": "iOS backup analysis not yet implemented"}
        else:
            return {"skipped": "not a recognized backup format"}
        
        iocs = []
        for detection in backup.check_indicators():
            iocs.append({"type": detection.type, "description": detection.description})
        
        return {"iocs_found": len(iocs), "iocs": iocs}
    except Exception as e:
        return {"error": str(e)}

async def _yara_scan(file_path: str):
    try:
        import yara
        rules = yara.compile(filepath="/app/rules/mobile.yar") if os.path.exists("/app/rules/mobile.yar") else None
        if not rules:
            return {"skipped": "no yara rules"}
        matches = rules.match(file_path)
        return {"matches": [{"rule": m.rule, "tags": m.tags} for m in matches]}
    except Exception as e:
        return {"error": str(e)}

async def _virustotal_scan(file_path: str):
    if not settings.vt_api_key:
        return {"skipped": "no api key"}
    try:
        import virustotal_python
        with virustotal_python.Virustotal(settings.vt_api_key) as vt:
            with open(file_path, "rb") as f:
                resp = vt.request("files", files={"file": f}, method="POST")
            analysis_id = resp.data["id"]
            return {"analysis_id": analysis_id, "status": "submitted"}
    except Exception as e:
        return {"error": str(e)}

async def _mobsf_scan(file_path: str):
    if not settings.mobsf_api_key:
        return {"skipped": "no mobsf api key"}
    try:
        async with httpx.AsyncClient(timeout=300) as client:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                headers = {"Authorization": settings.mobsf_api_key}
                upload = await client.post(f"{settings.mobsf_url}/api/v1/upload", files=files, headers=headers)
            if upload.status_code != 200:
                return {"error": "upload failed", "status": upload.status_code}
            scan_hash = upload.json()["hash"]
            
            scan = await client.post(f"{settings.mobsf_url}/api/v1/scan", data={"hash": scan_hash}, headers=headers)
            if scan.status_code != 200:
                return {"error": "scan failed", "status": scan.status_code}
            
            report = await client.post(f"{settings.mobsf_url}/api/v1/report_json", data={"hash": scan_hash}, headers=headers)
            return report.json() if report.status_code == 200 else {"error": "report failed"}
    except Exception as e:
        return {"error": str(e)}

async def _ghidra_scan(file_path: str):
    try:
        output_file = f"/tmp/ghidra_{os.path.basename(file_path)}.txt"
        project_dir = "/tmp/ghidra_project"
        os.makedirs(project_dir, exist_ok=True)
        
        if file_path.endswith(".apk"):
            import zipfile
            dex_files = []
            with zipfile.ZipFile(file_path, 'r') as apk:
                for name in apk.namelist():
                    if name.endswith(".dex"):
                        dex_path = f"/tmp/{os.path.basename(name)}"
                        with open(dex_path, "wb") as f:
                            f.write(apk.read(name))
                        dex_files.append(dex_path)
            
            if not dex_files:
                return {"skipped": "no dex files in apk"}
            
            results = []
            for dex_file in dex_files[:3]:
                result = subprocess.run([
                    "/opt/ghidra/support/analyzeHeadless-fixed",
                    project_dir, "analyze",
                    "-import", dex_file,
                    "-scriptPath", "/app/ghidra_scripts",
                    "-postScript", "ExtractInfo.java", output_file
                ], capture_output=True, text=True, timeout=300)
                if os.path.exists(output_file):
                    with open(output_file) as f:
                        results.append(f.read()[:5000])
                else:
                    results.append({"error": result.stderr[:2000] if result.stderr else "no output"})
            
            return {"dex_analyzed": len(dex_files), "results": results}
        else:
            result = subprocess.run([
                "/opt/ghidra/support/analyzeHeadless-fixed",
                project_dir, "analyze",
                "-import", file_path,
                "-scriptPath", "/app/ghidra_scripts",
                "-postScript", "ExtractInfo.java", output_file
            ], capture_output=True, text=True, timeout=600)
            
            if os.path.exists(output_file):
                with open(output_file) as f:
                    content = f.read()
                return {"output": content[:10000]}
            return {"error": result.stderr[:2000] if result.stderr else "no output"}
    except Exception as e:
        return {"error": str(e)}

def _calculate_risk(scans: dict) -> int:
    score = 0
    if scans.get("mvt", {}).get("iocs_found", 0) > 0:
        score += 40
    if scans.get("yara", {}).get("matches"):
        score += 30
    vt = scans.get("virustotal", {})
    if vt.get("status") == "submitted":
        score += 10
    if scans.get("static", {}).get("success"):
        score += 5
    mobsf = scans.get("mobsf", {})
    if mobsf.get("security_score", 100) < 50:
        score += 25
    elif mobsf.get("security_score", 100) < 75:
        score += 10
    ghidra = scans.get("ghidra", {})
    if "error" not in ghidra and "suspicious" in ghidra.get("output", "").lower():
        score += 15
    return min(score, 100)

# GDPR Privacy API helper functions
async def get_user_scans(user_id: str):
    """Get all scans for a user"""
    cursor = db.scans.find({"user_id": user_id}).sort("created_at", -1)
    scans = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        scans.append(doc)
    return scans

async def get_scan_count(user_id: str):
    """Get scan count for a user"""
    return db.scans.count_documents({"user_id": user_id})

async def delete_user_scans(user_id: str):
    """Delete all scans for a user"""
    result = db.scans.delete_many({"user_id": user_id})
    return result.deleted_count

async def get_user_file_count(user_id: str):
    """Get file count for a user"""
    upload_dir = "/data/uploads"
    if not os.path.exists(upload_dir):
        return 0
    count = 0
    for f in os.listdir(upload_dir):
        if f.startswith(user_id + "_") or f"_{user_id}_" in f:
            count += 1
    return count