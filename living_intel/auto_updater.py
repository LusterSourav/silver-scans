"""
Auto-Updater System
Automatic updates for threat intelligence platform components
"""
import asyncio
import logging
import subprocess
import json
import hashlib
import tempfile
import shutil
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
import aiohttp
import aiofiles
import semver

logger = logging.getLogger(__name__)


@dataclass
class UpdateInfo:
    """Information about an available update"""
    component: str
    current_version: str
    latest_version: str
    release_notes: str
    download_url: str
    checksum: str
    critical: bool = False
    release_date: Optional[datetime] = None


@dataclass
class UpdateStatus:
    """Status of an update operation"""
    component: str
    status: str  # pending, downloading, installing, completed, failed
    progress: float = 0.0
    message: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class AutoUpdater:
    """
    Automatic updater for threat intelligence platform components
    Handles CVE databases, threat intel feeds, plugins, GeoIP, and platform updates
    """
    
    def __init__(self, platform):
        self.platform = platform
        self.running = False
        self.update_tasks: Dict[str, asyncio.Task] = {}
        self.update_status: Dict[str, UpdateStatus] = {}
        self.update_callbacks: List[Callable] = []
        
        # Update configurations
        self.update_config = {
            "cve_database": {
                "enabled": True,
                "interval": 86400,  # Daily
                "source": "nvd",
                "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
                "critical": True
            },
            "threat_intel_feeds": {
                "enabled": True,
                "interval": 3600,  # Hourly
                "sources": "all"
            },
            "geoip_database": {
                "enabled": True,
                "interval": 604800,  # Weekly
                "url": "https://download.maxmind.com/app/geoip_download",
                "critical": False
            },
            "platform": {
                "enabled": True,
                "interval": 86400,  # Daily
                "source": "github",
                "repo": "silver-scan/silver-scan"
            },
            "plugins": {
                "enabled": True,
                "interval": 86400,
                "source": "pypi"
            },
            "geoip_database": {
                "enabled": True,
                "interval": 604800,  # Weekly
                "edition": "GeoLite2-City"
            }
        }
        
        self.update_status: Dict[str, UpdateStatus] = {}
        self.running = False
        self.update_callbacks: List[Callable] = []
    
    def add_update_callback(self, callback: Callable):
        """Add callback for update events"""
        self.update_callbacks.append(callback)
    
    async def start(self):
        """Start auto-updater"""
        self.running = True
        logger.info("Auto-updater started")
        
        # Start update loops for each component
        self.update_tasks = {
            "cve_database": asyncio.create_task(self._update_cve_loop()),
            "threat_intel_feeds": asyncio.create_task(self._update_feeds_loop()),
            "geoip_database": asyncio.create_task(self._update_geoip_loop()),
            "platform": asyncio.create_task(self._update_platform_loop()),
            "plugins": asyncio.create_task(self._update_plugins_loop()),
        }
        
        # Initial updates
        await self.check_all_updates()
    
    async def _update_cve_loop(self):
        """Update CVE database periodically"""
        while self.running:
            try:
                await self._update_cve_database()
            except Exception as e:
                logger.error(f"CVE database update loop error: {e}")
            await asyncio.sleep(86400)  # Daily
    
    async def _update_feeds_loop(self):
        """Update threat intel feeds periodically"""
        while self.running:
            try:
                await self._update_threat_intel_feeds()
            except Exception as e:
                logger.error(f"Threat intel feed update loop error: {e}")
            await asyncio.sleep(3600)  # Hourly
    
    async def _update_geoip_loop(self):
        """Update GeoIP database periodically"""
        while self.running:
            try:
                await self._update_geoip_database()
            except Exception as e:
                logger.error(f"GeoIP database update loop error: {e}")
            await asyncio.sleep(604800)  # Weekly
    
    async def _update_platform_loop(self):
        """Check for platform updates periodically"""
        while self.running:
            try:
                await self._update_platform()
            except Exception as e:
                logger.error(f"Platform update loop error: {e}")
            await asyncio.sleep(86400)  # Daily
    
    async def _update_plugins_loop(self):
        """Check for plugin updates periodically"""
        while self.running:
            try:
                # Check PyPI for plugin updates
                pass
            except Exception as e:
                logger.error(f"Plugin update loop error: {e}")
            await asyncio.sleep(86400)  # Daily
    
    def add_update_callback(self, callback: Callable):
        """Add callback for update events"""
        self.update_callbacks.append(callback)
    
    async def _notify_update(self, event: str, data: Dict):
        """Notify all callbacks of update event"""
        for callback in self.update_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event, data)
                else:
                    callback(event, data)
            except Exception as e:
                logger.error(f"Update callback error: {e}")
    
    async def check_all_updates(self) -> Dict[str, UpdateInfo]:
        """Check for updates for all components"""
        updates = {}
        
        for component, config in self.update_config.items():
            if not config.get("enabled", True):
                continue
            
            try:
                update_info = await self._check_component_update(component, config)
                if update_info:
                    updates[component] = update_info
            except Exception as e:
                logger.error(f"Update check failed for {component}: {e}")
        
        return updates
    
    async def _check_component_update(self, component: str, config: Dict) -> Optional[Any]:
        """Check for updates for a specific component"""
        if component == "cve_database":
            return await self._check_cve_update()
        elif component == "threat_intel_feeds":
            return await self._check_feed_updates()
        elif component == "geoip_database":
            return await self._check_geoip_update()
        elif component == "platform":
            return await self._check_platform_update()
        elif component == "plugins":
            return await self._check_plugin_updates()
        elif component == "geoip_database":
            return await self._check_geoip_update()
        return None
    
    async def _check_cve_update(self) -> Optional[Any]:
        """Check for CVE database updates"""
        try:
            async with aiohttp.ClientSession() as session:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.meta"
                    ) as resp:
                        if resp.status == 200:
                            meta = await resp.json()
                            # Compare with local version
                            return {
                                "component": "cve_database",
                                "latest_version": meta.get("version", "unknown"),
                                "release_date": meta.get("date"),
                                "download_url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
                            }
        except Exception as e:
            logger.error(f"CVE update check failed: {e}")
        return None
    
    async def _check_feed_updates(self) -> List[Dict]:
        """Check for feed updates"""
        updates = []
        for name, feed in self.platform.feed_sources.items():
            if feed.enabled:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.head(feed.url) as resp:
                            last_modified = resp.headers.get("Last-Modified")
                            etag = resp.headers.get("ETag")
                            if last_modified or etag:
                                updates.append({
                                    "feed": feed.name,
                                    "last_modified": last_modified,
                                    "etag": etag
                                })
                except:
                    pass
        return updates
    
    async def _check_geoip_update(self) -> Optional[Dict]:
        """Check for GeoIP database updates"""
        try:
            # Check MaxMind for updates
            return {"available": True, "edition": "GeoLite2-City"}
        except:
            return None
    
    async def _check_platform_update(self) -> Optional[Dict]:
        """Check for platform updates via GitHub"""
        try:
            async with aiohttp.ClientSession() as session:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        "https://api.github.com/repos/silver-scan/silver-scan/releases/latest"
                    ) as resp:
                        if resp.status == 200:
                            release = await resp.json()
                            return {
                                "component": "platform",
                                "latest_version": release.get("tag_name"),
                                "release_notes": release.get("body"),
                                "download_url": release.get("tarball_url"),
                                "published_at": release.get("published_at")
                            }
        except Exception as e:
            logger.error(f"Platform update check failed: {e}")
        return None
    
    async def _check_plugin_updates(self) -> List[Dict]:
        """Check for plugin updates"""
        updates = []
        # Check PyPI for plugin updates
        return updates
    
    async def _check_geoip_update(self) -> Optional[Dict]:
        """Check for GeoIP database updates"""
        return {"available": True, "edition": "GeoLite2-City"}
    
    async def apply_update(self, component: str, force: bool = False) -> bool:
        """Apply an update for a component"""
        status = UpdateStatus(
            component=component,
            status="installing",
            started_at=datetime.now()
        )
        self.update_status[component] = status
        
        await self._notify_update("update_started", {"component": component})
        
        try:
            if component == "cve_database":
                success = await self._update_cve_database()
            elif component == "threat_intel_feeds":
                success = await self._update_threat_intel_feeds()
            elif component == "geoip_database":
                success = await self._update_geoip_database()
            elif component == "platform":
                success = await self._update_platform()
            elif component == "geoip_database":
                success = await self._update_geoip_database()
            else:
                success = False
            
            status.status = "completed" if success else "failed"
            status.completed_at = datetime.now()
            status.progress = 1.0
            
            await self._notify_update("update_completed", {
                "component": component,
                "success": success
            })
            
            return success
            
        except Exception as e:
            status.status = "failed"
            status.error = str(e)
            status.completed_at = datetime.now()
            await self._notify_update("update_failed", {"component": component, "error": str(e)})
            return False
    
    async def _update_cve_database(self) -> bool:
        """Update CVE database from NVD"""
        try:
            async with aiohttp.ClientSession() as session:
                async with aiohttp.ClientSession() as session:
                    # Download recent CVEs
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
                        ) as resp:
                            if resp.status == 200:
                                content = await resp.read()
                                
                                # Save to file
                                async with aiofiles.open("/tmp/nvd_recent.json.gz", "wb") as f:
                                    await f.write(content)
                                
                                # Process and import
                                await self._import_cve_data(content)
                                
                                # Update platform database
                                await self.platform._sync_nvd_cves()
                                
                                return True
        except Exception as e:
            logger.error(f"CVE database update failed: {e}")
        return False
    
    async def _import_cve_data(self, content: bytes):
        """Import CVE data from NVD feed"""
        import gzip
        import json
        
        try:
            decompressed = gzip.decompress(content)
            data = json.loads(decompressed.decode('utf-8'))
            
            cve_items = data.get('CVE_Items', [])
            logger.info(f"Processing {len(cve_items)} CVEs")
            
            # Process in batches
            batch_size = 100
            for i in range(0, len(cve_items), batch_size):
                batch = cve_items[i:i+batch_size]
                await self._import_cve_batch(batch)
                
        except Exception as e:
            logger.error(f"CVE import failed: {e}")
    
    async def _import_cve_batch(self, batch: List):
        """Import a batch of CVEs"""
        # This would insert into the threat_intel table
        pass
    
    async def _update_threat_intel_feeds(self) -> bool:
        """Update threat intelligence feeds"""
        try:
            # Trigger feed refresh
            await self.platform.feed_manager.run_feeds()
            return True
        except Exception as e:
            logger.error(f"Threat intel feed update failed: {e}")
        return False
    
    async def _update_geoip_database(self) -> bool:
        """Update GeoIP database"""
        try:
            # Download MaxMind GeoLite2 database
            async with aiohttp.ClientSession() as session:
                url = "https://download.maxmind.com/app/geoip_download"
                params = {
                    "edition_id": "GeoLite2-City",
                    "license_key": self.platform.config.get("maxmind_license_key"),
                    "suffix": "tar.gz"
                }
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params) as resp:
                        if resp.status == 200:
                            content = await resp.read()
                            
                            # Save and extract
                            async with aiofiles.open("/tmp/GeoLite2-City.tar.gz", "wb") as f:
                                await f.write(content)
                            
                            # Extract
                            import tarfile
                            with tarfile.open("/tmp/GeoLite2-City.tar.gz", "r:gz") as tar:
                                tar.extractall("/usr/share/GeoIP/")
                            
                            return True
        except Exception as e:
            logger.error(f"GeoIP update failed: {e}")
        return False
    
    async def _update_platform(self) -> bool:
        """Update the platform itself"""
        try:
            # This would pull latest code and restart
            # For safety, this should be done externally
            logger.info("Platform update requested - should be handled by deployment system")
            return False
        except Exception as e:
            logger.error(f"Platform update failed: {e}")
        return False
    
    async def _update_geoip_database(self) -> bool:
        """Update GeoIP database"""
        return await self._update_geoip_database()
    
    def stop(self):
        self.running = False
        
        for task in self.update_tasks.values():
            task.cancel()
    
    def get_update_status(self, component: str = None) -> Dict:
        """Get update status for all or specific component"""
        if component:
            return self.update_status.get(component, {})
        return {k: v.__dict__ for k, v in self.update_status.items()}
    
    async def check_and_update_all(self) -> Dict[str, bool]:
        """Check and apply all available updates"""
        results = {}
        
        updates = await self.check_all_updates()
        
        for component, update_info in updates.items():
            if update_info:
                success = await self.apply_update(component)
                results[component] = success
        
        return results


class UpdateScheduler:
    """Schedule and manage updates"""
    
    def __init__(self, updater: AutoUpdater):
        self.updater = updater
        self.schedules: Dict[str, Dict] = {}
        self.jobs: Dict[str, asyncio.Task] = {}
    
    def add_schedule(self, name: str, component: str, cron_expression: str = None, interval: int = None):
        """Add update schedule"""
        self.schedules[name] = {
            "component": component,
            "cron": cron_expression,
            "interval": interval,
            "next_run": datetime.now()
        }
    
    async def start(self):
        """Start scheduler"""
        for name, schedule in self.schedules.items():
            self.jobs[name] = asyncio.create_task(self._run_job(name, schedule))
    
    async def _run_job(self, name: str, schedule: Dict):
        """Run scheduled job"""
        while True:
            try:
                if schedule.get("interval"):
                    await asyncio.sleep(schedule["interval"])
                elif schedule.get("cron"):
                    # Calculate next run time from cron
                    await asyncio.sleep(60)  # Check every minute
                    
                await self.updater.apply_update(schedule["component"])
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduled job {name} error: {e}")
                await asyncio.sleep(60)
    
    def stop(self):
        for job in self.jobs.values():
            job.cancel()