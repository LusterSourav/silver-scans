"""
REST API for Living Threat Intelligence Platform
Exposes threat intelligence queries, feed management, and enrichment
"""
import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import asdict

from aiohttp import web
import aiohttp_cors

logger = logging.getLogger(__name__)


def create_app(platform) -> web.Application:
    """Create aiohttp application with Living Intel API routes"""
    app = web.Application()
    
    # Setup CORS
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
            allow_methods="*"
        )
    })
    
    # Store platform reference
    app["platform"] = platform
    
    # Routes
    routes = [
        web.get("/api/v1/health", health),
        web.get("/api/v1/metrics", metrics),
        
        # Threat Intelligence queries
        web.post("/api/v1/threat-intel/query", query_threat_intel),
        web.get("/api/v1/threat-intel/search/{ioc_type}/{value}", search_iocs),
        web.get("/api/v1/threat-intel/stats", threat_intel_stats),
        
        # Feed management
        web.get("/api/v1/feeds", list_feeds),
        web.get("/api/v1/feeds/{name}", get_feed),
        web.post("/api/v1/feeds", create_feed),
        web.put("/api/v1/feeds/{name}", update_feed),
        web.delete("/api/v1/feeds/{name}", delete_feed),
        web.post("/api/v1/feeds/{name}/enable", enable_feed),
        web.post("/api/v1/feeds/{name}/disable", disable_feed),
        web.post("/api/v1/feeds/{name}/refresh", refresh_feed),
        
        # Live feeds
        web.get("/api/v1/live-feeds", list_live_feeds),
        web.get("/api/v1/live-feeds/{name}", get_live_feed),
        web.get("/api/v1/live-feeds/metrics", live_feed_metrics),
        web.post("/api/v1/live-feeds", create_live_feed),
        web.delete("/api/v1/live-feeds/{name}", delete_live_feed),
        
        # Enrichment
        web.post("/api/v1/enrich", enrich_ioc),
        web.get("/api/v1/enrich/plugins", list_enrichment_plugins),
        web.post("/api/v1/enrich/bulk", bulk_enrich),
        
        # Auto-updater
        web.get("/api/v1/updates", check_updates),
        web.post("/api/v1/updates/{component}", apply_update),
        web.get("/api/v1/updates/status", update_status),
        
        # Plugins
        web.get("/api/v1/plugins", list_plugins),
        web.get("/api/v1/plugins/{name}", get_plugin),
        web.post("/api/v1/plugins/{name}/enable", enable_plugin),
        web.post("/api/v1/plugins/{name}/disable", disable_plugin),
        web.post("/api/v1/plugins/{name}/reload", reload_plugin),
        
        # Threat hunting
        web.post("/api/v1/hunt", threat_hunt),
        
        # Export
        web.get("/api/v1/export/stix", export_stix),
        web.get("/api/v1/export/misp", export_misp),
        web.get("/api/v1/export/csv", export_csv),
    ]
    
    for route in routes:
        cors.add(app.router.add_route(route.method, route.path, route.handler))
    
    return app


# Health and Metrics
async def health(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    start_time = platform.metrics.get("start_time")
    if isinstance(start_time, float):
        import time
        uptime = time.time() - start_time
    else:
        uptime = (datetime.now() - (start_time or datetime.now())).total_seconds()
    
    health_data = {
        "status": "healthy" if platform.running else "stopped",
        "timestamp": datetime.now().isoformat(),
        "database": "connected" if platform.db_pool else "disconnected",
        "redis": "connected" if platform.redis else "disconnected",
        "feeds": len([f for f in platform.feed_sources.values() if f.enabled]),
        "live_feeds": len([f for f in platform.live_feed_manager.feed_sources.values() if f.enabled]),
        "plugins": len(platform.plugin_manager.plugins),
        "uptime_seconds": uptime
    }
    return web.json_response(health_data)


async def metrics(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    return web.json_response(platform.get_metrics())


# Threat Intelligence Queries
async def query_threat_intel(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    try:
        query = await request.json()
        results = await platform.query_threat_intel(query)
        return web.json_response({"results": results, "count": len(results)})
    except Exception as e:
        logger.error(f"Query error: {e}")
        return web.json_response({"error": str(e)}, status=400)


async def search_iocs(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    ioc_type = request.match_info["ioc_type"]
    value = request.match_info["value"]
    results = await platform.search_iocs(ioc_type, value)
    return web.json_response({"results": results, "count": len(results)})


async def threat_intel_stats(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    if not platform.db_pool:
        return web.json_response({"error": "Database not configured"}, status=503)
    
    try:
        async with platform.db_pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM threat_intel")
            by_type = await conn.fetch("SELECT type, COUNT(*) as count FROM threat_intel GROUP BY type")
            by_source = await conn.fetch("SELECT source, COUNT(*) as count FROM threat_intel GROUP BY source ORDER BY count DESC LIMIT 20")
            by_severity = await conn.fetch("SELECT severity, COUNT(*) as count FROM threat_intel GROUP BY severity")
            recent = await conn.fetchval("SELECT COUNT(*) FROM threat_intel WHERE last_seen > NOW() - INTERVAL '24 hours'")
        
        return web.json_response({
            "total": total,
            "recent_24h": recent,
            "by_type": [dict(row) for row in by_type],
            "by_source": [dict(row) for row in by_source],
            "by_severity": [dict(row) for row in by_severity]
        })
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return web.json_response({"error": str(e)}, status=500)


# Feed Management
async def list_feeds(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    return web.json_response(platform.get_feed_status())


async def get_feed(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    feed = platform.feed_sources.get(name)
    if not feed:
        return web.json_response({"error": "Feed not found"}, status=404)
    return web.json_response({
        "name": feed.name,
        "url": feed.url,
        "type": feed.type,
        "parser": feed.parser,
        "enabled": feed.enabled,
        "interval": feed.interval,
        "tags": feed.tags,
        "last_update": feed.last_update.isoformat() if feed.last_update else None,
        "error_count": feed.error_count
    })


async def create_feed(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    try:
        data = await request.json()
        from .platform import FeedSource
        feed = FeedSource(
            name=data["name"],
            url=data["url"],
            type=data.get("type", "json"),
            auth=data.get("auth", {}),
            headers=data.get("headers", {}),
            parser=data.get("parser", "auto"),
            enabled=data.get("enabled", True),
            interval=data.get("interval", 3600),
            tlp=data.get("tlp", "WHITE"),
            tags=data.get("tags", []),
            filters=data.get("filters", {})
        )
        platform.feed_sources[feed.name] = feed
        
        # Save to database
        if platform.db_pool:
            async with platform.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO feed_sources (name, url, type, auth, headers, parser, enabled, interval, tlp, tags, filters)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    ON CONFLICT (name) DO UPDATE SET
                        url = EXCLUDED.url,
                        type = EXCLUDED.type,
                        auth = EXCLUDED.auth,
                        headers = EXCLUDED.headers,
                        parser = EXCLUDED.parser,
                        enabled = EXCLUDED.enabled,
                        interval = EXCLUDED.interval,
                        tlp = EXCLUDED.tlp,
                        tags = EXCLUDED.tags,
                        filters = EXCLUDED.filters,
                        updated_at = NOW()
                """, feed.name, feed.url, feed.type, 
                json.dumps(feed.auth), json.dumps(feed.headers), feed.parser,
                feed.enabled, feed.interval, feed.tlp, feed.tags, json.dumps(feed.filters))
        
        return web.json_response({"status": "created", "feed": feed.name})
    except Exception as e:
        logger.error(f"Create feed error: {e}")
        return web.json_response({"error": str(e)}, status=400)


async def update_feed(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    feed = platform.feed_sources.get(name)
    if not feed:
        return web.json_response({"error": "Feed not found"}, status=404)
    
    try:
        data = await request.json()
        for key, value in data.items():
            if hasattr(feed, key) and key != "name":
                setattr(feed, key, value)
        
        # Update database
        if platform.db_pool:
            async with platform.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE feed_sources SET
                        url = $1, type = $2, auth = $3, headers = $4, parser = $5,
                        enabled = $6, interval = $7, tlp = $8, tags = $9, filters = $10,
                        updated_at = NOW()
                    WHERE name = $11
                """, feed.url, feed.type, json.dumps(feed.auth), json.dumps(feed.headers),
                feed.parser, feed.enabled, feed.interval, feed.tlp, feed.tags,
                json.dumps(feed.filters), name)
        
        return web.json_response({"status": "updated", "feed": name})
    except Exception as e:
        logger.error(f"Update feed error: {e}")
        return web.json_response({"error": str(e)}, status=400)


async def delete_feed(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    if name not in platform.feed_sources:
        return web.json_response({"error": "Feed not found"}, status=404)
    
    del platform.feed_sources[name]
    
    if platform.db_pool:
        async with platform.db_pool.acquire() as conn:
            await conn.execute("DELETE FROM feed_sources WHERE name = $1", name)
    
    return web.json_response({"status": "deleted", "feed": name})


async def enable_feed(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    feed = platform.feed_sources.get(name)
    if not feed:
        return web.json_response({"error": "Feed not found"}, status=404)
    
    feed.enabled = True
    return web.json_response({"status": "enabled", "feed": name})


async def disable_feed(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    feed = platform.feed_sources.get(name)
    if not feed:
        return web.json_response({"error": "Feed not found"}, status=404)
    
    feed.enabled = False
    return web.json_response({"status": "disabled", "feed": name})


async def refresh_feed(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    feed = platform.feed_sources.get(name)
    if not feed:
        return web.json_response({"error": "Feed not found"}, status=404)
    
    try:
        await platform.feed_manager._process_feed(feed)
        return web.json_response({"status": "refreshed", "feed": name})
    except Exception as e:
        logger.error(f"Refresh feed error: {e}")
        return web.json_response({"error": str(e)}, status=500)


# Live Feeds
async def list_live_feeds(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    return web.json_response(platform.get_live_feed_status())


async def get_live_feed(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    feed = platform.live_feed_manager.feed_sources.get(name)
    if not feed:
        return web.json_response({"error": "Live feed not found"}, status=404)
    
    return web.json_response({
        "name": feed.name,
        "url": feed.url,
        "protocol": feed.protocol.value,
        "enabled": feed.enabled,
        "interval": feed.interval,
        "tags": feed.tags,
        "connection_state": feed.connection_state,
        "last_update": feed.last_update.isoformat() if feed.last_update else None,
        "error_count": feed.error_count,
        "last_event_id": feed.last_event_id
    })


async def live_feed_metrics(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    return web.json_response(platform.get_live_feed_metrics())


async def create_live_feed(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    try:
        data = await request.json()
        from .live_feeds import LiveFeedSource, FeedProtocol
        feed = LiveFeedSource(
            name=data["name"],
            url=data["url"],
            protocol=FeedProtocol(data.get("protocol", "http_poll")),
            auth=data.get("auth", {}),
            headers=data.get("headers", {}),
            parser=data.get("parser", "auto"),
            enabled=data.get("enabled", True),
            interval=data.get("interval", 60),
            tlp=data.get("tlp", "WHITE"),
            tags=data.get("tags", []),
            filters=data.get("filters", {})
        )
        await platform.add_live_feed(feed)
        return web.json_response({"status": "created", "feed": feed.name})
    except Exception as e:
        logger.error(f"Create live feed error: {e}")
        return web.json_response({"error": str(e)}, status=400)


async def delete_live_feed(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    await platform.remove_live_feed(name)
    return web.json_response({"status": "deleted", "feed": name})


# Enrichment
async def enrich_ioc(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    try:
        data = await request.json()
        ioc_type = data.get("type")
        value = data.get("value")
        
        if not ioc_type or not value:
            return web.json_response({"error": "type and value required"}, status=400)
        
        from .platform import ThreatIntelItem
        item = ThreatIntelItem(
            id=f"api:{ioc_type}:{value}",
            type=ioc_type,
            value=value,
            confidence=0.5,
            severity="UNKNOWN",
            source="api",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            tags=["api_enrichment"],
            context={},
            tlp="WHITE"
        )
        
        # Run enrichment
        item = await platform.plugin_manager.enrich_item(item)
        
        return web.json_response({
            "type": item.type,
            "value": item.value,
            "context": item.context
        })
    except Exception as e:
        logger.error(f"Enrich error: {e}")
        return web.json_response({"error": str(e)}, status=400)


async def list_enrichment_plugins(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    return web.json_response({"plugins": platform.get_enrichment_plugins()})


async def bulk_enrich(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    try:
        data = await request.json()
        iocs = data.get("iocs", [])
        
        results = []
        for ioc in iocs:
            ioc_type = ioc.get("type")
            value = ioc.get("value")
            if not ioc_type or not value:
                continue
            
            from .platform import ThreatIntelItem
            item = ThreatIntelItem(
                id=f"bulk:{ioc_type}:{value}",
                type=ioc_type,
                value=value,
                confidence=0.5,
                severity="UNKNOWN",
                source="api",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                tags=["bulk_enrichment"],
                context={},
                tlp="WHITE"
            )
            
            item = await platform.plugin_manager.enrich_item(item)
            results.append({
                "type": item.type,
                "value": item.value,
                "context": item.context
            })
        
        return web.json_response({"results": results, "count": len(results)})
    except Exception as e:
        logger.error(f"Bulk enrich error: {e}")
        return web.json_response({"error": str(e)}, status=400)


# Auto-updater
async def check_updates(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    updates = await platform.auto_updater.check_all_updates()
    return web.json_response({"updates": updates})


async def apply_update(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    component = request.match_info["component"]
    force = request.query.get("force", "false").lower() == "true"
    
    success = await platform.auto_updater.apply_update(component, force)
    return web.json_response({"component": component, "success": success})


async def update_status(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    return web.json_response(platform.auto_updater.get_update_status())


# Plugins
async def list_plugins(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    plugins = platform.plugin_manager.list_plugins()
    return web.json_response({"plugins": [asdict(p) for p in plugins]})


async def get_plugin(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    plugin_info = platform.plugin_manager.get_plugin_info(name)
    if not plugin_info:
        return web.json_response({"error": "Plugin not found"}, status=404)
    return web.json_response(asdict(plugin_info))


async def enable_plugin(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    success = platform.plugin_manager.enable_plugin(name)
    if not success:
        return web.json_response({"error": "Plugin not found"}, status=404)
    return web.json_response({"status": "enabled", "plugin": name})


async def disable_plugin(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    success = platform.plugin_manager.disable_plugin(name)
    if not success:
        return web.json_response({"error": "Plugin not found"}, status=404)
    return web.json_response({"status": "disabled", "plugin": name})


async def reload_plugin(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    name = request.match_info["name"]
    success = await platform.plugin_manager.reload_plugin(name)
    if not success:
        return web.json_response({"error": "Plugin not found or reload failed"}, status=404)
    return web.json_response({"status": "reloaded", "plugin": name})


# Threat Hunting
async def threat_hunt(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    try:
        query = await request.json()
        results = await platform.plugin_manager.run_hunt(query)
        return web.json_response({
            "results": [asdict(r) for r in results],
            "count": len(results)
        })
    except Exception as e:
        logger.error(f"Hunt error: {e}")
        return web.json_response({"error": str(e)}, status=400)


# Export
async def export_stix(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    # Query parameters
    limit = int(request.query.get("limit", "1000"))
    since = request.query.get("since")
    
    query = {"limit": limit}
    if since:
        query["since"] = since
    
    items = await platform.query_threat_intel(query)
    
    # Convert to STIX 2.1 bundle
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:16]}",
        "spec_version": "2.1",
        "objects": []
    }
    
    for item in items:
        stix_obj = _item_to_stix(item)
        if stix_obj:
            stix_bundle["objects"].append(stix_obj)
    
    return web.json_response(stix_bundle)


async def export_misp(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    limit = int(request.query.get("limit", "1000"))
    since = request.query.get("since")
    
    query = {"limit": limit}
    if since:
        query["since"] = since
    
    items = await platform.query_threat_intel(query)
    
    # Convert to MISP format
    misp_events = []
    for item in items:
        misp_events.append(_item_to_misp(item))
    
    return web.json_response({"events": misp_events})


async def export_csv(request: web.Request) -> web.Response:
    platform = request.app["platform"]
    limit = int(request.query.get("limit", "1000"))
    since = request.query.get("since")
    
    query = {"limit": limit}
    if since:
        query["since"] = since
    
    items = await platform.query_threat_intel(query)
    
    # Generate CSV
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "type", "value", "confidence", "severity", "source", "first_seen", "last_seen", "tags", "tlp"])
    
    for item in items:
        writer.writerow([
            item.get("id", ""),
            item.get("type", ""),
            item.get("value", ""),
            item.get("confidence", ""),
            item.get("severity", ""),
            item.get("source", ""),
            item.get("first_seen", ""),
            item.get("last_seen", ""),
            ";".join(item.get("tags", [])),
            item.get("tlp", "")
        ])
    
    return web.Response(
        text=output.getvalue(),
        content_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threat_intel_export.csv"}
    )


def _item_to_stix(item: Dict) -> Optional[Dict]:
    """Convert ThreatIntelItem to STIX 2.1 object"""
    import hashlib
    
    ioc_type = item.get("type", "")
    value = item.get("value", "")
    
    if ioc_type in ["ipv4", "ipv6"]:
        return {
            "type": "ipv4-addr" if ioc_type == "ipv4" else "ipv6-addr",
            "spec_version": "2.1",
            "id": f"ipv4-addr--{hashlib.md5(value.encode()).hexdigest()[:16]}" if ioc_type == "ipv4" else f"ipv6-addr--{hashlib.md5(value.encode()).hexdigest()[:16]}",
            "value": value,
            "labels": ["malicious"] if item.get("severity") in ["HIGH", "CRITICAL"] else ["suspicious"],
            "confidence": int(item.get("confidence", 0.5) * 100),
            "created": item.get("first_seen", datetime.now().isoformat()),
            "modified": item.get("last_seen", datetime.now().isoformat())
        }
    elif ioc_type == "domain":
        return {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": f"domain-name--{hashlib.md5(value.encode()).hexdigest()[:16]}",
            "value": value,
            "labels": ["malicious"] if item.get("severity") in ["HIGH", "CRITICAL"] else ["suspicious"],
            "confidence": int(item.get("confidence", 0.5) * 100),
            "created": item.get("first_seen", datetime.now().isoformat()),
            "modified": item.get("last_seen", datetime.now().isoformat())
        }
    elif ioc_type == "url":
        return {
            "type": "url",
            "spec_version": "2.1",
            "id": f"url--{hashlib.md5(value.encode()).hexdigest()[:16]}",
            "value": value,
            "labels": ["malicious"] if item.get("severity") in ["HIGH", "CRITICAL"] else ["suspicious"],
            "confidence": int(item.get("confidence", 0.5) * 100),
            "created": item.get("first_seen", datetime.now().isoformat()),
            "modified": item.get("last_seen", datetime.now().isoformat())
        }
    elif ioc_type in ["hash", "md5", "sha1", "sha256", "sha512"]:
        hash_type = "MD5" if ioc_type == "md5" else "SHA-1" if ioc_type == "sha1" else "SHA-256" if ioc_type == "sha256" else "SHA-512"
        return {
            "type": "file",
            "spec_version": "2.1",
            "id": f"file--{hashlib.md5(value.encode()).hexdigest()[:16]}",
            "hashes": {hash_type.lower(): value},
            "labels": ["malicious"] if item.get("severity") in ["HIGH", "CRITICAL"] else ["suspicious"],
            "confidence": int(item.get("confidence", 0.5) * 100),
            "created": item.get("first_seen", datetime.now().isoformat()),
            "modified": item.get("last_seen", datetime.now().isoformat())
        }
    elif ioc_type == "cve":
        return {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": f"vulnerability--{hashlib.md5(value.encode()).hexdigest()[:16]}",
            "name": value,
            "description": item.get("context", {}).get("description", ""),
            "labels": ["exploited"] if item.get("tags", []).count("exploited") else ["vulnerability"],
            "confidence": int(item.get("confidence", 0.5) * 100),
            "created": item.get("first_seen", datetime.now().isoformat()),
            "modified": item.get("last_seen", datetime.now().isoformat())
        }
    return None


def _item_to_misp(item: Dict) -> Dict:
    """Convert ThreatIntelItem to MISP attribute format"""
    type_mapping = {
        "ipv4": "ip-src",
        "ipv6": "ip-src",
        "domain": "domain",
        "url": "url",
        "hash": "sha256",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "sha512": "sha512",
        "email": "email-src",
        "cve": "vulnerability"
    }
    
    return {
        "type": type_mapping.get(item.get("type", ""), "text"),
        "value": item.get("value", ""),
        "category": "Network activity" if item.get("type", "") in ["ipv4", "ipv6", "domain", "url"] else "Payload delivery" if item.get("type", "") in ["hash", "md5", "sha1", "sha256", "sha512"] else "Other",
        "to_ids": True,
        "comment": f"Source: {item.get('source', 'unknown')}, Confidence: {item.get('confidence', 0)}",
        "tags": item.get("tags", []),
        "timestamp": item.get("first_seen", ""),
        "last_seen": item.get("last_seen", "")
    }


import hashlib