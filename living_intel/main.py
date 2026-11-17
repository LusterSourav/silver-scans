"""
Living Threat Intelligence Platform - Main Entry Point
Self-updating, plugin-based threat intelligence platform with live feeds
"""
import asyncio
import logging
import signal
import sys
import os
from typing import Dict, Any

from .platform import LivingIntelPlatform
from .api import create_app
from aiohttp import web


def setup_logging(level: str = "INFO"):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("/var/log/living_intel/platform.log") if os.path.exists("/var/log/living_intel") else logging.NullHandler()
        ]
    )


def get_config() -> Dict[str, Any]:
    """Get platform configuration from environment"""
    return {
        "postgres": os.getenv("DATABASE_URL"),
        "redis": os.getenv("REDIS_URL", "redis://localhost:6379"),
        "virustotal_api_key": os.getenv("VT_API_KEY"),
        "otx_api_key": os.getenv("OTX_API_KEY"),
        "github_token": os.getenv("GITHUB_TOKEN"),
        "misp_url": os.getenv("MISP_URL"),
        "misp_key": os.getenv("MISP_KEY"),
        "opencti_url": os.getenv("OPENCTI_URL"),
        "opencti_token": os.getenv("OPENCTI_TOKEN"),
        "taxii_url": os.getenv("TAXII_URL"),
        "taxii_user": os.getenv("TAXII_USER"),
        "taxii_pass": os.getenv("TAXII_PASS"),
        "maxmind_license_key": os.getenv("MAXMIND_LICENSE_KEY"),
        "hybrid_analysis_api_key": os.getenv("HYBRID_ANALYSIS_API_KEY"),
        "greynoise_api_key": os.getenv("GREYNOISE_API_KEY"),
        "shodan_api_key": os.getenv("SHODAN_API_KEY"),
        "passivetotal_username": os.getenv("PASSIVETOTAL_USERNAME"),
        "passivetotal_api_key": os.getenv("PASSIVETOTAL_API_KEY"),
        "host": os.getenv("LIVING_INTEL_HOST", "0.0.0.0"),
        "port": int(os.getenv("LIVING_INTEL_PORT", "8080")),
        "log_level": os.getenv("LOG_LEVEL", "INFO")
    }


async def main():
    """Main entry point"""
    config = get_config()
    setup_logging(config["log_level"])
    
    logger = logging.getLogger(__name__)
    logger.info("Starting Living Threat Intelligence Platform")
    
    # Create platform
    platform = LivingIntelPlatform(config)
    
    try:
        # Initialize platform
        await platform.initialize()
        
        # Start platform (feeds, live feeds, auto-updater)
        await platform.start()
        
        # Create web application
        app = create_app(platform)
        import time
        platform.metrics["start_time"] = time.time()
        
        # Setup signal handlers
        loop = asyncio.get_event_loop()
        
        def signal_handler():
            logger.info("Shutdown signal received")
            asyncio.create_task(shutdown(platform, runner))
        
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, signal_handler)
        
        # Start web server
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, config["host"], config["port"])
        await site.start()
        
        logger.info(f"Living Intel Platform API running on http://{config['host']}:{config['port']}")
        
        # Keep running
        await asyncio.Event().wait()
        
    except Exception as e:
        logger.error(f"Platform error: {e}")
        raise
    finally:
        await platform.stop()


async def shutdown(platform: LivingIntelPlatform, runner: web.AppRunner):
    """Graceful shutdown"""
    logger = logging.getLogger(__name__)
    logger.info("Shutting down...")
    
    await runner.cleanup()
    await platform.stop()
    
    logger.info("Shutdown complete")
    asyncio.get_event_loop().stop()


if __name__ == "__main__":
    asyncio.run(main())