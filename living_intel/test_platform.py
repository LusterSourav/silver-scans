"""
Tests for Living Threat Intelligence Platform
"""
import asyncio
import pytest
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from living_intel import (
    LivingIntelPlatform, ThreatIntelItem, FeedSource, ThreatIntelPlugin,
    FeedManager, PluginManager, PluginInfo,
    LiveFeedManager, LiveFeedSource, FeedProtocol,
    GeoIPEnrichmentPlugin, VirusTotalEnrichmentPlugin, ThreatFoxEnrichmentPlugin,
    ENRICHMENT_PLUGINS
)


@pytest.fixture
def platform_config():
    return {
        "postgres": None,
        "redis": None,
        "virustotal_api_key": "test_key",
        "otx_api_key": "test_key"
    }


@pytest.fixture
def platform(platform_config):
    platform = LivingIntelPlatform(platform_config)
    platform.db_pool = None
    platform.redis = None
    yield platform


class TestThreatIntelItem:
    def test_create_item(self):
        item = ThreatIntelItem(
            id="test123",
            type="ipv4",
            value="1.2.3.4",
            confidence=0.9,
            severity="HIGH",
            source="test",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            tags=["test"],
            context={},
            tlp="WHITE"
        )
        assert item.id == "test123"
        assert item.type == "ipv4"
        assert item.value == "1.2.3.4"
        assert item.confidence == 0.9


class TestFeedManager:
    @pytest.fixture
    def feed_manager(self, platform):
        return FeedManager(platform)

    def test_register_parsers(self, feed_manager):
        assert "json" in feed_manager.parsers
        assert "csv" in feed_manager.parsers
        assert "txt" in feed_manager.parsers
        assert "alienvault_otx" in feed_manager.parsers

    @pytest.mark.asyncio
    async def test_parse_json(self, feed_manager):
        feed = FeedSource(name="test", url="http://test.com", type="json", parser="json")
        content = b'[{"ip": "1.2.3.4"}, {"domain": "example.com"}]'
        items = await feed_manager._parse_json(content, feed)
        assert len(items) == 2
        assert items[0]["value"] == "1.2.3.4"
        assert items[1]["value"] == "example.com"

    @pytest.mark.asyncio
    async def test_parse_csv(self, feed_manager):
        feed = FeedSource(name="test", url="http://test.com", type="csv", parser="csv")
        content = b"ip,port\n1.2.3.4,443\n5.6.7.8,80"
        items = await feed_manager._parse_csv(content, feed)
        assert len(items) == 2

    @pytest.mark.asyncio
    async def test_parse_txt(self, feed_manager):
        feed = FeedSource(name="test", url="http://test.com", type="txt", parser="txt")
        content = b"1.2.3.4\n5.6.7.8\n# comment\n"
        items = await feed_manager._parse_txt(content, feed)
        assert len(items) == 2

    def test_guess_ioc_type(self, feed_manager):
        assert feed_manager._guess_ioc_type("1.2.3.4") == "ipv4"
        assert feed_manager._guess_ioc_type("example.com") == "domain"
        assert feed_manager._guess_ioc_type("http://example.com") == "url"
        assert feed_manager._guess_ioc_type("a" * 32) == "md5"
        assert feed_manager._guess_ioc_type("a" * 40) == "sha1"
        assert feed_manager._guess_ioc_type("a" * 64) == "sha256"

    def test_validate_ioc(self, feed_manager):
        assert feed_manager._validate_ioc("ipv4", "1.2.3.4") is True
        assert feed_manager._validate_ioc("ipv4", "999.999.999.999") is False
        assert feed_manager._validate_ioc("domain", "example.com") is True
        assert feed_manager._validate_ioc("domain", "invalid") is False
        assert feed_manager._validate_ioc("md5", "a" * 32) is True
        assert feed_manager._validate_ioc("sha256", "a" * 64) is True
        assert feed_manager._validate_ioc("url", "http://example.com") is True
        assert feed_manager._validate_ioc("url", "ftp://example.com") is False


class TestLiveFeedManager:
    @pytest.fixture
    def live_feed_manager(self, platform):
        manager = LiveFeedManager(platform)
        # Add a test feed source
        manager.feed_sources["test"] = LiveFeedSource(
            name="test",
            url="http://test.com",
            protocol=FeedProtocol.HTTP_POLL,
            tags=["test_tag"]
        )
        return manager

    def test_register_live_feeds(self, live_feed_manager):
        assert "alienvault_otx_pulses" in live_feed_manager.feed_sources
        assert "urlhaus_recent" in live_feed_manager.feed_sources
        assert "cisa_kev_live" in live_feed_manager.feed_sources

    def test_feed_protocols(self, live_feed_manager):
        feed = live_feed_manager.feed_sources["alienvault_otx_pulses"]
        assert feed.protocol == FeedProtocol.HTTP_POLL
        assert feed.interval == 300

    @pytest.mark.asyncio
    async def test_normalize_event_ip(self, live_feed_manager):
        from living_intel.live_feeds import LiveFeedEvent
        event = LiveFeedEvent(
            feed_name="test",
            event_id="evt1",
            timestamp=datetime.now(),
            event_type="indicator",
            data={"ip": "1.2.3.4", "tags": ["malware"]}
        )
        item = live_feed_manager._normalize_event(event)
        assert item is not None
        assert item.type == "ipv4"
        assert item.value == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_normalize_event_domain(self, live_feed_manager):
        from living_intel.live_feeds import LiveFeedEvent
        event = LiveFeedEvent(
            feed_name="test",
            event_id="evt1",
            timestamp=datetime.now(),
            event_type="indicator",
            data={"domain": "example.com"}
        )
        item = live_feed_manager._normalize_event(event)
        assert item is not None
        assert item.type == "domain"
        assert item.value == "example.com"

    @pytest.mark.asyncio
    async def test_normalize_event_hash(self, live_feed_manager):
        from living_intel.live_feeds import LiveFeedEvent
        event = LiveFeedEvent(
            feed_name="test",
            event_id="evt1",
            timestamp=datetime.now(),
            event_type="indicator",
            data={"sha256": "a" * 64}
        )
        item = live_feed_manager._normalize_event(event)
        assert item is not None
        assert item.type == "sha256"
        assert item.value == "a" * 64


class TestEnrichmentPlugins:
    @pytest.fixture
    def mock_platform(self):
        platform = MagicMock()
        platform.config = {
            "virustotal_api_key": "test_key",
            "otx_api_key": "test_key"
        }
        return platform

    @pytest.mark.asyncio
    async def test_virustotal_plugin_init(self, mock_platform):
        plugin = VirusTotalEnrichmentPlugin(mock_platform)
        await plugin.initialize()
        assert plugin.name == "VirusTotalEnrichment"
        assert plugin.api_key == "test_key"

    @pytest.mark.asyncio
    async def test_threatfox_plugin_init(self, mock_platform):
        plugin = ThreatFoxEnrichmentPlugin(mock_platform)
        await plugin.initialize()
        assert plugin.name == "ThreatFoxEnrichment"

    def test_enrichment_plugins_registry(self):
        assert "virustotal" in ENRICHMENT_PLUGINS
        assert "threatfox" in ENRICHMENT_PLUGINS
        assert "geoip" in ENRICHMENT_PLUGINS
        assert "misp" in ENRICHMENT_PLUGINS
        assert "abuse_ch" in ENRICHMENT_PLUGINS
        assert "hybrid_analysis" in ENRICHMENT_PLUGINS
        assert "greynoise" in ENRICHMENT_PLUGINS
        assert "shodan" in ENRICHMENT_PLUGINS
        assert "passivetotal" in ENRICHMENT_PLUGINS
        assert "alienvault_otx" in ENRICHMENT_PLUGINS
        assert "circl" in ENRICHMENT_PLUGINS
        assert "cisco_talos" in ENRICHMENT_PLUGINS


class TestPluginManager:
    @pytest.fixture
    def plugin_manager(self, platform):
        return PluginManager(platform)

    def test_hook_points(self, plugin_manager):
        assert "on_startup" in plugin_manager.hook_points
        assert "on_shutdown" in plugin_manager.hook_points
        assert "on_ingest" in plugin_manager.hook_points
        assert "on_enrich" in plugin_manager.hook_points
        assert "on_alert" in plugin_manager.hook_points
        assert "on_hunt" in plugin_manager.hook_points


class TestPlatformIntegration:
    @pytest.mark.asyncio
    async def test_platform_initialization(self, platform):
        # Components are initialized in initialize() method
        assert platform is not None
        assert platform.config is not None
        # Check attributes exist (initialized to None)
        assert hasattr(platform, 'feed_manager')
        assert hasattr(platform, 'plugin_manager')
        assert hasattr(platform, 'auto_updater')
        assert hasattr(platform, 'live_feed_manager')

    @pytest.mark.asyncio
    async def test_ingest_threat_item(self, platform):
        # Mock the db_pool acquire to return a proper async context manager
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(return_value=None)
        
        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(return_value=AsyncContextManager(mock_conn))
        platform.db_pool = mock_pool
        
        item = ThreatIntelItem(
            id="test123",
            type="ipv4",
            value="1.2.3.4",
            confidence=0.9,
            severity="HIGH",
            source="test",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            tags=["test"],
            context={},
            tlp="WHITE"
        )
        
        result = await platform.ingest_threat_item(item)
        assert result is True
        mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_query_threat_intel(self, platform):
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[{"id": "1", "type": "ipv4", "value": "1.2.3.4"}])
        
        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(return_value=AsyncContextManager(mock_conn))
        platform.db_pool = mock_pool
        
        results = await platform.query_threat_intel({"type": "ipv4"})
        assert len(results) == 1
        assert results[0]["value"] == "1.2.3.4"


class AsyncContextManager:
    """Helper to create async context manager for mocking"""
    def __init__(self, obj):
        self.obj = obj
    
    async def __aenter__(self):
        return self.obj
    
    async def __aexit__(self, *args):
        pass


class TestAutoUpdater:
    @pytest.fixture
    def auto_updater(self, platform):
        from living_intel.auto_updater import AutoUpdater
        return AutoUpdater(platform)

    def test_update_config(self, auto_updater):
        assert "cve_database" in auto_updater.update_config
        assert "threat_intel_feeds" in auto_updater.update_config
        assert "geoip_database" in auto_updater.update_config
        assert "platform" in auto_updater.update_config
        assert "plugins" in auto_updater.update_config

    @pytest.mark.asyncio
    async def test_check_all_updates(self, auto_updater):
        auto_updater._check_component_update = AsyncMock(return_value=None)
        updates = await auto_updater.check_all_updates()
        assert isinstance(updates, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])