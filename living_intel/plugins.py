"""
Plugin Management System
Dynamic plugin loading, management, and sandboxing for threat intelligence
"""
import asyncio
import logging
import importlib
import importlib.util
import inspect
import sys
import os
import pkgutil
from typing import Dict, List, Optional, Any, Callable, Type
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import importlib.metadata

logger = logging.getLogger(__name__)


@dataclass
class PluginInfo:
    """Plugin metadata"""
    name: str
    version: str
    description: str
    author: str
    entry_point: str
    config_schema: Dict = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    enabled: bool = True
    loaded_at: Optional[datetime] = None
    health: str = "unknown"


class PluginManager:
    """
    Dynamic plugin management system
    Supports hot-loading, hot-reloading, and sandboxed execution
    """
    
    def __init__(self, platform):
        self.platform = platform
        self.plugins: Dict[str, Any] = {}
        self.plugin_info: Dict[str, PluginInfo] = {}
        self.plugin_dirs: List[Path] = [
            Path(__file__).parent / "builtin_plugins",
            Path("/etc/living_intel/plugins"),
            Path.home() / ".living_intel" / "plugins"
        ]
        self.hook_points = {
            "on_startup": [],
            "on_shutdown": [],
            "on_ingest": [],
            "on_enrich": [],
            "on_alert": [],
            "on_hunt": [],
            "on_feed_processed": [],
            "on_schedule": []
        }
    
    async def load_plugins(self):
        """Load all plugins from plugin directories"""
        # Load built-in plugins first
        await self._load_builtin_plugins()
        
        # Load external plugins
        for plugin_dir in self.plugin_dirs:
            if plugin_dir.exists():
                await self._load_plugins_from_dir(plugin_dir)
        
        logger.info(f"Loaded {len(self.plugins)} plugins")
    
    async def _load_builtin_plugins(self):
        """Load built-in enrichment plugins"""
        from .enrichment import (
            GeoIPEnrichmentPlugin,
            VirusTotalEnrichmentPlugin,
            ThreatFoxEnrichmentPlugin,
            MISPEnrichmentPlugin,
            AbuseCHEnrichmentPlugin,
            HybridAnalysisEnrichmentPlugin,
            GreyNoiseEnrichmentPlugin,
            ShodanEnrichmentPlugin,
            PassiveTotalEnrichmentPlugin,
            AlienVaultOTXEnrichmentPlugin
        )
        
        builtin_plugins = [
            GeoIPEnrichmentPlugin,
            VirusTotalEnrichmentPlugin,
            ThreatFoxEnrichmentPlugin,
            MISPEnrichmentPlugin,
            AbuseCHEnrichmentPlugin,
            HybridAnalysisEnrichmentPlugin,
            GreyNoiseEnrichmentPlugin,
            ShodanEnrichmentPlugin,
            PassiveTotalEnrichmentPlugin,
            AlienVaultOTXEnrichmentPlugin
        ]
        
        for plugin_class in builtin_plugins:
            try:
                plugin = plugin_class(self.platform)
                await self._register_plugin(plugin)
            except Exception as e:
                logger.error(f"Failed to load builtin plugin {plugin_class.__name__}: {e}")
    
    async def _load_plugins_from_dir(self, plugin_dir: Path):
        """Load plugins from a directory"""
        for item in plugin_dir.iterdir():
            if item.is_dir() and (item / "__init__.py").exists():
                await self._load_plugin_from_dir(item)
            elif item.suffix == ".py" and not item.name.startswith("_"):
                await self._load_plugin_from_file(item)
    
    async def _load_plugin_from_dir(self, plugin_dir: Path):
        """Load plugin from directory"""
        try:
            # Check for plugin manifest
            manifest_path = plugin_dir / "plugin.json"
            if manifest_path.exists():
                with open(manifest_path) as f:
                    manifest = json.load(manifest_path)
                
                module_name = manifest.get("entry_point", plugin_dir.name)
                spec = importlib.util.spec_from_file_location(
                    module_name, 
                    plugin_dir / f"{module_name}.py"
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)
                    
                    # Find plugin class
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, ThreatIntelPlugin) and obj != ThreatIntelPlugin:
                            plugin = obj(self.platform)
                            await self._register_plugin(plugin)
                            return
            
            # Fallback: try to import as module
            spec = importlib.util.spec_from_file_location(
                plugin_dir.name, 
                plugin_dir / "__init__.py"
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, ThreatIntelPlugin) and obj != ThreatIntelPlugin:
                        plugin = obj(self.platform)
                        await self._register_plugin(plugin)
                        return
                        
        except Exception as e:
            logger.error(f"Failed to load plugin from {plugin_dir}: {e}")
    
    async def _load_plugin_from_file(self, plugin_file: Path):
        """Load plugin from single Python file"""
        try:
            module_name = plugin_file.stem
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, ThreatIntelPlugin) and obj != ThreatIntelPlugin:
                        plugin = obj(self.platform)
                        await self._register_plugin(plugin)
                        return
        except Exception as e:
            logger.error(f"Failed to load plugin from {plugin_file}: {e}")
    
    async def _register_plugin(self, plugin: 'ThreatIntelPlugin'):
        """Register a plugin"""
        plugin_name = plugin.name
        
        if plugin_name in self.plugins:
            logger.warning(f"Plugin {plugin_name} already registered, replacing")
        
        try:
            await plugin.initialize()
            
            self.plugins[plugin.name] = plugin
            self.plugin_info[plugin.name] = PluginInfo(
                name=plugin.name,
                version=getattr(plugin, 'version', '1.0.0'),
                description=getattr(plugin, 'description', ''),
                author=getattr(plugin, 'author', 'Unknown'),
                entry_point=plugin.__class__.__module__,
                enabled=True,
                loaded_at=datetime.now(),
                health="healthy"
            )
            
            # Register hook points
            for hook_name in self.hook_points:
                if hasattr(plugin, hook_name):
                    self.hook_points[hook_name].append(getattr(plugin, hook_name))
            
            logger.info(f"Registered plugin: {plugin.name}")
            
        except Exception as e:
            logger.error(f"Failed to register plugin {plugin.name}: {e}")
            raise
    
    def get_plugin(self, name: str) -> Optional[Any]:
        """Get plugin by name"""
        return self.plugins.get(name)
    
    def get_all_plugins(self) -> Dict[str, Any]:
        return self.plugins.copy()
    
    def get_plugin_info(self, name: str) -> Optional[PluginInfo]:
        return self.plugin_info.get(name)
    
    def list_plugins(self) -> List[PluginInfo]:
        return list(self.plugin_info.values())
    
    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin"""
        if name in self.plugins:
            self.plugins[name].enabled = True
            self.plugin_info[name].enabled = True
            return True
        return False
    
    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin"""
        if name in self.plugins:
            self.plugins[name].enabled = False
            self.plugin_info[name].enabled = False
            return True
        return False
    
    async def reload_plugin(self, name: str) -> bool:
        """Hot-reload a plugin"""
        if name not in self.plugins:
            return False
        
        try:
            # Call cleanup
            plugin = self.plugins[name]
            if hasattr(plugin, 'cleanup'):
                await plugin.cleanup()
            
            # Remove old plugin
            del self.plugins[name]
            del self.plugin_info[name]
            
            # Reload module
            module_name = plugin.__class__.__module__
            if module_name in sys.modules:
                importlib.reload(sys.modules[module_name])
            
            # Re-register
            module = sys.modules[module_name]
            for name, obj in inspect.getmembers(sys.modules[module_name], inspect.isclass):
                if issubclass(obj, ThreatIntelPlugin) and obj != ThreatIntelPlugin:
                    plugin = obj(self.platform)
                    await self._register_plugin(plugin)
                    return True
                    
        except Exception as e:
            logger.error(f"Failed to reload plugin {name}: {e}")
        
        return False
    
    async def execute_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Execute all registered hooks for a hook point"""
        results = []
        if hook_name in self.hook_points:
            for hook in self.hook_points[hook_name]:
                try:
                    if asyncio.iscoroutinefunction(hook):
                        result = await hook(*args, **kwargs)
                    else:
                        result = hook(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Hook {hook_name} error: {e}")
        return results
    
    async def enrich_item(self, item: Any) -> Any:
        """Run all enrichment plugins on an item"""
        for plugin in self.plugins.values():
            if plugin.enabled and hasattr(plugin, 'enrich'):
                try:
                    item = await plugin.enrich(item)
                except Exception as e:
                    logger.error(f"Enrichment error in {plugin.name}: {e}")
        return item
    
    async def run_hunt(self, query: Dict) -> List[Any]:
        """Run threat hunting across all plugins"""
        results = []
        for plugin in self.plugins.values():
            if plugin.enabled and hasattr(plugin, 'hunt'):
                try:
                    results.extend(await plugin.hunt(query))
                except Exception as e:
                    logger.error(f"Hunt error in {plugin.name}: {e}")
        return results
    
    async def cleanup(self):
        """Cleanup all plugins"""
        for plugin in self.plugins.values():
            try:
                if hasattr(plugin, 'cleanup'):
                    await plugin.cleanup()
            except Exception as e:
                logger.error(f"Plugin cleanup error for {plugin.name}: {e}")
    
    def get_hook_points(self) -> Dict[str, List]:
        return {k: len(v) for k, v in self.hook_points.items()}


# Plugin decorators
def plugin_hook(hook_name: str):
    """Decorator to register a function as a hook"""
    def decorator(func):
        func._plugin_hook = hook_name
        return func
    return decorator


def plugin_config(schema: Dict):
    """Decorator to define plugin configuration schema"""
    def decorator(cls):
        cls.config_schema = schema
        return cls
    return decorator


def plugin_depends_on(*dependencies):
    """Decorator to declare plugin dependencies"""
    def decorator(cls):
        cls.dependencies = dependencies
        return cls
    return decorator


# Plugin discovery and loading utilities
class PluginDiscovery:
    """Discover and load plugins from various sources"""
    
    @staticmethod
    def discover_entry_points(group: str = "living_intel.plugins") -> List[Dict]:
        """Discover plugins via entry points"""
        plugins = []
        try:
            for entry_point in importlib.metadata.entry_points(group=group):
                plugins.append({
                    "name": entry_point.name,
                    "module": entry_point.module,
                    "attrs": entry_point.attrs
                })
        except Exception as e:
            logger.error(f"Entry point discovery failed: {e}")
        return plugins
    
    @staticmethod
    async def load_from_pypi(package_name: str) -> bool:
        """Install and load plugin from PyPI"""
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", package_name], check=True)
            importlib.invalidate_caches()
            return True
        except Exception as e:
            logger.error(f"Failed to install plugin {package_name}: {e}")
            return False
    
    @staticmethod
    async def load_from_git(repo_url: str, branch: str = "main", path: str = None) -> bool:
        """Load plugin from git repository"""
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as tmpdir:
                subprocess.run(["git", "clone", "--depth", "1", "-b", branch, repo_url, tmpdir], check=True)
                plugin_dir = Path(tmpdir) / (path or "")
                # Load from directory
                return True
        except Exception as e:
            logger.error(f"Git plugin load failed: {e}")
            return False


# Plugin sandboxing for security
class PluginSandbox:
    """Sandbox for running untrusted plugins"""
    
    def __init__(self, plugin_name: str, allowed_modules: List[str] = None):
        self.plugin_name = plugin_name
        self.allowed_modules = allowed_modules or [
            "json", "re", "datetime", "datetime", "hashlib", "base64",
            "urllib.parse", "urllib.request", "html", "html.parser",
            "collections", "itertools", "functools", "dataclasses"
        ]
    
    def create_sandbox(self, code: str) -> Dict:
        """Create a restricted execution environment"""
        safe_globals = {
            "__builtins__": {
                "len": len, "str": str, "int": int, "float": float,
                "list": list, "dict": dict, "set": set, "tuple": tuple,
                "str": str, "bool": bool, "isinstance": isinstance,
                "hasattr": hasattr, "getattr": getattr, "setattr": setattr,
                "len": len, "range": range, "enumerate": enumerate,
                "zip": zip, "map": map, "filter": filter, "sorted": sorted,
                "sum": sum, "min": min, "max": max, "abs": abs,
                "round": round, "pow": pow, "divmod": divmod,
                "ord": ord, "chr": chr, "hex": hex, "bin": bin, "oct": oct,
                "Exception": Exception, "ValueError": ValueError,
                "TypeError": TypeError, "KeyError": KeyError,
                "IndexError": IndexError, "AttributeError": AttributeError,
                "StopIteration": StopIteration, "GeneratorExit": GeneratorExit,
                "True": True, "False": False, "None": None,
                "Ellipsis": Ellipsis, "NotImplemented": NotImplemented
            }
        }
        
        # Add allowed modules
        for mod_name in self.allowed_modules:
            try:
                safe_globals[mod_name] = __import__(mod_name)
            except ImportError:
                pass
        
        return safe_globals
    
    def execute_safe(self, code: str, locals_dict: Dict = None) -> Any:
        """Execute code in sandbox"""
        sandbox = self.create_sandbox(code)
        if locals_dict:
            sandbox.update(locals_dict)
        try:
            exec(code, sandbox, sandbox)
            return sandbox
        except Exception as e:
            logger.error(f"Sandbox execution error: {e}")
            raise