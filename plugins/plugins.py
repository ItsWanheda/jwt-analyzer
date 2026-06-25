import importlib
import logging
from pathlib import Path
from typing import Dict, Callable

logger = logging.getLogger(__name__)


class PluginManager:
    """Simple plugin architecture for extensibility."""
    
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.plugins: Dict[str, Callable] = {}
    
    def load_plugins(self):
        """Auto-discover and load plugins from the plugins directory."""
        if not self.plugin_dir.exists():
            logger.debug(f"Plugin directory not found: {self.plugin_dir}")
            return
        
        for plugin_file in self.plugin_dir.glob("*_plugin.py"):
            module_name = plugin_file.stem
            try:
                module = importlib.import_module(f"plugins.{module_name}")
                if hasattr(module, 'register'):
                    plugin = module.register()
                    self.plugins[plugin.name] = plugin
                    logger.info(f"Loaded plugin: {plugin.name}")
            except Exception as e:
                logger.error(f"Failed to load plugin {module_name}: {e}")
    
    def run_check(self, token: str) -> list:
        """Run all plugin checks against a token."""
        results = []
        for name, plugin in self.plugins.items():
            try:
                result = plugin.check(token)
                if result:
                    results.append({'plugin': name, **result})
            except Exception as e:
                logger.error(f"Plugin {name} failed: {e}")
        return results