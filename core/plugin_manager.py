#!/usr/bin/env python3
"""
Plugin Manager for BugHunter Pro
Provides extensible plugin architecture for custom scanners
"""

import logging
import importlib
import importlib.util
import inspect
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Type
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PluginMetadata:
    """Plugin metadata"""
    name: str
    version: str
    description: str
    author: str
    enabled: bool = True
    category: str = "general"
    severity_level: str = "medium"


class ScannerPlugin(ABC):
    """Base class for scanner plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description"""
        pass
    
    @property
    def author(self) -> str:
        """Plugin author"""
        return "Unknown"
    
    @property
    def category(self) -> str:
        """Plugin category (injection, xss, auth, etc.)"""
        return "general"
    
    @property
    def severity_level(self) -> str:
        """Default severity level (critical, high, medium, low, info)"""
        return "medium"
    
    @abstractmethod
    def scan(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute the scan
        
        Args:
            target: Target URL or resource
            **kwargs: Additional scan parameters
        
        Returns:
            List of vulnerability findings
        """
        pass
    
    def initialize(self) -> bool:
        """
        Initialize the plugin (optional)
        
        Returns:
            True if initialization successful
        """
        return True
    
    def cleanup(self) -> None:
        """Cleanup resources (optional)"""
        pass
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata"""
        return PluginMetadata(
            name=self.name,
            version=self.version,
            description=self.description,
            author=self.author,
            category=self.category,
            severity_level=self.severity_level
        )


class PluginManager:
    """Manages scanner plugins"""
    
    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        """
        Initialize plugin manager
        
        Args:
            plugin_dirs: List of directories to search for plugins
        """
        self._plugins: Dict[str, ScannerPlugin] = {}
        self._enabled_plugins: Dict[str, bool] = {}
        self._plugin_dirs = plugin_dirs or ['plugins']
        self._categories: Dict[str, List[str]] = {}
        
        logger.info("Plugin manager initialized")
    
    def register_plugin(self, plugin: ScannerPlugin) -> bool:
        """
        Register a plugin instance
        
        Args:
            plugin: Plugin instance to register
        
        Returns:
            True if registration successful
        """
        try:
            name = plugin.name
            
            if name in self._plugins:
                logger.warning(f"Plugin '{name}' already registered, replacing...")
            
            # Initialize plugin
            if not plugin.initialize():
                logger.error(f"Failed to initialize plugin '{name}'")
                return False
            
            self._plugins[name] = plugin
            self._enabled_plugins[name] = True
            
            # Add to category index
            category = plugin.category
            if category not in self._categories:
                self._categories[category] = []
            self._categories[category].append(name)
            
            logger.info(f"✅ Registered plugin: {name} v{plugin.version} ({category})")
            return True
        
        except Exception as e:
            logger.error(f"Failed to register plugin: {e}")
            return False
    
    def unregister_plugin(self, name: str) -> bool:
        """
        Unregister a plugin
        
        Args:
            name: Plugin name
        
        Returns:
            True if successful
        """
        if name not in self._plugins:
            logger.warning(f"Plugin '{name}' not found")
            return False
        
        try:
            plugin = self._plugins[name]
            plugin.cleanup()
            
            # Remove from category index
            category = plugin.category
            if category in self._categories and name in self._categories[category]:
                self._categories[category].remove(name)
            
            del self._plugins[name]
            del self._enabled_plugins[name]
            
            logger.info(f"Unregistered plugin: {name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to unregister plugin '{name}': {e}")
            return False
    
    def enable_plugin(self, name: str) -> bool:
        """
        Enable a plugin
        
        Args:
            name: Plugin name
        
        Returns:
            True if successful
        """
        if name not in self._plugins:
            logger.warning(f"Plugin '{name}' not found")
            return False
        
        self._enabled_plugins[name] = True
        logger.info(f"Enabled plugin: {name}")
        return True
    
    def disable_plugin(self, name: str) -> bool:
        """
        Disable a plugin
        
        Args:
            name: Plugin name
        
        Returns:
            True if successful
        """
        if name not in self._plugins:
            logger.warning(f"Plugin '{name}' not found")
            return False
        
        self._enabled_plugins[name] = False
        logger.info(f"Disabled plugin: {name}")
        return True
    
    def get_plugin(self, name: str) -> Optional[ScannerPlugin]:
        """
        Get a plugin by name
        
        Args:
            name: Plugin name
        
        Returns:
            Plugin instance or None
        """
        return self._plugins.get(name)
    
    def get_enabled_plugins(self) -> List[ScannerPlugin]:
        """
        Get all enabled plugins
        
        Returns:
            List of enabled plugin instances
        """
        return [
            plugin for name, plugin in self._plugins.items()
            if self._enabled_plugins.get(name, False)
        ]
    
    def get_plugins_by_category(self, category: str) -> List[ScannerPlugin]:
        """
        Get plugins by category
        
        Args:
            category: Plugin category
        
        Returns:
            List of plugins in the category
        """
        plugin_names = self._categories.get(category, [])
        return [self._plugins[name] for name in plugin_names if name in self._plugins]
    
    def list_plugins(self) -> List[PluginMetadata]:
        """
        List all registered plugins
        
        Returns:
            List of plugin metadata
        """
        metadata = []
        for name, plugin in self._plugins.items():
            meta = plugin.get_metadata()
            meta.enabled = self._enabled_plugins.get(name, False)
            metadata.append(meta)
        return metadata
    
    def discover_plugins(self, directory: Optional[str] = None) -> int:
        """
        Discover and load plugins from directory
        
        Args:
            directory: Directory to search (optional)
        
        Returns:
            Number of plugins discovered
        """
        search_dirs = [directory] if directory else self._plugin_dirs
        discovered = 0
        
        for plugin_dir in search_dirs:
            path = Path(plugin_dir)
            
            if not path.exists():
                logger.warning(f"Plugin directory not found: {plugin_dir}")
                continue
            
            logger.info(f"Searching for plugins in: {plugin_dir}")
            
            # Find all Python files
            for plugin_file in path.glob("*.py"):
                if plugin_file.name.startswith("__"):
                    continue
                
                try:
                    # Import the module
                    module_name = plugin_file.stem
                    spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                    
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Find plugin classes
                        for name, obj in inspect.getmembers(module):
                            if (inspect.isclass(obj) and 
                                issubclass(obj, ScannerPlugin) and 
                                obj != ScannerPlugin):
                                
                                # Instantiate and register
                                plugin_instance = obj()
                                if self.register_plugin(plugin_instance):
                                    discovered += 1
                
                except Exception as e:
                    logger.error(f"Failed to load plugin from {plugin_file}: {e}")
        
        logger.info(f"Discovered {discovered} plugins")
        return discovered
    
    def execute_scan(
        self,
        target: str,
        categories: Optional[List[str]] = None,
        plugin_names: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Execute scans using plugins
        
        Args:
            target: Target URL or resource
            categories: Filter by categories (optional)
            plugin_names: Filter by plugin names (optional)
            **kwargs: Additional scan parameters
        
        Returns:
            Dict mapping plugin names to their findings
        """
        results = {}
        
        # Determine which plugins to run
        if plugin_names:
            plugins = [self._plugins[name] for name in plugin_names if name in self._plugins]
        elif categories:
            plugins = []
            for category in categories:
                plugins.extend(self.get_plugins_by_category(category))
        else:
            plugins = self.get_enabled_plugins()
        
        logger.info(f"Executing {len(plugins)} plugins against {target}")
        
        for plugin in plugins:
            try:
                logger.debug(f"Running plugin: {plugin.name}")
                findings = plugin.scan(target, **kwargs)
                
                if findings:
                    results[plugin.name] = findings
                    logger.info(f"  {plugin.name}: {len(findings)} findings")
            
            except Exception as e:
                logger.error(f"Plugin '{plugin.name}' failed: {e}")
                results[plugin.name] = []
        
        return results
    
    def cleanup_all(self):
        """Cleanup all plugins"""
        for plugin in self._plugins.values():
            try:
                plugin.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up plugin: {e}")


# Example plugin implementation
class ExampleXSSPlugin(ScannerPlugin):
    """Example XSS scanner plugin"""
    
    @property
    def name(self) -> str:
        return "example_xss"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def description(self) -> str:
        return "Example XSS scanner plugin"
    
    @property
    def category(self) -> str:
        return "xss"
    
    @property
    def severity_level(self) -> str:
        return "high"
    
    def scan(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Example scan implementation"""
        findings = []
        
        # Example finding
        findings.append({
            'type': 'XSS',
            'severity': 'high',
            'url': target,
            'parameter': 'test',
            'payload': '<script>alert(1)</script>',
            'evidence': 'Reflected in response'
        })
        
        return findings


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    manager = PluginManager()
    
    # Register example plugin
    example_plugin = ExampleXSSPlugin()
    manager.register_plugin(example_plugin)
    
    # List plugins
    print("\nRegistered Plugins:")
    for meta in manager.list_plugins():
        print(f"  - {meta.name} v{meta.version}: {meta.description}")
    
    # Execute scan
    results = manager.execute_scan("http://example.com")
    print(f"\nScan Results: {results}")
