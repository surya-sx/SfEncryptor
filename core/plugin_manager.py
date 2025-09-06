"""
Plugin Manager - Handles loading and management of encryption plugins.

This module provides the PluginManager class which is responsible for:
- Loading encryption plugins from the plugins directory
- Managing plugin states (enabled/disabled)
- Providing access to available plugins and their configurations
"""

import os
import sys
import json
import logging
import importlib

logger = logging.getLogger("SF FileManager")

class PluginManager:
    """Manages encryption plugins for the SF-Encryptor application."""
    
    def __init__(self, settings, plugins_dir=None):
        """
        Initialize the plugin manager.
        
        Args:
            settings (dict): Application settings dictionary
            plugins_dir (str, optional): Path to plugins directory
        """
        self.encryption_plugins = {}
        self.settings = settings
        
        # Determine plugins directory
        if plugins_dir:
            self.plugins_dir = plugins_dir
        else:
            # Default to plugins folder in application directory
            if getattr(sys, 'frozen', False):
                base_dir = sys._MEIPASS
            else:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.plugins_dir = os.path.join(base_dir, "plugins")
        
        self.load_plugins()
    
    def load_plugins(self):
        """Load all encryption plugins from the plugins directory."""
        self.encryption_plugins.clear()
        
        logger.info(f"Scanning for plugins in: {self.plugins_dir}")

        # Add the plugins directory to Python's import path
        if self.plugins_dir not in sys.path:
            sys.path.append(self.plugins_dir)
            logger.info(f"Added '{self.plugins_dir}' to sys.path.")
        
        if not os.path.exists(self.plugins_dir):
            logger.warning(f"Plugins directory not found at {self.plugins_dir}. Skipping plugin loading.")
            return

        # Scan for plugin files
        try:
            plugin_files = [f for f in os.listdir(self.plugins_dir) 
                           if f.endswith(".py") and not f.startswith("__")]
            logger.info(f"Found plugin files in directory: {plugin_files}")
        except FileNotFoundError:
            logger.error(f"Plugins directory does not exist at {self.plugins_dir}.")
            return
        except Exception as e:
            logger.error(f"An error occurred while listing plugin files: {e}")
            return
        
        # Load each plugin
        for filename in plugin_files:
            try:
                module_name = filename[:-3]  # Remove .py extension
                
                # Use importlib.import_module for more robust import in frozen environments
                module = importlib.import_module(module_name)
                
                if hasattr(module, 'EncryptorPlugin'):
                    plugin_instance = module.EncryptorPlugin()
                    self.encryption_plugins[plugin_instance.name] = plugin_instance
                    logger.info(f"Successfully loaded plugin: {plugin_instance.name} from {filename}")
                else:
                    logger.warning(f"Plugin file {filename} does not contain an 'EncryptorPlugin' class.")
                    
            except ImportError as e:
                logger.error(f"Failed to import plugin '{filename}': {e}", exc_info=True)
            except Exception as e:
                logger.error(f"Failed to load plugin '{filename}': {e}", exc_info=True)
    
    def reload_plugins(self):
        """Reload all plugins."""
        self.load_plugins()
    
    def get_available_plugins(self):
        """
        Get list of enabled plugin names.
        
        Returns:
            list: List of enabled plugin names
        """
        # Initialize settings if not present
        if "enabled_plugins" not in self.settings:
            self.settings["enabled_plugins"] = {name: True for name in self.encryption_plugins}
        
        enabled_plugins = self.settings.get("enabled_plugins", {})
        return [name for name, is_enabled in enabled_plugins.items() 
                if is_enabled and name in self.encryption_plugins]
    
    def get_all_plugins(self):
        """
        Get all loaded plugins regardless of enabled status.
        
        Returns:
            dict: Dictionary of all loaded plugins
        """
        return self.encryption_plugins
    
    def get_plugin(self, name):
        """
        Get a specific plugin by name.
        
        Args:
            name (str): Plugin name
            
        Returns:
            EncryptorPlugin or None: The plugin instance or None if not found
        """
        return self.encryption_plugins.get(name)
    
    def get_plugin_key_length(self, name):
        """
        Get the key length for a specific plugin.
        
        Args:
            name (str): Plugin name
            
        Returns:
            int: Key length in bits (default: 256)
        """
        plugin = self.encryption_plugins.get(name)
        return getattr(plugin, 'key_length_bits', 256) if plugin else 256
    
    def set_plugin_status(self, name, is_enabled):
        """
        Enable or disable a plugin.
        
        Args:
            name (str): Plugin name
            is_enabled (bool): Whether the plugin should be enabled
        """
        if "enabled_plugins" not in self.settings:
            self.settings["enabled_plugins"] = {}
        
        self.settings["enabled_plugins"][name] = is_enabled
        logger.info(f"Plugin '{name}' {'enabled' if is_enabled else 'disabled'}")
    
    def is_plugin_enabled(self, name):
        """
        Check if a plugin is enabled.
        
        Args:
            name (str): Plugin name
            
        Returns:
            bool: True if plugin is enabled, False otherwise
        """
        enabled_plugins = self.settings.get("enabled_plugins", {})
        return enabled_plugins.get(name, True)  # Default to enabled
    
    def get_plugin_count(self):
        """
        Get the total number of loaded plugins.
        
        Returns:
            int: Number of loaded plugins
        """
        return len(self.encryption_plugins)
    
    def get_enabled_plugin_count(self):
        """
        Get the number of enabled plugins.
        
        Returns:
            int: Number of enabled plugins
        """
        return len(self.get_available_plugins())
    
    def validate_plugin(self, plugin_instance):
        """
        Validate that a plugin instance has required methods and attributes.
        
        Args:
            plugin_instance: Plugin instance to validate
            
        Returns:
            bool: True if plugin is valid, False otherwise
        """
        required_attributes = ['name', 'encrypt', 'decrypt']
        
        for attr in required_attributes:
            if not hasattr(plugin_instance, attr):
                logger.error(f"Plugin missing required attribute: {attr}")
                return False
        
        return True
