"""
Key Manager - Handles storage and management of encryption keys.

This module provides the KeyManager class which is responsible for:
- Storing and retrieving encryption keys
- Managing key metadata (name, type, path, creation date)
- Key validation and security
"""

import os
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class KeyManager:
    """Manages encryption keys for the SF-Encryptor application."""
    
    def __init__(self, key_store_file=None):
        """
        Initialize the key manager.
        
        Args:
            key_store_file (str, optional): Path to key store file
        """
        if key_store_file:
            self.key_store_file = key_store_file
        else:
            # Default key store location
            if os.name == 'nt':  # Windows
                app_data_dir = os.environ.get("LOCALAPPDATA", 
                                            os.path.join(os.path.expanduser("~"), "AppData", "Local"))
            elif os.name == 'posix':  # Unix-like (Linux, macOS)
                if sys.platform == "darwin":  # macOS
                    app_data_dir = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
                else:  # Linux
                    app_data_dir = os.environ.get("XDG_DATA_HOME", 
                                                os.path.join(os.path.expanduser("~"), ".local", "share"))
            else:
                app_data_dir = os.path.expanduser("~")
            
            app_specific_dir = os.path.join(app_data_dir, "SF FileManager")
            keys_dir = os.path.join(app_specific_dir, "keys")
            os.makedirs(keys_dir, exist_ok=True)
            self.key_store_file = os.path.join(keys_dir, "key_store.json")
        
        self.keys = self._load_keys()
    
    def _load_keys(self):
        """
        Load keys from the key store file.
        
        Returns:
            list: List of key dictionaries
        """
        if os.path.exists(self.key_store_file):
            try:
                with open(self.key_store_file, 'r', encoding='utf-8') as f:
                    keys = json.load(f)
                logger.info(f"Loaded {len(keys)} keys from key store")
                return keys
            except Exception as e:
                logger.error(f"Failed to load key store: {e}")
                return []
        else:
            logger.info("Key store file not found, starting with empty key store")
            return []
    
    def _save_keys(self):
        """Save keys to the key store file."""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.key_store_file), exist_ok=True)
            
            with open(self.key_store_file, 'w', encoding='utf-8') as f:
                json.dump(self.keys, f, indent=4, ensure_ascii=False)
            
            logger.info(f"Saved {len(self.keys)} keys to key store")
            
        except Exception as e:
            logger.error(f"Failed to save key store: {e}")
            raise
    
    def add_key(self, name, key_type, path, metadata=None):
        """
        Add a new key to the key store.
        
        Args:
            name (str): Key name
            key_type (str): Key type (e.g., 'RSA', 'AES', 'Symmetric')
            path (str): Path to the key file
            metadata (dict, optional): Additional key metadata
            
        Returns:
            str: The final key name (may be modified if duplicate)
        """
        # Ensure unique name
        original_name = name
        counter = 1
        while any(key['name'] == name for key in self.keys):
            name = f"{original_name}_{counter}"
            counter += 1
        
        # Create key entry
        key_entry = {
            "name": name,
            "type": key_type,
            "path": path,
            "added_on": datetime.now().isoformat(),
            "metadata": metadata or {}
        }
        
        # Validate key file exists
        if not os.path.exists(path):
            logger.warning(f"Key file does not exist: {path}")
        
        self.keys.append(key_entry)
        self._save_keys()
        
        logger.info(f"Added key '{name}' of type '{key_type}' at '{path}'")
        return name
    
    def get_keys(self):
        """
        Get all stored keys.
        
        Returns:
            list: List of key dictionaries
        """
        return self.keys.copy()
    
    def get_key_by_name(self, name):
        """
        Get a specific key by name.
        
        Args:
            name (str): Key name
            
        Returns:
            dict or None: Key dictionary or None if not found
        """
        return next((key for key in self.keys if key['name'] == name), None)
    
    def delete_key(self, name):
        """
        Delete a key from the key store.
        
        Args:
            name (str): Key name to delete
            
        Returns:
            bool: True if key was deleted, False if not found
        """
        original_len = len(self.keys)
        self.keys = [key for key in self.keys if key['name'] != name]
        
        if len(self.keys) < original_len:
            self._save_keys()
            logger.info(f"Deleted key '{name}'")
            return True
        else:
            logger.warning(f"Key '{name}' not found for deletion")
            return False
    
    def update_key(self, name, **kwargs):
        """
        Update key metadata.
        
        Args:
            name (str): Key name
            **kwargs: Key attributes to update
            
        Returns:
            bool: True if key was updated, False if not found
        """
        key = self.get_key_by_name(name)
        if key:
            key.update(kwargs)
            key['modified_on'] = datetime.now().isoformat()
            self._save_keys()
            logger.info(f"Updated key '{name}'")
            return True
        else:
            logger.warning(f"Key '{name}' not found for update")
            return False
    
    def get_keys_by_type(self, key_type):
        """
        Get keys by type.
        
        Args:
            key_type (str): Key type to filter by
            
        Returns:
            list: List of keys of the specified type
        """
        return [key for key in self.keys if key.get('type') == key_type]
    
    def validate_key_file(self, path):
        """
        Validate that a key file exists and is accessible.
        
        Args:
            path (str): Path to key file
            
        Returns:
            bool: True if key file is valid, False otherwise
        """
        try:
            return os.path.exists(path) and os.path.isfile(path) and os.access(path, os.R_OK)
        except Exception as e:
            logger.error(f"Error validating key file {path}: {e}")
            return False
    
    def cleanup_invalid_keys(self):
        """
        Remove keys that reference non-existent files.
        
        Returns:
            int: Number of keys removed
        """
        invalid_keys = [key for key in self.keys if not self.validate_key_file(key['path'])]
        
        for key in invalid_keys:
            logger.warning(f"Removing invalid key '{key['name']}' - file not found: {key['path']}")
            self.keys.remove(key)
        
        if invalid_keys:
            self._save_keys()
        
        return len(invalid_keys)
    
    def export_key_list(self, export_path):
        """
        Export key list to a JSON file.
        
        Args:
            export_path (str): Path to export file
            
        Returns:
            bool: True if export successful, False otherwise
        """
        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(self.keys, f, indent=4, ensure_ascii=False)
            
            logger.info(f"Exported key list to {export_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export key list: {e}")
            return False
    
    def import_key_list(self, import_path, merge=True):
        """
        Import keys from a JSON file.
        
        Args:
            import_path (str): Path to import file
            merge (bool): If True, merge with existing keys; if False, replace
            
        Returns:
            int: Number of keys imported
        """
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                imported_keys = json.load(f)
            
            if not merge:
                self.keys.clear()
            
            imported_count = 0
            for key in imported_keys:
                # Ensure required fields
                if 'name' in key and 'type' in key and 'path' in key:
                    # Add with automatic name resolution
                    self.add_key(key['name'], key['type'], key['path'], key.get('metadata'))
                    imported_count += 1
            
            logger.info(f"Imported {imported_count} keys from {import_path}")
            return imported_count
            
        except Exception as e:
            logger.error(f"Failed to import key list: {e}")
            return 0
    
    def get_key_count(self):
        """
        Get the total number of stored keys.
        
        Returns:
            int: Number of keys
        """
        return len(self.keys)
    
    def search_keys(self, query):
        """
        Search keys by name or type.
        
        Args:
            query (str): Search query
            
        Returns:
            list: List of matching keys
        """
        query_lower = query.lower()
        return [key for key in self.keys 
                if query_lower in key.get('name', '').lower() 
                or query_lower in key.get('type', '').lower()]

    def get_all_keys(self):
        """
        Get all stored keys.
        
        Returns:
            list: List of all keys
        """
        return self.keys.copy()
    
    def remove_key(self, name):
        """
        Remove a key from the key store by name.
        
        Args:
            name (str): Name of the key to remove
            
        Returns:
            bool: True if key was removed, False if not found
        """
        try:
            # Find the key by name
            for i, key in enumerate(self.keys):
                if key.get('name') == name:
                    removed_key = self.keys.pop(i)
                    self._save_keys()
                    logger.info(f"Removed key: {name}")
                    return True
            
            logger.warning(f"Key not found for removal: {name}")
            return False
            
        except Exception as e:
            logger.error(f"Failed to remove key {name}: {e}")
            return False
