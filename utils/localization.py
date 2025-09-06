"""
Localization Manager - Handles application translations and language support.

This module provides the LocalizationManager class which handles:
- Loading and managing translations
- Language switching
- String formatting with parameters
- Fallback to default language
"""

import os
import json
import logging

logger = logging.getLogger(__name__)

class LocalizationManager:
    """Manages localization and translations for the SF-Encryptor application."""
    
    def __init__(self, languages_dir=None):
        """
        Initialize the localization manager.
        
        Args:
            languages_dir (str, optional): Path to languages directory
        """
        self.current_language = "en"
        self.translations = {}
        self.fallback_language = "en"
        
        # Set languages directory
        if languages_dir:
            self.languages_dir = languages_dir
        else:
            # Default to languages folder in application data directory
            from utils.helpers import setup_directories
            directories = setup_directories()
            self.languages_dir = directories['languages']
        
        # Load default English translations
        self._load_default_translations()
        
        # Load additional language files
        self._load_language_files()
    
    def _load_default_translations(self):
        """Load default English translations."""
        default_translations = {
            # Application basics
            "app_name": "SF FileManager",
            "version": "Version: ",
            "developed_by": "Developed by: ",
            
            # Main tabs
            "encrypt_tab": "Encrypt",
            "decrypt_tab": "Decrypt",
            "generate_keys_tab": "Generate Keys",
            "settings_tab": "Settings",
            "about_tab": "About",
            "plugins_tab": "Plugins",
            "key_management_tab": "Key Management",
            "file_integrity_tab": "File Integrity",
            "log_viewer": "Log Viewer",
            "whats_new_tab": "What's New",
            
            # Common UI elements
            "browse": "Browse",
            "select_file": "Select File",
            "select_folder": "Select Folder",
            "select_file_folder": "Select File/Folder",
            "input_file_folder": "Input File/Folder:",
            "output_folder": "Output Folder:",
            "select_output_folder": "Select output folder",
            
            # Encryption/Decryption
            "encryption_algorithm": "Encryption Algorithm:",
            "decryption_algorithm": "Decryption Algorithm:",
            "key_type": "Key Type:",
            "password_derive_key": "Password (Derive Key)",
            "direct_key_base64_pem": "Direct Key (Base64/PEM)",
            "password": "Password:",
            "direct_key": "Direct Key:",
            "show_input": "Show Input",
            "password_strength": "Password Strength: ",
            "kdf_iterations": "KDF Iterations:",
            "output_suffix": "Output Suffix:",
            "delete_original_after_encrypt": "Delete Original After Encrypt",
            "encrypt_files": "Encrypt File(s)",
            "decrypt_files": "Decrypt File(s)",
            "encrypting": "Encrypting...",
            "decrypting": "Decrypting...",
            
            # Password strength
            "weak": "Weak",
            "medium": "Medium",
            "strong": "Strong",
            "password_strength_weak": "Weak: Use a mix of characters.",
            "password_strength_medium": "Medium: Add numbers and symbols.",
            "password_strength_strong": "Strong: Longer, complex password.",
            
            # Compression
            "compression_algorithm": "Compression Algorithm:",
            "compression_level": "Compression Level:",
            "no_compression": "No Compression",
            "gzip": "Gzip",
            "bzip2": "Bzip2",
            "lzma": "LZMA",
            "lzma2": "LZMA2/XZ",
            "zstd": "Zstandard",
            "brotli": "Brotli",
            "lz4": "LZ4",
            "auto_compression": "Auto-Select (Recommended)",
            "compression_priority": "Compression Priority:",
            "priority_speed": "Speed Priority",
            "priority_balanced": "Balanced",
            "priority_ratio": "Compression Ratio Priority",
            
            # Key generation
            "algorithm_key_generation": "Algorithm for Key Generation:",
            "key_length_bits_rsa": "Key Length (bits, for RSA):",
            "output_format": "Output Format:",
            "base64_url_safe": "Base64 (URL-safe)",
            "hex": "Hex",
            "pem_rsa_only": "PEM (RSA Only)",
            "generate_keys": "Generate Key(s)",
            "generated_keys": "Generated Key(s):",
            "copy_keys_clipboard": "Copy Key(s) to Clipboard",
            "save_public_key": "Save Public Key...",
            "save_private_key": "Save Private Key...",
            "save_symmetric_key": "Save Symmetric Key...",
            "rsa_gen_password_label": "Key Password (optional):",
            
            # Settings
            "theme": "Theme:",
            "system": "System",
            "language_wip": "Language:",
            "auto_clear_logs_startup": "Auto-clear logs on startup",
            "confirm_overwrite_files": "Confirm before overwriting files",
            "enable_expert_mode": "Enable Expert Mode (More Options)",
            "log_level": "Log Level:",
            "file_chunk_size_kb": "File Chunk Size (KB):",
            "default_output_folder": "Default Output Folder:",
            "select_default_output_folder": "Select Default Output Folder",
            "default_encryption_algorithm": "Default Encryption Algorithm:",
            "confirm_on_exit": "Confirm on Exit",
            "max_log_size_mb": "Max Log Size (MB):",
            "enable_log_rotation": "Enable Log Rotation",
            "export_settings": "Export Settings",
            "import_settings": "Import Settings",
            "save_settings_as": "Save Settings As...",
            "load_settings_from": "Load Settings From...",
            
            # Animation settings
            "animation_settings": "Animation Settings",
            "enable_animations": "Enable Animations",
            "transition_effects": "Transition Effects",
            "animation_speed": "Animation Speed:",
            "fade_duration_ms": "Fade Duration (ms):",
            "slide_duration_ms": "Slide Duration (ms):",
            "test_animations": "Test Animations",
            
            # Plugins
            "loaded_encryption_plugins": "Loaded Encryption Plugins",
            "reload_plugins": "Reload Plugins",
            "selected_plugin_details": "Selected Plugin Details:",
            "name": "Name:",
            "key_length": "Key Length:",
            "nonce_iv_length": "Nonce/IV Length:",
            "cipher_mode": "Cipher Mode:",
            "no_plugins_found": "No plugins found. Place .py files in the 'plugins' folder.",
            "no_plugins_loaded": "No Plugins Loaded",
            "plugins_enable_disable": "Enable or disable encryption plugins. Changes are saved automatically.",
            
            # Key management
            "managed_keys": "Managed Keys:",
            "key_name": "Key Name",
            "key_type": "Type",
            "key_path": "Path",
            "key_actions": "Actions",
            "export_key": "Export Key",
            "delete_key": "Delete Key",
            "view_key": "View Key",
            "password_input_type": "Password Input Type:",
            "use_password": "Use Password",
            "use_key_file": "Use Key File",
            "key_file_path": "Key File Path:",
            "select_key_file": "Select Key File",
            
            # File integrity
            "file_integrity_title": "File Integrity & Password Generator",
            "file_to_hash": "File to Hash:",
            "calculate_hash": "Calculate Hash",
            "sha256_hash": "SHA-256 Hash:",
            "sha512_hash": "SHA-512 Hash:",
            "secure_password_generator": "Secure Password Generator",
            "password_length": "Password Length:",
            "include_uppercase": "Include Uppercase",
            "include_numbers": "Include Numbers",
            "include_symbols": "Include Symbols",
            "generate_password": "Generate Password",
            "generated_password": "Generated Password:",
            "secure_shredding_passes": "Secure Shredding Passes (0 for none):",
            "file_integrity_check": "File Integrity Check (SHA-256)",
            
            # Log viewer
            "filter_by_level": "Filter by Level:",
            "search_logs": "Search Logs...",
            "export_logs": "Export Logs",
            "all_levels": "All Levels",
            "info": "INFO",
            "warning": "WARNING",
            "error": "ERROR",
            "Time": "Time",
            "Level": "Level",
            "Message": "Message",
            
            # Status messages
            "success": "Success",
            "error": "Error",
            "no_key": "No Key",
            "loading_app": "Loading Application...",
            "initializing_ui": "Initializing User Interface...",
            "loading_plugins": "Loading Encryption Plugins...",
            "preparing_key_manager": "Preparing Key Manager...",
            "finalizing_startup": "Finalizing Startup...",
            "waiting_for_op": "Waiting for operation...",
            "operation_cancelled": "Operation cancelled by user.",
            
            # Messages and notifications
            "input_error": "Input Error",
            "all_fields_filled": "All fields must be filled.",
            "encryption_complete_title": "Encryption Complete",
            "encryption_complete": "{count} file(s) encrypted successfully!",
            "decryption_complete_title": "Decryption Complete",
            "decryption_complete": "{count} file(s) decrypted successfully!",
            "key_generation": "Key Generation",
            "key_generation_success": "{algo_name} key(s) generated successfully!",
            "key_generation_error_title": "Key Generation Error",
            "key_copied_clipboard": "Key(s) copied to clipboard!",
            "no_key_copy": "No key to copy.",
            "key_saved_to": "Key saved to {path}",
            "file_save_error": "File Save Error",
            "no_key_to_save": "No key to save.",
            "copied_to_clipboard": "Copied to clipboard!",
            "plugins_reloaded": "Plugins Reloaded",
            "plugins_reloaded_success": "Plugins reloaded successfully!",
            "settings_exported": "Settings exported to {path}",
            "settings_imported": "Settings imported from {path}",
            "import_export_error": "Error importing/exporting settings: {e}",
            "log_exported_to": "Logs exported to {path}",
            "log_export_error": "Error exporting logs: {e}",
            
            # Key management messages
            "key_deleted": "Key '{name}' deleted.",
            "key_exported": "Key '{name}' exported to {path}",
            "confirm_delete_key": "Are you sure you want to delete key '{name}'? This action cannot be undone.",
            "key_view_title": "View Key: {name}",
            "key_load_error": "Error loading key: {e}",
            "confirm_delete_key_title": "Confirm Key Deletion",
            "delete_failed_title": "Delete Failed",
            "delete_failed_message": "Failed to delete key '{name}'.",
            "export_complete_title": "Export Complete",
            "export_error_title": "Export Error",
            "no_symmetric_plugins_found": "No symmetric encryption plugins found. Please add plugins to the 'plugins' folder.",
            "select_algorithm_warning": "Please select an encryption algorithm.",
            "key_error_title": "Key Error",
            
            # File processing
            "status_file_selected": "File selected: {path}",
            "status_metadata_found": "Metadata found. Algorithm set to {algo}.",
            "status_metadata_error": "Could not read metadata: {e}",
            "metadata_not_found": "Metadata file (.meta) not found. Manual configuration required.",
            "invalid_password_or_corrupt": "Decryption failed: Invalid password or corrupted file.",
            "decrypt_failed_invalid_password": "Decryption failed: Incorrect password.",
            "decrypt_failed_corrupt": "Decryption failed: The file is corrupted or not a valid encrypted file.",
            "file_processing_status": "Processing: {filename}",
            "file_processing_status_batch": "Processing file {current_file_index}/{total_files}: {filename}",
            "batch_processing_progress": "Overall Progress: {current}/{total} files ({percentage:.1f}%)",
            "checksum_mismatch": "Checksum mismatch for {filename}! File may be corrupted.",
            "checksum_verified": "Checksum verified for {filename}.",
            "file_shredding": "Securely shredding original file...",
            "shredding_complete": "Original file securely shredded.",
            
            # About and contact
            "view_github": "View GitHub",
            "open_github": "Open GitHub",
            "license_proprietary": "License: Proprietary (See terms.txt)",
            "feedback_contact_github": "For feedback or contact, please visit the GitHub page.",
            "contact_developer": "Contact Developer",
            "contact_email_label": "Contact Email:",
            
            # Exit confirmation
            "confirm_exit_title": "Confirm Exit",
            "confirm_exit_message": "Are you sure you want to exit?",
            
            # Expert mode
            "expert_mode_warning_title": "Expert Mode Enabled",
            "expert_mode_warning_message": "Expert Mode exposes advanced cryptographic options. Incorrect use may lead to data loss or insecure operations. Proceed with caution.",
            
            # Tooltips
            "tooltip_input_file": "Select the file or folder to process. You can also drag and drop a file here.",
            "tooltip_output_folder": "Select the destination folder for the output files.",
            "tooltip_algorithm": "Choose the encryption or decryption algorithm.",
            "tooltip_key_type": "Choose between deriving a key from a password or using a direct key (Base64/PEM).",
            "tooltip_password": "Enter the password. Used to generate a secure encryption key.",
            "tooltip_direct_key": "Enter the key directly, usually in Base64 or PEM format.",
            "tooltip_iterations": "Number of rounds for password-based key derivation. Higher is more secure.",
            "tooltip_delete_original": "If checked, the original file will be deleted after a successful operation.",
            "tooltip_rsa_gen_password": "Optional. If provided, the generated RSA private key will be encrypted with this password.",
            "tooltip_save_key": "Save the generated key(s) to a file.",
            
            # What's New content
            "whats_new_content": """
                <h3>Welcome to the new and improved SF FileManager Suite!</h3>
                <p>This version brings a host of new features and improvements:</p>
                <ul>
                    <li><b>Modern UI Overhaul:</b> A fresh, clean look with new colors, gradients, and styles for a better user experience.</li>
                    <li><b>Modular Architecture:</b> Clean separation of concerns with organized code structure for easier maintenance.</li>
                    <li><b>Enhanced Compression:</b> Support for modern compression algorithms including Zstandard, Brotli, and LZ4.</li>
                    <li><b>Animation System:</b> Smooth transitions and animations for a more polished user experience.</li>
                    <li><b>Drag & Drop Support:</b> You can now drag files directly onto the input fields to select them instantly.</li>
                    <li><b>Automatic Metadata Files:</b> Encryption settings are saved automatically with your files for easier decryption.</li>
                    <li><b>Enhanced Security:</b> Generate password-protected RSA keys and secure file shredding options.</li>
                    <li><b>Plugin Management:</b> Easily enable or disable encryption algorithms from the new 'Plugins' tab.</li>
                    <li><b>Improved Key Management:</b> Better tools to view, export, and delete your stored keys.</li>
                </ul>
                <p>Thank you for using the application!</p>
            """,
            
            # Application messages
            "app_started": "{app_name} v{app_version} started.",
            "app_closed": "{app_name} closed.",
        }
        
        self.translations[self.fallback_language] = default_translations
        logger.info("Default English translations loaded")
    
    def _load_language_files(self):
        """Load language files from the languages directory."""
        if not os.path.exists(self.languages_dir):
            logger.info(f"Languages directory not found: {self.languages_dir}")
            return
        
        try:
            for filename in os.listdir(self.languages_dir):
                if filename.endswith('.json'):
                    lang_code = filename[:-5]  # Remove .json extension
                    file_path = os.path.join(self.languages_dir, filename)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            translations = json.load(f)
                        
                        self.translations[lang_code] = translations
                        logger.info(f"Loaded translations for language: {lang_code}")
                        
                    except Exception as e:
                        logger.error(f"Failed to load language file {filename}: {e}")
                        
        except Exception as e:
            logger.error(f"Error scanning languages directory: {e}")
    
    def set_language(self, language_code):
        """
        Set the current language.
        
        Args:
            language_code (str): Language code (e.g., 'en', 'es', 'fr')
        """
        if language_code in self.translations:
            self.current_language = language_code
            logger.info(f"Language set to: {language_code}")
        else:
            logger.warning(f"Language '{language_code}' not found, using fallback")
            self.current_language = self.fallback_language
    
    def get_available_languages(self):
        """
        Get list of available languages.
        
        Returns:
            list: List of language codes
        """
        return list(self.translations.keys())
    
    def get_string(self, key, **kwargs):
        """
        Get localized string by key.
        
        Args:
            key (str): Translation key
            **kwargs: Format parameters for string formatting
            
        Returns:
            str: Localized string
        """
        # Try current language first
        current_translations = self.translations.get(self.current_language, {})
        
        if key in current_translations:
            text = current_translations[key]
        else:
            # Fallback to default language
            fallback_translations = self.translations.get(self.fallback_language, {})
            if key in fallback_translations:
                text = fallback_translations[key]
                logger.debug(f"Using fallback translation for key: {key}")
            else:
                # Return key if no translation found
                logger.warning(f"Translation not found for key: {key}")
                text = key
        
        # Format string with provided parameters
        try:
            return text.format(**kwargs)
        except (KeyError, ValueError) as e:
            logger.error(f"String formatting error for key '{key}': {e}")
            return text
    
    def get_current_language(self):
        """
        Get the current language code.
        
        Returns:
            str: Current language code
        """
        return self.current_language
    
    def get_language_name(self, language_code=None):
        """
        Get the human-readable name of a language.
        
        Args:
            language_code (str, optional): Language code, defaults to current language
            
        Returns:
            str: Language name
        """
        if language_code is None:
            language_code = self.current_language
        
        # Language name mappings
        language_names = {
            'en': 'English',
            'es': 'Español',
            'fr': 'Français',
            'de': 'Deutsch',
            'it': 'Italiano',
            'pt': 'Português',
            'ru': 'Русский',
            'zh': '中文',
            'ja': '日本語',
            'ko': '한국어'
        }
        
        return language_names.get(language_code, language_code.upper())
    
    def add_language(self, language_code, translations_dict):
        """
        Add a new language with translations.
        
        Args:
            language_code (str): Language code
            translations_dict (dict): Dictionary of translations
        """
        self.translations[language_code] = translations_dict
        logger.info(f"Added language: {language_code}")
    
    def save_language_file(self, language_code, file_path=None):
        """
        Save language translations to a file.
        
        Args:
            language_code (str): Language code to save
            file_path (str, optional): File path, defaults to languages directory
            
        Returns:
            bool: True if successful, False otherwise
        """
        if language_code not in self.translations:
            logger.error(f"Language '{language_code}' not found")
            return False
        
        if file_path is None:
            file_path = os.path.join(self.languages_dir, f"{language_code}.json")
        
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.translations[language_code], f, 
                         indent=4, ensure_ascii=False, sort_keys=True)
            
            logger.info(f"Saved language file: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save language file: {e}")
            return False
    
    def export_current_language(self, export_path):
        """
        Export current language to a file.
        
        Args:
            export_path (str): Path to export file
            
        Returns:
            bool: True if successful, False otherwise
        """
        return self.save_language_file(self.current_language, export_path)
    
    def import_language_file(self, file_path):
        """
        Import language from a file.
        
        Args:
            file_path (str): Path to language file
            
        Returns:
            str or None: Language code if successful, None otherwise
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                translations = json.load(f)
            
            # Determine language code from filename
            filename = os.path.basename(file_path)
            language_code = os.path.splitext(filename)[0]
            
            self.translations[language_code] = translations
            logger.info(f"Imported language '{language_code}' from {file_path}")
            return language_code
            
        except Exception as e:
            logger.error(f"Failed to import language file: {e}")
            return None
