"""
Helper utilities for SF-Encryptor application.

This module provides various utility functions for:
- Directory and file management
- Logging setup
- Application configuration
- System-specific operations
"""

import os
import sys
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

# Application constants
APP_NAME = "SF FileManager"
APP_VERSION = "1.3.0.0"

def setup_directories():
    """
    Set up application directories for data storage.
    
    Returns:
        dict: Dictionary containing directory paths
    """
    # Determine base directory for PyInstaller compatibility
    if getattr(sys, 'frozen', False):
        base_dir = sys._MEIPASS
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # OS-specific application data directory
    if sys.platform == "win32":
        app_data_base = os.environ.get("LOCALAPPDATA", 
                                      os.path.join(os.path.expanduser("~"), "AppData", "Local"))
    elif sys.platform == "darwin":
        app_data_base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        app_data_base = os.environ.get("XDG_DATA_HOME", 
                                      os.path.join(os.path.expanduser("~"), ".local", "share"))
    
    # Create directory structure
    app_specific_dir = os.path.join(app_data_base, APP_NAME)
    directories = {
        'base': base_dir,
        'app_data': app_specific_dir,
        'logs': os.path.join(app_specific_dir, "logs"),
        'settings': app_specific_dir,
        'languages': os.path.join(app_specific_dir, "languages"),
        'keys': os.path.join(app_specific_dir, "keys"),
        'plugins': os.path.join(base_dir, "plugins"),
        'assets': os.path.join(base_dir, "assets")
    }
    
    # Create directories if they don't exist
    for dir_path in directories.values():
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
    
    return directories

def setup_logging(app_name=APP_NAME, log_level=logging.INFO):
    """
    Set up application logging.
    
    Args:
        app_name (str): Application name for logger
        log_level (int): Logging level
        
    Returns:
        logging.Logger: Configured logger instance
    """
    directories = setup_directories()
    log_file = os.path.join(directories['logs'], f"{app_name.lower().replace(' ', '_')}.log")
    
    # Create logger
    logger = logging.getLogger(app_name)
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    try:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        logger.info(f"Logging initialized - Log file: {log_file}")
        
    except Exception as e:
        logger.warning(f"Failed to setup file logging: {e}")
    
    return logger

def get_app_icon_path():
    """
    Get the path to the application icon.
    
    Returns:
        str or None: Path to icon file or None if not found
    """
    directories = setup_directories()
    icon_files = ["Sf_encryptor.png", "Sf_encryptor.ico", "icon.png", "icon.ico"]
    
    for icon_file in icon_files:
        icon_path = os.path.join(directories['assets'], icon_file)
        if os.path.exists(icon_path):
            return icon_path
    
    return None

def load_settings(settings_file=None):
    """
    Load application settings from JSON file.
    
    Args:
        settings_file (str, optional): Path to settings file
        
    Returns:
        dict: Settings dictionary
    """
    if not settings_file:
        directories = setup_directories()
        settings_file = os.path.join(directories['settings'], "settings.json")
    
    default_settings = {
        "theme": "system",
        "language": "en",
        "log_level": "INFO",
        "auto_clear_logs_startup": False,
        "confirm_overwrite_files": True,
        "enable_expert_mode": False,
        "file_chunk_size_kb": 1024,
        "default_encryption_algorithm": "",
        "default_output_folder": "",
        "max_log_size_mb": 10,
        "enable_log_rotation": True,
        "confirm_on_exit": True,
        "enabled_plugins": {},
        "compression_settings": {
            "default_algorithm": "auto",
            "default_level": 6,
            "default_priority": "balanced"
        },
        "animation_settings": {
            "enable_animations": True,
            "transition_effects": True,
            "fade_duration_ms": 300,
            "slide_duration_ms": 400,
            "animation_speed": 5
        }
    }
    
    try:
        if os.path.exists(settings_file):
            with open(settings_file, 'r', encoding='utf-8') as f:
                loaded_settings = json.load(f)
            
            # Merge with defaults (add any missing keys)
            for key, value in default_settings.items():
                if key not in loaded_settings:
                    loaded_settings[key] = value
            
            return loaded_settings
        else:
            return default_settings.copy()
            
    except Exception as e:
        logging.error(f"Failed to load settings: {e}")
        return default_settings.copy()

def save_settings(settings, settings_file=None):
    """
    Save application settings to JSON file.
    
    Args:
        settings (dict): Settings dictionary to save
        settings_file (str, optional): Path to settings file
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not settings_file:
        directories = setup_directories()
        settings_file = os.path.join(directories['settings'], "settings.json")
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(settings_file), exist_ok=True)
        
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=4, ensure_ascii=False)
        
        logging.info(f"Settings saved to {settings_file}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to save settings: {e}")
        return False

def export_settings(settings, export_path):
    """
    Export settings to a specified file.
    
    Args:
        settings (dict): Settings to export
        export_path (str): Path to export file
        
    Returns:
        bool: True if successful, False otherwise
    """
    return save_settings(settings, export_path)

def import_settings(import_path):
    """
    Import settings from a specified file.
    
    Args:
        import_path (str): Path to import file
        
    Returns:
        dict or None: Imported settings or None if failed
    """
    try:
        with open(import_path, 'r', encoding='utf-8') as f:
            imported_settings = json.load(f)
        
        logging.info(f"Settings imported from {import_path}")
        return imported_settings
        
    except Exception as e:
        logging.error(f"Failed to import settings: {e}")
        return None

def get_system_info():
    """
    Get system information for debugging.
    
    Returns:
        dict: System information
    """
    return {
        "platform": sys.platform,
        "python_version": sys.version,
        "executable": sys.executable,
        "frozen": getattr(sys, 'frozen', False),
        "app_name": APP_NAME,
        "app_version": APP_VERSION
    }

def format_file_size(size_bytes):
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes (int): Size in bytes
        
    Returns:
        str: Formatted size string
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    
    while size_bytes >= 1024.0 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

def validate_file_path(file_path):
    """
    Validate that a file path exists and is accessible.
    
    Args:
        file_path (str): Path to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not file_path:
        return False, "No file path provided"
    
    if not os.path.exists(file_path):
        return False, "File does not exist"
    
    if not os.path.isfile(file_path):
        return False, "Path is not a file"
    
    try:
        # Test read access
        with open(file_path, 'rb') as f:
            f.read(1)
        return True, "File is valid"
    except PermissionError:
        return False, "Permission denied"
    except Exception as e:
        return False, f"File access error: {str(e)}"

def validate_directory_path(dir_path):
    """
    Validate that a directory path exists and is accessible.
    
    Args:
        dir_path (str): Directory path to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not dir_path:
        return False, "No directory path provided"
    
    if not os.path.exists(dir_path):
        return False, "Directory does not exist"
    
    if not os.path.isdir(dir_path):
        return False, "Path is not a directory"
    
    try:
        # Test write access
        test_file = os.path.join(dir_path, ".write_test")
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        return True, "Directory is valid"
    except PermissionError:
        return False, "Permission denied"
    except Exception as e:
        return False, f"Directory access error: {str(e)}"

def generate_unique_filename(base_path, extension=""):
    """
    Generate a unique filename by adding a counter if necessary.
    
    Args:
        base_path (str): Base file path
        extension (str): File extension
        
    Returns:
        str: Unique file path
    """
    if extension and not extension.startswith('.'):
        extension = '.' + extension
    
    full_path = base_path + extension
    
    if not os.path.exists(full_path):
        return full_path
    
    counter = 1
    while True:
        name, ext = os.path.splitext(base_path)
        unique_path = f"{name}_{counter}{extension}"
        
        if not os.path.exists(unique_path):
            return unique_path
        
        counter += 1

def safe_filename(filename):
    """
    Create a safe filename by removing/replacing invalid characters.
    
    Args:
        filename (str): Original filename
        
    Returns:
        str: Safe filename
    """
    # Characters not allowed in filenames on Windows
    invalid_chars = '<>:"/\\|?*'
    
    safe_name = filename
    for char in invalid_chars:
        safe_name = safe_name.replace(char, '_')
    
    # Remove control characters
    safe_name = ''.join(char for char in safe_name if ord(char) >= 32)
    
    # Trim whitespace and dots from the end
    safe_name = safe_name.strip(' .')
    
    # Ensure it's not empty
    if not safe_name:
        safe_name = "untitled"
    
    return safe_name

def calculate_password_strength(password):
    """
    Calculate password strength score.
    
    Args:
        password (str): Password to evaluate
        
    Returns:
        tuple: (score, strength_text)
    """
    if not password:
        return 0, "No Password"
    
    score = 0
    
    # Length bonus
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    
    # Character variety
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    char_variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += char_variety
    
    # Determine strength
    if score <= 2:
        return score, "Weak"
    elif score <= 4:
        return score, "Medium"
    else:
        return score, "Strong"
