#!/usr/bin/env python3
"""
SF-Encryptor - Main Entry Point
A secure file encryption application with modern UI and plugin architecture.

Author: Surya B
Version: 1.3.0.0
GitHub: https://github.com/Suryabx
Email: myselfsuryaaz@gmail.com
"""

import sys
import os
import logging

# Add the project root to Python path for imports
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt

from ui.main_window import MainWindow
from utils.helpers import setup_directories, setup_logging, get_app_icon_path
from core.plugin_manager import PluginManager
from core.key_manager import KeyManager
from utils.localization import LocalizationManager

# Application constants
APP_NAME = "SF-Encryptor"
APP_VERSION = "3.0.0"
DEVELOPER_NAME = "Surya B"
DEVELOPER_EMAIL = "sfencryptor@gmail.com"
GITHUB_URL = "https://sfencryptor.dev/"

def main():
    """Main application entry point."""
    # Create QApplication instance
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(DEVELOPER_NAME)
    
    # Setup application directories and logging
    setup_directories()
    logger = setup_logging(APP_NAME)
    
    logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
    
    try:
        # Set application icon
        icon_path = get_app_icon_path()
        if icon_path and os.path.exists(icon_path):
            app.setWindowIcon(QIcon(icon_path))
        
        # Initialize core components
        localization_manager = LocalizationManager()
        key_manager = KeyManager()
        
        # Load application settings
        from utils.helpers import load_settings
        app_settings = load_settings()
        
        # Initialize plugin manager with settings
        plugin_manager = PluginManager(app_settings)
        
        # Create and show main window
        main_window = MainWindow(
            plugin_manager=plugin_manager,
            key_manager=key_manager,
            localization_manager=localization_manager,
            app_settings=app_settings
        )
        
        main_window.show()
        
        logger.info("Application initialized successfully")
        
        # Start the application event loop
        exit_code = app.exec()
        
        logger.info(f"{APP_NAME} closed with exit code: {exit_code}")
        return exit_code
        
    except Exception as e:
        logger.error(f"Fatal error during application startup: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
