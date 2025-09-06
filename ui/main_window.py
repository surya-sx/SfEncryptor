"""
Main Window - SF-Encryptor Application Main Window.

This module provides the MainWindow class which serves as the primary
application window containing all tabs and core functionality.
"""

import os
import sys
import json
import logging
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QPushButton, QButtonGroup, QStatusBar, QMessageBox, QApplication
)
from PyQt6.QtGui import QIcon, QGuiApplication
from PyQt6.QtCore import Qt, pyqtSignal, QTimer

from utils.helpers import load_settings, save_settings, setup_directories, get_app_icon_path
from utils.localization import LocalizationManager
from ui.tabs.settings_tab import SettingsTab
from ui.tabs.file_integrity_tab import FileIntegrityTab
from ui.tabs.encrypt_tab import EncryptTab
from ui.tabs.decrypt_tab import DecryptTab
from ui.tabs.generate_keys_tab import GenerateKeysTab
from ui.tabs.key_management_tab import KeyManagementTab
from ui.tabs.plugins_tab import PluginsTab
from ui.tabs.logs_tab import LogsTab
from ui.tabs.about_tab import AboutTab

logger = logging.getLogger(__name__)

# Modern UI Theme
THEME_PRIMARY_BG = "#e0f7fa"  # Lighter, more vibrant sky blue
THEME_SECONDARY_BG = "#b2ebf2" # Brighter, slightly darker sky blue
THEME_FOREGROUND = "#004d40"    # Dark teal for high contrast text
THEME_ACCENT = "#00bcd4"        # Cyan for vibrant accents
THEME_ACCENT_DARK = "#00838f"   # Darker cyan for hover
THEME_BORDER = "#80deea"        # Light cyan border
THEME_CARD_BG = "#ffffff"       # White card background with shadow

MODERN_STYLESHEET = f"""
    QWidget {{
        background-color: {THEME_PRIMARY_BG};
        color: {THEME_FOREGROUND};
        font-family: "Segoe UI", "Inter", sans-serif;
        font-size: 10pt;
    }}
    QMainWindow {{
        background-color: {THEME_PRIMARY_BG};
    }}
    #MainContainer {{
        background-color: {THEME_PRIMARY_BG};
    }}
    #Sidebar {{
        background-color: {THEME_SECONDARY_BG};
        border-right: 1px solid {THEME_BORDER};
        border-radius: 0 15px 15px 0;
        padding: 10px;
    }}
    #NavButton {{
        background-color: transparent;
        border: none;
        padding: 12px 15px;
        text-align: left;
        border-radius: 8px;
        font-weight: 500;
        color: {THEME_FOREGROUND};
        font-size: 11pt;
    }}
    #NavButton:hover {{
        background-color: {THEME_BORDER};
    }}
    #NavButton:checked {{
        background-color: {THEME_ACCENT};
        color: white;
        font-weight: bold;
    }}
    #MainContentArea {{
        background-color: {THEME_PRIMARY_BG};
        padding: 20px;
    }}
    QPushButton {{
        background-color: {THEME_ACCENT};
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 8px;
        font-weight: bold;
    }}
    QPushButton:hover {{
        background-color: {THEME_ACCENT_DARK};
    }}
    QPushButton:pressed {{
        background-color: #1e6091;
    }}
    QPushButton:disabled {{
        background-color: {THEME_BORDER};
        color: #6c7a89;
    }}
"""

class MainWindow(QMainWindow):
    """Main application window for SF-Encryptor."""
    
    log_signal = pyqtSignal(str, str)  # level, message
    
    def __init__(self, plugin_manager, key_manager, localization_manager, app_settings):
        """
        Initialize the main window.
        
        Args:
            plugin_manager: Plugin management instance
            key_manager: Key management instance  
            localization_manager: Localization management instance
            app_settings: Application settings dictionary
        """
        super().__init__()
        
        # Store references to managers
        self.plugin_manager = plugin_manager
        self.key_manager = key_manager
        self.localization_manager = localization_manager
        
        # Load settings if not provided
        if not app_settings:
            from utils.helpers import load_settings
            self.app_settings = load_settings()
        else:
            self.app_settings = app_settings
        
        # Get directories
        self.directories = setup_directories()
        
        logger.info("Initializing main window")
        
        # Setup UI
        self.setup_ui()
        self.setup_status_bar()
        self.apply_theme()
        
        # Initialize with welcome message
        self.show_status_message("SF FileManager initialized successfully", 3000)
        
        logger.info("Main window initialized successfully")
    
    def setup_ui(self):
        """Set up the main user interface."""
        # Set window properties
        self.setWindowTitle("SF-Encryptor v3.0.0 - Secure File Encryption")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        
        # Set application icon
        icon_path = get_app_icon_path()
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))
        
        # Create main container
        main_container = QWidget()
        main_container.setObjectName("MainContainer")
        main_layout = QHBoxLayout(main_container)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setCentralWidget(main_container)
        
        # Create sidebar
        self.sidebar_widget = QWidget()
        self.sidebar_widget.setObjectName("Sidebar")
        self.sidebar_widget.setFixedWidth(250)
        
        self.sidebar_layout = QVBoxLayout(self.sidebar_widget)
        self.sidebar_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.sidebar_layout.setContentsMargins(10, 20, 10, 10)
        
        # Create content area
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setObjectName("MainContentArea")
        
        # Create navigation buttons and tabs (simplified for now)
        self.create_navigation_and_tabs()
        
        # Add widgets to main layout
        main_layout.addWidget(self.sidebar_widget)
        main_layout.addWidget(self.stacked_widget, 1)
        
        # Set initial tab
        if self.nav_buttons:
            self.nav_buttons[0].setChecked(True)
            self.stacked_widget.setCurrentIndex(0)
    
    def create_navigation_and_tabs(self):
        """Create navigation buttons and corresponding tabs."""
        from PyQt6.QtWidgets import QLabel
        
        # Create fully functional tabs
        self.tabs = []
        tab_configs = [
            ("Encrypt", "encrypt.png"),
            ("Decrypt", "decrypt.png"),
            ("Generate Keys", "fingerprint.png"),
            ("Key Management", "fingerprint.png"),
            ("File Integrity", "fingerprint.png"),
            ("Plugins", "plugins.png"),
            ("Settings", "settings.png"),
            ("Logs", "log.png"),
            ("About", "about.png")
        ]
        
        # Create tabs and navigation buttons
        self.nav_buttons = []
        self.button_group = QButtonGroup(self)
        
        for i, (name, icon_filename) in enumerate(tab_configs):
            # Create fully functional tab content
            if name == "Encrypt":
                # Use the real EncryptTab
                tab_widget = EncryptTab(self.plugin_manager, self.app_settings, self)
            elif name == "Decrypt":
                # Use the real DecryptTab
                tab_widget = DecryptTab(self.plugin_manager, self.app_settings, self)
            elif name == "Generate Keys":
                # Use the real GenerateKeysTab
                tab_widget = GenerateKeysTab(self.plugin_manager, self.key_manager, self.app_settings, self)
            elif name == "Key Management":
                # Use the real KeyManagementTab
                tab_widget = KeyManagementTab(self.key_manager, self.app_settings, self)
            elif name == "Settings":
                # Use the real SettingsTab
                tab_widget = SettingsTab(self.plugin_manager, self.app_settings, self)
            elif name == "File Integrity":
                # Use the real FileIntegrityTab  
                tab_widget = FileIntegrityTab(self)
            elif name == "Plugins":
                # Use the real PluginsTab
                tab_widget = PluginsTab(self.plugin_manager, self.app_settings, self)
            elif name == "Logs":
                # Use the real LogsTab
                tab_widget = LogsTab(self.app_settings, self)
            elif name == "About":
                # Use the real AboutTab
                tab_widget = AboutTab(self.app_settings, self)
            else:
                # Fallback - this should not happen in production
                tab_widget = QWidget()
                tab_layout = QVBoxLayout(tab_widget)
                
                # Load icon for fallback
                icon_path = os.path.join(self.directories['assets'], icon_filename)
                icon_display = ""
                if os.path.exists(icon_path):
                    icon_display = f"[IMG] {name}"
                else:
                    icon_display = f"[FILE] {name}"
                
                error_label = QLabel(f"{icon_display} Tab\n\nTab loading error - please contact support.")
                error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                error_label.setStyleSheet("""
                    QLabel {
                        font-size: 16pt;
                        color: #dc3545;
                        padding: 40px;
                        background-color: white;
                        border-radius: 10px;
                        border: 1px solid #dc3545;
                    }
                """)
                tab_layout.addWidget(error_label)
            
            self.tabs.append(tab_widget)
            self.stacked_widget.addWidget(tab_widget)
            
            # Create navigation button with icon
            nav_button = QPushButton(f"  {name}")
            nav_button.setObjectName("NavButton")
            nav_button.setCheckable(True)
            nav_button.clicked.connect(lambda checked, index=i: self.switch_tab(index))
            
            # Set button icon
            icon_path = os.path.join(self.directories['assets'], icon_filename)
            if os.path.exists(icon_path):
                nav_button.setIcon(QIcon(icon_path))
                nav_button.setIconSize(QIcon.fromTheme("").actualSize(QIcon.fromTheme("").actualSize(nav_button.size()) or nav_button.size()))
                # Set a reasonable icon size
                from PyQt6.QtCore import QSize
                nav_button.setIconSize(QSize(20, 20))
            
            self.nav_buttons.append(nav_button)
            self.button_group.addButton(nav_button, i)
            self.sidebar_layout.addWidget(nav_button)
        
        # Add stretch to push buttons to top
        self.sidebar_layout.addStretch()
    
    def switch_tab(self, index):
        """Switch to the specified tab."""
        if 0 <= index < self.stacked_widget.count():
            self.stacked_widget.setCurrentIndex(index)
            
            # Update button states
            for i, button in enumerate(self.nav_buttons):
                button.setChecked(i == index)
            
            # Update status bar
            tab_names = ["Encrypt", "Decrypt", "Generate Keys", "Key Management", 
                        "File Integrity", "Plugins", "Settings", "Logs", "About"]
            if index < len(tab_names):
                self.show_status_message(f"Switched to {tab_names[index]} tab")
    
    def setup_status_bar(self):
        """Set up the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
    
    def apply_theme(self):
        """Apply the modern theme to the application."""
        self.setStyleSheet(MODERN_STYLESHEET)
    
    def show_status_message(self, message, timeout=5000):
        """
        Show a message in the status bar.
        
        Args:
            message (str): Message to display
            timeout (int): Timeout in milliseconds (0 for permanent)
        """
        if hasattr(self, 'status_bar'):
            self.status_bar.showMessage(message, timeout)
        logger.info(f"Status: {message}")
    
    def optimize_window_size(self):
        """Optimize window size based on screen resolution."""
        screen = QGuiApplication.primaryScreen()
        if screen:
            screen_geometry = screen.availableGeometry()
            screen_width = screen_geometry.width()
            screen_height = screen_geometry.height()
            
            # Calculate optimal window size
            if screen_width >= 1920 and screen_height >= 1080:
                window_width = 1400
                window_height = 900
                min_width = 1200
                min_height = 800
            elif screen_width >= 1366 and screen_height >= 768:
                window_width = min(1200, int(screen_width * 0.8))
                window_height = min(800, int(screen_height * 0.8))
                min_width = 1000
                min_height = 700
            else:
                window_width = min(1000, int(screen_width * 0.9))
                window_height = min(700, int(screen_height * 0.9))
                min_width = 800
                min_height = 600
            
            self.setMinimumSize(min_width, min_height)
            self.resize(window_width, window_height)
            
            # Center window
            window_geometry = self.frameGeometry()
            center_point = screen_geometry.center()
            window_geometry.moveCenter(center_point)
            self.move(window_geometry.topLeft())
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Save settings before closing
        save_settings(self.app_settings)
        
        # Ask for confirmation if enabled
        if self.app_settings.get("confirm_on_exit", True):
            reply = QMessageBox.question(
                self,
                "Confirm Exit",
                "Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                logger.info("Application closing by user request")
                event.accept()
            else:
                event.ignore()
        else:
            logger.info("Application closing")
            event.accept()
    
    def load_settings(self):
        """Load application settings (fallback method)."""
        return load_settings()
    
    def save_settings(self):
        """Save application settings."""
        save_settings(self.app_settings)
        logger.info("Settings saved")
    
    def get_current_tab_index(self):
        """Get the index of the currently active tab."""
        return self.stacked_widget.currentIndex()
    
    def get_localized_string(self, key, **kwargs):
        """Get a localized string."""
        return self.localization_manager.get_string(key, **kwargs)
    
    def log_message(self, level, message):
        """Log a message and emit signal for log viewer."""
        getattr(logger, level.lower(), logger.info)(message)
        self.log_signal.emit(level, message)
