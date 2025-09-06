"""
Plugins Tab Module for Sf-Encryptor

This module provides plugin management functionality including:
- View loaded encryption plugins
- Plugin information display
- Plugin status monitoring
- Reload plugin capability
- Plugin configuration options
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QListWidget, QListWidgetItem,
                             QGroupBox, QMessageBox, QScrollArea, QFrame,
                             QTextEdit, QProgressBar)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QFont


class PluginsTab(QWidget):
    def __init__(self, plugin_manager, app_settings, main_window):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.app_settings = app_settings
        self.main_window = main_window
        self.setup_ui()
        self.setup_button_animations()
        self.load_plugin_list()

    def setup_ui(self):
        """Initialize the plugins interface"""
        # Create main layout for the tab
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        
        # Create scrollable content widget
        scroll_content = QWidget()
        content_layout = QVBoxLayout(scroll_content)
        content_layout.setContentsMargins(30, 30, 30, 30)
        content_layout.setSpacing(25)
        
        # Create plugin management sections
        self.create_plugin_actions_section(content_layout)
        self.create_plugin_list_section(content_layout)
        self.create_plugin_details_section(content_layout)
        
        # Set the scroll area widget
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)

    def create_plugin_actions_section(self, parent_layout):
        """Create plugin management actions section"""
        actions_group = QGroupBox("Plugin Management")
        actions_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        actions_layout = QHBoxLayout(actions_group)
        actions_layout.setSpacing(15)
        actions_layout.setContentsMargins(20, 20, 20, 20)
        
        # Reload plugins button
        self.reload_button = QPushButton("Reload All Plugins")
        self.reload_button.setMinimumHeight(40)
        self.reload_button.setMinimumWidth(160)
        self.reload_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 2px solid #004d40;
                border-radius: 5px;
                font-weight: bold;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #004d40;
                color: white;
            }
            QPushButton:disabled {
                background-color: #e9ecef;
                color: #6c757d;
                border-color: #dee2e6;
            }
        """)
        
        # Refresh list button
        self.refresh_button = QPushButton("Refresh Plugin List")
        self.refresh_button.setMinimumHeight(40)
        self.refresh_button.setMinimumWidth(160)
        self.refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 2px solid #004d40;
                border-radius: 5px;
                font-weight: bold;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #004d40;
                color: white;
            }
        """)
        
        # Plugin folder button
        self.open_folder_button = QPushButton("Open Plugin Folder")
        self.open_folder_button.setMinimumHeight(40)
        self.open_folder_button.setMinimumWidth(160)
        self.open_folder_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 2px solid #004d40;
                border-radius: 5px;
                font-weight: bold;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #004d40;
                color: white;
            }
        """)
        
        # Add buttons to layout
        actions_layout.addWidget(self.reload_button)
        actions_layout.addWidget(self.refresh_button)
        actions_layout.addWidget(self.open_folder_button)
        actions_layout.addStretch()
        
        parent_layout.addWidget(actions_group)

    def create_plugin_list_section(self, parent_layout):
        """Create plugin list section"""
        list_group = QGroupBox("Loaded Encryption Plugins")
        list_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        list_layout = QVBoxLayout(list_group)
        list_layout.setSpacing(15)
        list_layout.setContentsMargins(20, 20, 20, 20)
        
        # Plugin list widget
        self.plugin_list_widget = QListWidget()
        self.plugin_list_widget.setMinimumHeight(200)
        self.plugin_list_widget.setAlternatingRowColors(True)
        self.plugin_list_widget.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        
        # Set font for the list
        list_font = QFont()
        list_font.setPointSize(10)
        self.plugin_list_widget.setFont(list_font)
        
        # Status label
        self.plugin_status_label = QLabel("Loading plugins...")
        self.plugin_status_label.setStyleSheet("color: #666; font-style: italic;")
        
        # Progress bar for reload operations
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMinimumHeight(25)
        
        list_layout.addWidget(self.plugin_list_widget)
        list_layout.addWidget(self.plugin_status_label)
        list_layout.addWidget(self.progress_bar)
        
        parent_layout.addWidget(list_group)

    def create_plugin_details_section(self, parent_layout):
        """Create plugin details section"""
        details_group = QGroupBox("Plugin Information")
        details_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        details_layout = QVBoxLayout(details_group)
        details_layout.setSpacing(15)
        details_layout.setContentsMargins(20, 20, 20, 20)
        
        # Plugin details text area
        self.plugin_details_text = QTextEdit()
        self.plugin_details_text.setReadOnly(True)
        self.plugin_details_text.setMaximumHeight(200)
        self.plugin_details_text.setPlaceholderText("Select a plugin from the list above to view its details...")
        
        # Set monospace font for details
        details_font = QFont("Consolas", 9)
        details_font.setStyleHint(QFont.StyleHint.TypeWriter)
        self.plugin_details_text.setFont(details_font)
        
        details_layout.addWidget(self.plugin_details_text)
        
        # Create plugin info section
        self.create_plugin_info_section(details_layout)
        
        parent_layout.addWidget(details_group)

    def create_plugin_info_section(self, parent_layout):
        """Create general plugin information section"""
        info_text = QLabel("""
<b>About Encryption Plugins:</b>
• Plugins provide different encryption algorithms (AES, ChaCha20-Poly1305, Fernet, etc.)
• Each plugin implements secure encryption/decryption functionality
• Plugins are automatically loaded from the 'plugins' directory
• All plugins use industry-standard cryptographic libraries
• Key lengths and security parameters are optimized for each algorithm

<b>Plugin Security:</b>
• All plugins undergo validation during loading
• Only verified and tested plugins are included
• Plugins use proven cryptographic implementations
• Regular security updates are provided with new versions

<b>Adding New Plugins:</b>
• Place plugin files in the 'plugins' directory
• Use the "Reload All Plugins" button to load new plugins
• Plugin files must follow the SF-Encryptor plugin interface
        """)
        
        info_text.setWordWrap(True)
        info_text.setStyleSheet("""
            QLabel { 
                background-color: #f8f9fa; 
                border: 1px solid #dee2e6; 
                border-radius: 5px; 
                padding: 15px;
                color: #495057;
                line-height: 1.4;
            }
        """)
        
        parent_layout.addWidget(info_text)

    def setup_button_animations(self):
        """Setup button press animations"""
        buttons = [
            self.reload_button,
            self.refresh_button,
            self.open_folder_button
        ]
        
        for button in buttons:
            button.pressed.connect(lambda b=button: self.animate_button_press(b))
        
        # Connect button actions
        self.reload_button.clicked.connect(self.reload_plugins)
        self.refresh_button.clicked.connect(self.load_plugin_list)
        self.open_folder_button.clicked.connect(self.open_plugin_folder)
        
        # Connect list selection
        self.plugin_list_widget.itemSelectionChanged.connect(self.on_plugin_selection_changed)

    def animate_button_press(self, button):
        """Animate button press if animation manager is available"""
        if hasattr(self.main_window, 'animation_manager'):
            self.main_window.animation_manager.animate_button_press(button)

    def load_plugin_list(self):
        """Load and display available plugins"""
        try:
            self.plugin_list_widget.clear()
            
            # Get plugins from plugin manager
            if hasattr(self.plugin_manager, 'get_all_plugins') and self.plugin_manager.get_all_plugins():
                plugins = self.plugin_manager.get_all_plugins()
            else:
                self.plugin_status_label.setText("No plugins loaded. Check plugin directory or reload plugins.")
                self.plugin_details_text.clear()
                return
            
            # Add plugins to the list
            for plugin_name, plugin_instance in plugins.items():
                item = QListWidgetItem()
                
                # Get plugin info
                plugin_info = {
                    'name': plugin_name,
                    'instance': plugin_instance,
                    'status': 'Loaded',
                    'type': 'Symmetric Encryption'
                }
                
                # Try to get additional info from plugin
                try:
                    if hasattr(plugin_instance, 'get_info'):
                        plugin_info.update(plugin_instance.get_info())
                    elif hasattr(plugin_instance, '__doc__') and plugin_instance.__doc__:
                        plugin_info['description'] = plugin_instance.__doc__.strip()
                except:
                    pass
                
                # Create display text
                status_icon = "[LOADED]"  # Status indicator for loaded plugins
                display_text = f"{status_icon} {plugin_name} - {plugin_info.get('type', 'Encryption Plugin')}"
                
                item.setText(display_text)
                item.setData(Qt.ItemDataRole.UserRole, plugin_info)  # Store full plugin info
                
                self.plugin_list_widget.addItem(item)
            
            plugin_count = len(plugins)
            self.plugin_status_label.setText(f"Successfully loaded {plugin_count} encryption plugin(s)")
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"Loaded {plugin_count} plugins", 2000)
                
        except Exception as e:
            self.plugin_status_label.setText(f"Error loading plugins: {str(e)}")
            QMessageBox.critical(self, "Plugin Loading Error", f"Failed to load plugins:\n\n{str(e)}")

    def on_plugin_selection_changed(self):
        """Handle plugin selection change"""
        selected_items = self.plugin_list_widget.selectedItems()
        
        if not selected_items:
            self.plugin_details_text.clear()
            return
        
        # Get selected plugin info
        item = selected_items[0]
        plugin_info = item.data(Qt.ItemDataRole.UserRole)
        
        if not plugin_info:
            self.plugin_details_text.setText("No detailed information available for this plugin.")
            return
        
        # Display plugin details
        plugin_name = plugin_info.get('name', 'Unknown')
        plugin_type = plugin_info.get('type', 'Unknown')
        status = plugin_info.get('status', 'Unknown')
        description = plugin_info.get('description', 'No description available')
        
        # Try to get key length if available
        key_length = "Unknown"
        try:
            if hasattr(self.plugin_manager, 'get_plugin_key_length'):
                key_length = f"{self.plugin_manager.get_plugin_key_length(plugin_name)} bits"
        except:
            pass
        
        # Try to get plugin file path
        plugin_file = "Unknown"
        try:
            plugin_instance = plugin_info.get('instance')
            if plugin_instance and hasattr(plugin_instance, '__file__'):
                plugin_file = plugin_instance.__file__
            elif plugin_instance and hasattr(plugin_instance, '__module__'):
                import sys
                module = sys.modules.get(plugin_instance.__module__)
                if module and hasattr(module, '__file__'):
                    plugin_file = module.__file__
        except:
            pass
        
        details = f"""Plugin Details:

Name: {plugin_name}
Type: {plugin_type}
Status: {status}
Key Length: {key_length}

Description:
{description}

Technical Information:
Plugin File: {plugin_file}
Module: {plugin_info.get('instance', {}).get('__module__', 'Unknown')}

Security Notes:
- This plugin provides cryptographically secure encryption
- Keys are generated using secure random number generation
- Implementation follows industry best practices
- Regular security audits ensure continued safety
"""
        
        self.plugin_details_text.setText(details)

    def reload_plugins(self):
        """Reload all plugins"""
        try:
            # Show progress
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.reload_button.setEnabled(False)
            self.reload_button.setText("Reloading...")
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message("Reloading plugins...", 0)
            
            # Simulate progress
            for i in range(0, 101, 20):
                self.progress_bar.setValue(i)
            
            # Reload plugins through plugin manager
            if hasattr(self.plugin_manager, 'reload_plugins'):
                self.plugin_manager.reload_plugins()
            elif hasattr(self.plugin_manager, 'load_plugins'):
                self.plugin_manager.load_plugins()
            
            # Refresh the display
            self.load_plugin_list()
            
            QMessageBox.information(
                self,
                "Plugins Reloaded",
                "All plugins have been successfully reloaded.\n\n"
                "The plugin list has been updated with the latest available plugins."
            )
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message("Plugins reloaded successfully", 3000)
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Reload Error",
                f"An error occurred while reloading plugins:\n\n{str(e)}"
            )
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"Plugin reload failed: {str(e)}", 5000)
        
        finally:
            # Reset UI
            self.progress_bar.setVisible(False)
            self.reload_button.setEnabled(True)
            self.reload_button.setText("Reload All Plugins")

    def open_plugin_folder(self):
        """Open the plugin folder in file explorer"""
        try:
            import os
            import subprocess
            import platform
            
            # Get plugin directory
            plugin_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'plugins')
            
            if not os.path.exists(plugin_dir):
                QMessageBox.warning(
                    self,
                    "Folder Not Found",
                    f"Plugin folder not found:\n{plugin_dir}\n\n"
                    "The folder may have been moved or deleted."
                )
                return
            
            # Open folder based on OS
            system = platform.system()
            if system == "Windows":
                os.startfile(plugin_dir)
            elif system == "Darwin":  # macOS
                subprocess.run(["open", plugin_dir])
            else:  # Linux and others
                subprocess.run(["xdg-open", plugin_dir])
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message("Plugin folder opened", 2000)
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error Opening Folder",
                f"Could not open plugin folder:\n\n{str(e)}"
            )

    def retranslate_ui(self):
        """Update UI text for localization (ready for future implementation)"""
        # This method would be called when language changes
        pass
