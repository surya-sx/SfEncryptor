"""
Settings Tab Module for Sf-Encryptor

This module provides a comprehensive settings interface with features including:
- Language selection (ready for future localization)
- Animation speed and effects configuration
- Default output folder selection with drag/drop support
- Default encryption algorithm selection
- Secure file shredding configuration
- Exit confirmation settings
- Logging configuration (size limits, rotation)
- Animation system settings (enable/disable, effects, durations)
- Settings export/import functionality
"""

import os
import json
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, 
                             QLabel, QComboBox, QSlider, QLineEdit, QPushButton, 
                             QCheckBox, QGroupBox, QSpinBox, QFileDialog, QMessageBox,
                             QScrollArea, QFrame)
from PyQt6.QtCore import Qt
from utils.drag_drop_widgets import DragDropLineEdit
from utils.localization import LocalizationManager


class SettingsTab(QWidget):
    def __init__(self, plugin_manager, app_settings, main_window):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.app_settings = app_settings
        self.main_window = main_window
        self.setup_ui()
        self.setup_button_animations()
        self.load_settings_to_ui()

    def setup_ui(self):
        """Initialize the complete settings interface with scrolling"""
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
        content_layout.setSpacing(25)  # Increased spacing between sections
        
        # Create settings sections with better spacing
        self.create_language_section(content_layout)
        self.create_animation_section(content_layout)
        self.create_default_folders_section(content_layout)
        self.create_encryption_section(content_layout)
        self.create_file_operations_section(content_layout)
        self.create_application_section(content_layout)
        self.create_logging_section(content_layout)
        self.create_advanced_animations_section(content_layout)
        self.create_import_export_section(content_layout)
        
        # Add stretch to push everything to top
        content_layout.addStretch()
        
        # Set the scroll area widget
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)

    def create_language_section(self, parent_layout):
        """Create language selection section (currently disabled)"""
        language_group = QGroupBox("Language")
        language_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        language_layout = QVBoxLayout(language_group)
        language_layout.setSpacing(12)
        language_layout.setContentsMargins(15, 15, 15, 15)
        
        language_info_layout = QHBoxLayout()
        language_info_layout.setSpacing(10)
        self.language_label = QLabel("Application Language:")
        self.language_dropdown = QComboBox()
        self.language_dropdown.addItems(["English (Default)"])
        self.language_dropdown.setEnabled(False)  # Currently disabled
        
        language_info_layout.addWidget(self.language_label)
        language_info_layout.addWidget(self.language_dropdown)
        language_info_layout.addStretch()
        
        language_layout.addLayout(language_info_layout)
        parent_layout.addWidget(language_group)

    def create_animation_section(self, parent_layout):
        """Create animation speed section"""
        animation_group = QGroupBox("Animation Settings")
        animation_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        animation_layout = QVBoxLayout(animation_group)
        animation_layout.setSpacing(12)
        animation_layout.setContentsMargins(15, 15, 15, 15)
        
        # Animation speed slider
        speed_layout = QHBoxLayout()
        speed_layout.setSpacing(10)
        self.animation_speed_label = QLabel("Animation Speed:")
        self.animation_speed_slider = QSlider(Qt.Orientation.Horizontal)
        self.animation_speed_slider.setRange(1, 10)
        self.animation_speed_slider.setValue(5)
        self.animation_speed_slider.valueChanged.connect(self.save_animation_speed)
        
        self.animation_speed_value_label = QLabel("5")
        self.animation_speed_value_label.setMinimumWidth(20)
        self.animation_speed_slider.valueChanged.connect(
            lambda v: self.animation_speed_value_label.setText(str(v))
        )
        
        speed_layout.addWidget(self.animation_speed_label)
        speed_layout.addWidget(self.animation_speed_slider, 1)
        speed_layout.addWidget(self.animation_speed_value_label)
        
        animation_layout.addLayout(speed_layout)
        parent_layout.addWidget(animation_group)

    def create_default_folders_section(self, parent_layout):
        """Create default output folder section"""
        folder_group = QGroupBox("Default Folders")
        folder_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        folder_layout = QVBoxLayout(folder_group)
        folder_layout.setSpacing(12)
        folder_layout.setContentsMargins(15, 15, 15, 15)
        
        # Default output folder
        output_layout = QHBoxLayout()
        output_layout.setSpacing(10)
        self.output_folder_label = QLabel("Default Output Folder:")
        self.default_output_folder_entry = DragDropLineEdit()
        self.default_output_folder_entry.setPlaceholderText("Select or drag a folder here...")
        self.default_output_folder_entry.setMinimumHeight(30)
        self.browse_output_folder_button = QPushButton("Browse")
        self.browse_output_folder_button.setMinimumWidth(80)
        self.browse_output_folder_button.setMinimumHeight(30)
        self.browse_output_folder_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 2px solid #004d40;
                border-radius: 5px;
                font-weight: bold;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #004d40;
                color: white;
            }
        """)
        self.browse_output_folder_button.clicked.connect(self.browse_default_output_folder)
        
        output_layout.addWidget(self.output_folder_label)
        output_layout.addWidget(self.default_output_folder_entry, 1)
        output_layout.addWidget(self.browse_output_folder_button)
        
        folder_layout.addLayout(output_layout)
        parent_layout.addWidget(folder_group)

    def create_encryption_section(self, parent_layout):
        """Create encryption algorithm selection section"""
        encryption_group = QGroupBox("Encryption Settings")
        encryption_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        encryption_layout = QVBoxLayout(encryption_group)
        encryption_layout.setSpacing(12)
        encryption_layout.setContentsMargins(15, 15, 15, 15)
        
        # Default encryption algorithm
        algo_layout = QHBoxLayout()
        algo_layout.setSpacing(10)
        self.encryption_algo_label = QLabel("Default Encryption Algorithm:")
        self.default_encryption_algo_dropdown = QComboBox()
        self.default_encryption_algo_dropdown.setMinimumHeight(30)
        self.default_encryption_algo_dropdown.currentTextChanged.connect(
            self.save_default_encryption_algo
        )
        
        algo_layout.addWidget(self.encryption_algo_label)
        algo_layout.addWidget(self.default_encryption_algo_dropdown)
        algo_layout.addStretch()
        
        encryption_layout.addLayout(algo_layout)
        parent_layout.addWidget(encryption_group)

    def create_file_operations_section(self, parent_layout):
        """Create file operations section"""
        file_ops_group = QGroupBox("File Operations")
        file_ops_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        file_ops_layout = QVBoxLayout(file_ops_group)
        file_ops_layout.setSpacing(12)
        file_ops_layout.setContentsMargins(15, 15, 15, 15)
        
        # Secure shredding passes
        shred_layout = QHBoxLayout()
        shred_layout.setSpacing(10)
        self.shred_passes_label = QLabel("Secure Shredding Passes:")
        self.default_shred_passes_entry = QLineEdit()
        self.default_shred_passes_entry.setPlaceholderText("0 for no shredding")
        self.default_shred_passes_entry.setMinimumHeight(30)
        self.default_shred_passes_entry.setMaximumWidth(200)
        self.default_shred_passes_entry.textChanged.connect(self.save_shred_passes_setting)
        
        shred_layout.addWidget(self.shred_passes_label)
        shred_layout.addWidget(self.default_shred_passes_entry)
        shred_layout.addStretch()
        
        file_ops_layout.addLayout(shred_layout)
        parent_layout.addWidget(file_ops_group)

    def create_application_section(self, parent_layout):
        """Create application behavior section"""
        app_group = QGroupBox("Application Behavior")
        app_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        app_layout = QVBoxLayout(app_group)
        app_layout.setSpacing(12)
        app_layout.setContentsMargins(15, 15, 15, 15)
        
        # Confirm on exit
        self.confirm_on_exit_checkbox = QCheckBox("Confirm before exiting the application")
        self.confirm_on_exit_checkbox.stateChanged.connect(self.save_confirm_on_exit_setting)
        
        app_layout.addWidget(self.confirm_on_exit_checkbox)
        parent_layout.addWidget(app_group)

    def create_logging_section(self, parent_layout):
        """Create logging configuration section"""
        logging_group = QGroupBox("Logging Settings")
        logging_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        logging_layout = QVBoxLayout(logging_group)
        logging_layout.setSpacing(12)
        logging_layout.setContentsMargins(15, 15, 15, 15)
        
        # Max log size
        log_size_layout = QHBoxLayout()
        log_size_layout.setSpacing(10)
        self.max_log_size_label = QLabel("Max Log File Size (MB):")
        self.max_log_size_entry = QLineEdit()
        self.max_log_size_entry.setPlaceholderText("5")
        self.max_log_size_entry.setMinimumHeight(30)
        self.max_log_size_entry.setMaximumWidth(200)
        self.max_log_size_entry.textChanged.connect(self.save_log_settings)
        
        log_size_layout.addWidget(self.max_log_size_label)
        log_size_layout.addWidget(self.max_log_size_entry)
        log_size_layout.addStretch()
        
        # Log rotation
        self.enable_log_rotation_checkbox = QCheckBox("Enable log rotation")
        self.enable_log_rotation_checkbox.stateChanged.connect(self.save_log_settings)
        
        logging_layout.addLayout(log_size_layout)
        logging_layout.addWidget(self.enable_log_rotation_checkbox)
        parent_layout.addWidget(logging_group)

    def create_advanced_animations_section(self, parent_layout):
        """Create advanced animation settings section"""
        advanced_anim_group = QGroupBox("Advanced Animation Settings")
        advanced_anim_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        advanced_anim_layout = QVBoxLayout(advanced_anim_group)
        advanced_anim_layout.setSpacing(12)
        advanced_anim_layout.setContentsMargins(15, 15, 15, 15)
        
        # Enable animations
        self.enable_animations_checkbox = QCheckBox("Enable animations")
        self.enable_animations_checkbox.stateChanged.connect(self.save_animation_settings)
        
        # Transition effects
        self.transition_effects_checkbox = QCheckBox("Enable transition effects")
        self.transition_effects_checkbox.stateChanged.connect(self.save_animation_settings)
        
        # Fade duration
        fade_layout = QHBoxLayout()
        fade_layout.setSpacing(10)
        self.fade_duration_label = QLabel("Fade Duration (ms):")
        self.fade_duration_spinbox = QSpinBox()
        self.fade_duration_spinbox.setRange(100, 1000)
        self.fade_duration_spinbox.setValue(300)
        self.fade_duration_spinbox.setMinimumHeight(30)
        self.fade_duration_spinbox.setMaximumWidth(150)
        self.fade_duration_spinbox.valueChanged.connect(self.save_animation_settings)
        
        fade_layout.addWidget(self.fade_duration_label)
        fade_layout.addWidget(self.fade_duration_spinbox)
        fade_layout.addStretch()
        
        # Slide duration
        slide_layout = QHBoxLayout()
        slide_layout.setSpacing(10)
        self.slide_duration_label = QLabel("Slide Duration (ms):")
        self.slide_duration_spinbox = QSpinBox()
        self.slide_duration_spinbox.setRange(100, 1000)
        self.slide_duration_spinbox.setValue(400)
        self.slide_duration_spinbox.setMinimumHeight(30)
        self.slide_duration_spinbox.setMaximumWidth(150)
        self.slide_duration_spinbox.valueChanged.connect(self.save_animation_settings)
        
        slide_layout.addWidget(self.slide_duration_label)
        slide_layout.addWidget(self.slide_duration_spinbox)
        slide_layout.addStretch()
        
        # Test animations button
        self.test_animations_button = QPushButton("Test Animations")
        self.test_animations_button.setMinimumHeight(35)
        self.test_animations_button.setMaximumWidth(150)
        self.test_animations_button.setStyleSheet("""
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
        self.test_animations_button.clicked.connect(self.test_animations)
        
        advanced_anim_layout.addWidget(self.enable_animations_checkbox)
        advanced_anim_layout.addWidget(self.transition_effects_checkbox)
        advanced_anim_layout.addLayout(fade_layout)
        advanced_anim_layout.addLayout(slide_layout)
        
        # Center the test button
        test_button_layout = QHBoxLayout()
        test_button_layout.addStretch()
        test_button_layout.addWidget(self.test_animations_button)
        test_button_layout.addStretch()
        advanced_anim_layout.addLayout(test_button_layout)
        
        parent_layout.addWidget(advanced_anim_group)

    def create_import_export_section(self, parent_layout):
        """Create settings import/export section"""
        import_export_group = QGroupBox("Settings Management")
        import_export_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        import_export_layout = QVBoxLayout(import_export_group)
        import_export_layout.setSpacing(12)
        import_export_layout.setContentsMargins(15, 15, 15, 15)
        
        # Create horizontal layout for buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(15)
        
        self.export_settings_button = QPushButton("Export Settings")
        self.export_settings_button.setMinimumHeight(35)
        self.export_settings_button.setMinimumWidth(130)
        self.export_settings_button.setStyleSheet("""
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
        self.export_settings_button.clicked.connect(self.export_settings)
        
        self.import_settings_button = QPushButton("Import Settings")
        self.import_settings_button.setMinimumHeight(35)
        self.import_settings_button.setMinimumWidth(130)
        self.import_settings_button.setStyleSheet("""
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
        self.import_settings_button.clicked.connect(self.import_settings)
        
        buttons_layout.addWidget(self.export_settings_button)
        buttons_layout.addWidget(self.import_settings_button)
        buttons_layout.addStretch()
        
        import_export_layout.addLayout(buttons_layout)
        parent_layout.addWidget(import_export_group)

    def setup_button_animations(self):
        """Setup button press animations"""
        buttons = [
            self.browse_output_folder_button,
            self.test_animations_button,
            self.export_settings_button,
            self.import_settings_button
        ]
        
        for button in buttons:
            button.pressed.connect(lambda b=button: self.animate_button_press(b))

    def animate_button_press(self, button):
        """Animate button press if animation manager is available"""
        if hasattr(self.main_window, 'animation_manager'):
            self.main_window.animation_manager.animate_button_press(button)

    # Event handlers and save methods
    def save_animation_speed(self, value):
        """Save animation speed setting"""
        self.app_settings["animation_speed"] = value
        self.main_window.save_settings()

    def browse_default_output_folder(self):
        """Browse for default output folder"""
        folder = QFileDialog.getExistingDirectory(self, "Select Default Output Folder")
        if folder:
            self.default_output_folder_entry.setText(folder)
            self.app_settings["default_output_folder"] = folder
            self.main_window.save_settings()

    def save_default_encryption_algo(self, algo_name):
        """Save default encryption algorithm setting"""
        if algo_name:  # Only save if algo_name is not empty
            self.app_settings["default_encryption_algorithm"] = algo_name
            self.main_window.save_settings()

    def save_shred_passes_setting(self):
        """Save secure shredding passes setting"""
        try:
            passes = int(self.default_shred_passes_entry.text()) if self.default_shred_passes_entry.text() else 0
            self.app_settings["default_shredding_passes"] = max(0, passes)
            self.main_window.save_settings()
        except ValueError:
            pass

    def save_confirm_on_exit_setting(self, state):
        """Save confirm on exit setting"""
        self.app_settings["confirm_on_exit"] = (state == Qt.CheckState.Checked)
        self.main_window.save_settings()

    def save_log_settings(self):
        """Save logging configuration settings"""
        try:
            max_size_mb = int(self.max_log_size_entry.text()) if self.max_log_size_entry.text() else 5
            self.app_settings["max_log_size_mb"] = max(1, max_size_mb)
            self.app_settings["enable_log_rotation"] = self.enable_log_rotation_checkbox.isChecked()
            
            # Configure logging with new settings
            if hasattr(self.main_window, 'configure_logging'):
                self.main_window.configure_logging()
            
            self.main_window.save_settings()
        except ValueError:
            pass

    def save_animation_settings(self):
        """Save advanced animation settings"""
        self.app_settings["animations_enabled"] = self.enable_animations_checkbox.isChecked()
        self.app_settings["transition_effects"] = self.transition_effects_checkbox.isChecked()
        self.app_settings["fade_duration"] = self.fade_duration_spinbox.value()
        self.app_settings["slide_duration"] = self.slide_duration_spinbox.value()
        
        # Update animation manager settings if available
        if hasattr(self.main_window, 'animation_manager'):
            self.main_window.animation_manager.set_enabled(self.app_settings["animations_enabled"])
            self.main_window.animation_manager.set_transition_effects(self.app_settings["transition_effects"])
            self.main_window.animation_manager.set_fade_duration(self.app_settings["fade_duration"])
            self.main_window.animation_manager.set_slide_duration(self.app_settings["slide_duration"])
        
        self.main_window.save_settings()

    def test_animations(self):
        """Test animation showcase"""
        if hasattr(self.main_window, 'animation_manager'):
            self.main_window.animation_manager.test_animation_showcase(self.main_window)

    def export_settings(self):
        """Export current settings to JSON file"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, 
                "Export Settings", 
                "sf_encryptor_settings.json", 
                "JSON files (*.json)"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(self.app_settings, f, indent=2)
                
                QMessageBox.information(
                    self, 
                    "Export Successful", 
                    f"Settings exported to {file_path}"
                )
                
                if hasattr(self.main_window, 'show_status_message'):
                    self.main_window.show_status_message("Settings exported successfully", 3000)
                    
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Export Error", 
                f"Failed to export settings: {str(e)}"
            )

    def import_settings(self):
        """Import settings from JSON file"""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self, 
                "Import Settings", 
                "", 
                "JSON files (*.json)"
            )
            
            if file_path and os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    imported_settings = json.load(f)
                
                # Validate and merge settings
                for key, value in imported_settings.items():
                    if key in self.app_settings:  # Only import known settings
                        self.app_settings[key] = value
                
                # Refresh UI with new settings
                self.load_settings_to_ui()
                self.main_window.save_settings()
                
                QMessageBox.information(
                    self, 
                    "Import Successful", 
                    f"Settings imported from {file_path}"
                )
                
                if hasattr(self.main_window, 'show_status_message'):
                    self.main_window.show_status_message("Settings imported successfully", 3000)
                    
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Import Error", 
                f"Failed to import settings: {str(e)}"
            )

    def update_default_encryption_algo_options(self):
        """Update encryption algorithm dropdown with available plugins"""
        current_selection = self.default_encryption_algo_dropdown.currentText()
        self.default_encryption_algo_dropdown.clear()
        
        # Add available encryption plugins
        if hasattr(self.plugin_manager, 'get_all_plugins') and self.plugin_manager.get_all_plugins():
            plugin_names = list(self.plugin_manager.get_all_plugins().keys())
            self.default_encryption_algo_dropdown.addItems(plugin_names)
            
            # Restore previous selection if it still exists
            index = self.default_encryption_algo_dropdown.findText(current_selection)
            if index >= 0:
                self.default_encryption_algo_dropdown.setCurrentIndex(index)
            else:
                # Set to saved setting or first available
                saved_algo = self.app_settings.get("default_encryption_algorithm", "")
                index = self.default_encryption_algo_dropdown.findText(saved_algo)
                if index >= 0:
                    self.default_encryption_algo_dropdown.setCurrentIndex(index)

    def load_settings_to_ui(self):
        """Load current settings into UI elements"""
        # Load basic settings
        self.default_shred_passes_entry.setText(str(self.app_settings.get("default_shredding_passes", 0)))
        self.animation_speed_slider.setValue(self.app_settings.get("animation_speed", 5))
        self.max_log_size_entry.setText(str(self.app_settings.get("max_log_size_mb", 5)))
        self.enable_log_rotation_checkbox.setChecked(self.app_settings.get("enable_log_rotation", True))
        self.default_output_folder_entry.setText(self.app_settings.get("default_output_folder", ""))
        self.confirm_on_exit_checkbox.setChecked(self.app_settings.get("confirm_on_exit", False))
        
        # Load animation settings
        self.enable_animations_checkbox.setChecked(self.app_settings.get("animations_enabled", True))
        self.transition_effects_checkbox.setChecked(self.app_settings.get("transition_effects", True))
        self.fade_duration_spinbox.setValue(self.app_settings.get("fade_duration", 300))
        self.slide_duration_spinbox.setValue(self.app_settings.get("slide_duration", 400))
        
        # Update encryption algorithm options and selection
        self.update_default_encryption_algo_options()

    def retranslate_ui(self):
        """Update UI text for localization (ready for future implementation)"""
        # This method would be called when language changes
        # Currently keeping English text as localization is disabled
        pass
