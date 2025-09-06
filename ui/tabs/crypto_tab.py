"""
Base Crypto Tab Module for Sf-Encryptor

This module provides the base CryptoTab class that serves as the foundation
for both encryption and decryption tabs. It includes:
- Common UI elements and layout
- File/folder selection with drag & drop
- Password and key file input methods
- Progress tracking and status updates
- Button animations and user feedback
"""

import os
import secrets
import threading
import time
from base64 import b64encode
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, 
                             QLabel, QPushButton, QLineEdit, QCheckBox, QSpinBox,
                             QRadioButton, QButtonGroup, QProgressBar, QComboBox,
                             QFileDialog, QMessageBox, QScrollArea, QFrame)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QIcon
from utils.drag_drop_widgets import DragDropLineEdit


class CryptoWorker(QObject):
    """Worker class for handling encryption/decryption operations in a separate thread"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    operation_completed = pyqtSignal(bool, str)  # success, message
    
    def __init__(self, plugin_manager, operation_params):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.params = operation_params
        self.is_cancelled = False
    
    def cancel(self):
        """Cancel the current operation"""
        self.is_cancelled = True
    
    def run(self):
        """Run the encryption/decryption operation"""
        try:
            if self.params['is_encrypt']:
                success, message = self._perform_encryption()
            else:
                success, message = self._perform_decryption()
            
            self.operation_completed.emit(success, message)
            
        except Exception as e:
            self.operation_completed.emit(False, f"Operation failed: {str(e)}")
    
    def _perform_encryption(self):
        """Perform the encryption operation"""
        try:
            # Get plugin
            algorithm = self.params['algorithm']
            plugin = self.plugin_manager.get_plugin(algorithm)
            if not plugin:
                return False, f"Plugin '{algorithm}' not found"
            
            # Get input files
            input_path = self.params['input_path']
            output_path = self.params['output_path']
            
            files_to_process = []
            if os.path.isfile(input_path):
                files_to_process = [input_path]
            elif os.path.isdir(input_path):
                for root, dirs, files in os.walk(input_path):
                    for file in files:
                        files_to_process.append(os.path.join(root, file))
            
            if not files_to_process:
                return False, "No files found to encrypt"
            
            self.status_updated.emit("Starting encryption...")
            total_files = len(files_to_process)
            processed_files = 0
            
            for file_path in files_to_process:
                if self.is_cancelled:
                    return False, "Operation cancelled by user"
                
                # Update status
                file_name = os.path.basename(file_path)
                self.status_updated.emit(f"Encrypting: {file_name}")
                
                # Generate output file path
                if os.path.isfile(input_path):
                    output_file = os.path.join(output_path, f"{file_name}.enc")
                else:
                    # Preserve directory structure
                    rel_path = os.path.relpath(file_path, input_path)
                    output_file = os.path.join(output_path, f"{rel_path}.enc")
                    os.makedirs(os.path.dirname(output_file), exist_ok=True)
                
                # Encrypt file using plugin
                try:
                    if self.params['use_password']:
                        # Use password-based encryption
                        plugin.encrypt_file(
                            input_filepath=file_path,
                            output_filepath=output_file,
                            key=None,  # Will be derived from password
                            password=self.params['password'],
                            progress_callback=None,
                            iterations=100000,
                            compression="None",
                            integrity_check="None"
                        )
                    else:
                        # Use key file
                        plugin.encrypt_file(
                            input_filepath=file_path,
                            output_filepath=output_file,
                            key=self.params['key_file_path'],
                            password=None,
                            progress_callback=None,
                            iterations=100000,
                            compression="None",
                            integrity_check="None"
                        )
                except Exception as e:
                    return False, f"Failed to encrypt {file_name}: {str(e)}"
                
                processed_files += 1
                progress = int((processed_files / total_files) * 100)
                self.progress_updated.emit(progress)
                
                # Small delay to allow UI updates
                time.sleep(0.01)
            
            return True, f"Successfully encrypted {processed_files} file(s)"
            
        except Exception as e:
            return False, f"Encryption failed: {str(e)}"
    
    def _perform_decryption(self):
        """Perform the decryption operation"""
        try:
            # Get plugin
            algorithm = self.params['algorithm']
            plugin = self.plugin_manager.get_plugin(algorithm)
            if not plugin:
                return False, f"Plugin '{algorithm}' not found"
            
            # Get input files
            input_path = self.params['input_path']
            output_path = self.params['output_path']
            
            files_to_process = []
            if os.path.isfile(input_path):
                if input_path.endswith('.enc'):
                    files_to_process = [input_path]
                else:
                    return False, "Selected file is not an encrypted file (.enc)"
            elif os.path.isdir(input_path):
                for root, dirs, files in os.walk(input_path):
                    for file in files:
                        if file.endswith('.enc'):
                            files_to_process.append(os.path.join(root, file))
            
            if not files_to_process:
                return False, "No encrypted files (.enc) found to decrypt"
            
            self.status_updated.emit("Starting decryption...")
            total_files = len(files_to_process)
            processed_files = 0
            
            for file_path in files_to_process:
                if self.is_cancelled:
                    return False, "Operation cancelled by user"
                
                # Update status
                file_name = os.path.basename(file_path)
                self.status_updated.emit(f"Decrypting: {file_name}")
                
                # Generate output file path (remove .enc extension)
                if file_name.endswith('.enc'):
                    original_name = file_name[:-4]  # Remove .enc
                else:
                    original_name = f"{file_name}_decrypted"
                
                if os.path.isfile(input_path):
                    output_file = os.path.join(output_path, original_name)
                else:
                    # Preserve directory structure
                    rel_path = os.path.relpath(file_path, input_path)
                    if rel_path.endswith('.enc'):
                        rel_path = rel_path[:-4]
                    output_file = os.path.join(output_path, rel_path)
                    os.makedirs(os.path.dirname(output_file), exist_ok=True)
                
                # Decrypt file using plugin
                try:
                    if self.params['use_password']:
                        # Use password-based decryption
                        plugin.decrypt_file(
                            input_filepath=file_path,
                            output_filepath=output_file,
                            key=None,  # Will be derived from password
                            password=self.params['password'],
                            progress_callback=None,
                            iterations=100000,
                            decompression="None",
                            integrity_check="None"
                        )
                    else:
                        # Use key file
                        plugin.decrypt_file(
                            input_filepath=file_path,
                            output_filepath=output_file,
                            key=self.params['key_file_path'],
                            password=None,
                            progress_callback=None,
                            iterations=100000,
                            decompression="None",
                            integrity_check="None"
                        )
                except Exception as e:
                    return False, f"Failed to decrypt {file_name}: {str(e)}"
                
                processed_files += 1
                progress = int((processed_files / total_files) * 100)
                self.progress_updated.emit(progress)
                
                # Small delay to allow UI updates
                time.sleep(0.01)
            
            return True, f"Successfully decrypted {processed_files} file(s)"
            
        except Exception as e:
            return False, f"Decryption failed: {str(e)}"


class CryptoTab(QWidget):
    """Base class for encryption and decryption tabs"""
    
    def __init__(self, plugin_manager, app_settings, main_window, is_encrypt_mode):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.app_settings = app_settings
        self.main_window = main_window
        self.is_encrypt_mode = is_encrypt_mode
        self.worker = None
        self.thread = None
        self.setup_ui()
        self.connect_signals()
        self.update_plugin_options()

    def setup_ui(self):
        """Initialize the user interface with scrolling"""
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
        self.layout = QGridLayout(scroll_content)
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(15)
        
        self.create_ui_elements()
        self.layout_ui_elements()
        
        # Set the scroll area widget
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)

    def create_ui_elements(self):
        """Create all UI elements"""
        # File input/output
        self.input_path_entry = DragDropLineEdit()
        self.input_path_entry.setPlaceholderText("Select files or folders to process...")
        self.input_path_entry.setMinimumHeight(35)
        
        self.output_path_entry = DragDropLineEdit()
        self.output_path_entry.setPlaceholderText("Select output destination...")
        self.output_path_entry.setMinimumHeight(35)
        
        # Browse buttons
        self.browse_input_file_button = QPushButton("Select File")
        self.browse_input_file_button.setMinimumHeight(35)
        self.browse_input_file_button.setMinimumWidth(100)
        self.browse_input_file_button.setStyleSheet("""
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
        
        self.browse_input_folder_button = QPushButton("Select Folder")
        self.browse_input_folder_button.setMinimumHeight(35)
        self.browse_input_folder_button.setMinimumWidth(100)
        self.browse_input_folder_button.setStyleSheet("""
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
        
        self.browse_output_button = QPushButton("Browse")
        self.browse_output_button.setMinimumHeight(35)
        self.browse_output_button.setMinimumWidth(80)
        self.browse_output_button.setStyleSheet("""
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
        
        # Algorithm selection
        self.algo_dropdown = QComboBox()
        self.algo_dropdown.setMinimumHeight(35)
        
        # Key input method selection
        self.key_input_type_label = QLabel("Password Input Type:")
        self.password_radio_button = QRadioButton("Use Password")
        self.key_file_radio_button = QRadioButton("Use Key File")
        self.password_radio_button.setChecked(True)
        
        self.key_input_group = QButtonGroup(self)
        self.key_input_group.addButton(self.password_radio_button)
        self.key_input_group.addButton(self.key_file_radio_button)
        
        # Password input
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_entry.setMinimumHeight(35)
        self.password_entry.setPlaceholderText("Enter your password...")
        
        self.password_strength_label = QLabel()
        self.password_strength_label.setStyleSheet("color: grey; font-size: 11px;")
        
        # Key file input
        self.key_file_label = QLabel("Key File Path:")
        self.key_file_path_entry = DragDropLineEdit()
        self.key_file_path_entry.setReadOnly(True)
        self.key_file_path_entry.setMinimumHeight(35)
        self.key_file_path_entry.setPlaceholderText("Select or drag a key file...")
        
        self.browse_key_file_button = QPushButton("Browse")
        self.browse_key_file_button.setMinimumHeight(35)
        self.browse_key_file_button.setMinimumWidth(80)
        self.browse_key_file_button.setStyleSheet("""
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
        
        # Encryption-specific options
        if self.is_encrypt_mode:
            self.checksum_checkbox = QCheckBox("Enable file integrity verification")
            self.delete_original_checkbox = QCheckBox("Delete original files after encryption")
            
            self.secure_shredding_passes_label = QLabel("Secure Shredding Passes:")
            self.secure_shredding_passes_spinbox = QSpinBox()
            self.secure_shredding_passes_spinbox.setRange(0, 100)
            self.secure_shredding_passes_spinbox.setValue(0)
            self.secure_shredding_passes_spinbox.setMinimumHeight(35)
            self.secure_shredding_passes_spinbox.setMaximumWidth(150)
        
        # Action button
        action_text = "Encrypt Files" if self.is_encrypt_mode else "Decrypt Files"
        self.action_button = QPushButton(action_text)
        self.action_button.setMinimumHeight(45)
        self.action_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 2px solid #004d40;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #004d40;
                color: white;
            }
            QPushButton:pressed {
                background-color: #00352b;
                color: white;
            }
            QPushButton:disabled {
                background-color: #e9ecef;
                color: #6c757d;
                border-color: #dee2e6;
            }
        """)
        
        # Progress tracking
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMinimumHeight(25)
        
        self.batch_progress_label = QLabel("")
        self.batch_progress_label.setStyleSheet("color: #666; font-size: 12px;")
        
        self.file_status_label = QLabel("Ready to process files")
        self.file_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.file_status_label.setStyleSheet("color: #333; font-weight: bold;")

    def layout_ui_elements(self):
        """Layout all UI elements in the grid"""
        row = 0
        
        # Input file/folder selection
        self.layout.addWidget(QLabel("Input File/Folder:"), row, 0)
        self.layout.addWidget(self.input_path_entry, row, 1, 1, 2)
        
        input_browse_layout = QHBoxLayout()
        input_browse_layout.setSpacing(5)
        input_browse_layout.addWidget(self.browse_input_file_button)
        input_browse_layout.addWidget(self.browse_input_folder_button)
        self.layout.addLayout(input_browse_layout, row, 3)
        row += 1
        
        # Output folder selection
        self.layout.addWidget(QLabel("Output Folder:"), row, 0)
        self.layout.addWidget(self.output_path_entry, row, 1, 1, 2)
        self.layout.addWidget(self.browse_output_button, row, 3)
        row += 1
        
        # Algorithm selection
        algo_label = "Encryption Algorithm:" if self.is_encrypt_mode else "Decryption Algorithm:"
        self.layout.addWidget(QLabel(algo_label), row, 0)
        self.layout.addWidget(self.algo_dropdown, row, 1, 1, 3)
        row += 1
        
        # Key input method selection
        key_input_method_layout = QHBoxLayout()
        key_input_method_layout.setSpacing(10)
        key_input_method_layout.addWidget(self.key_input_type_label)
        key_input_method_layout.addWidget(self.password_radio_button)
        key_input_method_layout.addWidget(self.key_file_radio_button)
        key_input_method_layout.addStretch()
        self.layout.addLayout(key_input_method_layout, row, 0, 1, 4)
        row += 1
        
        # Password input
        self.layout.addWidget(self.password_label, row, 0)
        self.layout.addWidget(self.password_entry, row, 1, 1, 3)
        row += 1
        
        # Password strength indicator
        self.layout.addWidget(self.password_strength_label, row, 1, 1, 3)
        row += 1
        
        # Key file input
        self.layout.addWidget(self.key_file_label, row, 0)
        self.layout.addWidget(self.key_file_path_entry, row, 1, 1, 2)
        self.layout.addWidget(self.browse_key_file_button, row, 3)
        row += 1
        
        # Encryption-specific options
        if self.is_encrypt_mode:
            options_layout = QHBoxLayout()
            options_layout.addWidget(self.checksum_checkbox)
            options_layout.addWidget(self.delete_original_checkbox)
            options_layout.addStretch()
            self.layout.addLayout(options_layout, row, 0, 1, 4)
            row += 1
            
            self.layout.addWidget(self.secure_shredding_passes_label, row, 0)
            self.layout.addWidget(self.secure_shredding_passes_spinbox, row, 1)
            row += 1
        
        # Action button
        self.layout.addWidget(self.action_button, row, 0, 1, 4)
        row += 1
        
        # Progress tracking
        self.layout.addWidget(self.batch_progress_label, row, 0, 1, 4)
        row += 1
        
        self.layout.addWidget(self.progress_bar, row, 0, 1, 4)
        row += 1
        
        self.layout.addWidget(self.file_status_label, row, 0, 1, 4)
        row += 1
        
        # Add stretch to push everything to top
        self.layout.setRowStretch(row, 1)
        
        # Setup initial UI state
        self.toggle_key_input_method(True)
        
        # Setup button animations
        self.setup_button_animations()

    def setup_button_animations(self):
        """Setup button press animations"""
        buttons = [
            self.browse_input_file_button,
            self.browse_input_folder_button,
            self.browse_output_button,
            self.browse_key_file_button,
            self.action_button
        ]
        
        for button in buttons:
            button.pressed.connect(lambda b=button: self.animate_button_press(b))

    def animate_button_press(self, button):
        """Animate button press if animation manager is available"""
        if hasattr(self.main_window, 'animation_manager'):
            self.main_window.animation_manager.animate_button_press(button)

    def connect_signals(self):
        """Connect all signal handlers"""
        # File selection
        self.input_path_entry.fileDropped.connect(self.on_file_dropped)
        self.input_path_entry.folderDropped.connect(self.on_folder_dropped)
        self.browse_input_file_button.clicked.connect(self.browse_input_file)
        self.browse_input_folder_button.clicked.connect(self.browse_input_folder)
        self.browse_output_button.clicked.connect(self.browse_output)
        
        # Key input method
        self.key_input_group.buttonToggled.connect(
            lambda button: self.toggle_key_input_method(button == self.password_radio_button)
        )
        
        # Key file handling
        self.browse_key_file_button.clicked.connect(self.browse_key_file)
        self.key_file_path_entry.fileDropped.connect(self.on_key_file_dropped)
        
        # Password strength
        if self.is_encrypt_mode:
            self.password_entry.textChanged.connect(self.update_password_strength_label)
            self.delete_original_checkbox.stateChanged.connect(self.toggle_shredding_options)
        
        # Main action
        self.action_button.clicked.connect(self.start_operation)

    def toggle_key_input_method(self, use_password):
        """Toggle between password and key file input methods"""
        # Password controls
        self.password_label.setVisible(use_password)
        self.password_entry.setVisible(use_password)
        self.password_strength_label.setVisible(use_password and self.is_encrypt_mode)
        
        # Key file controls
        self.key_file_label.setVisible(not use_password)
        self.key_file_path_entry.setVisible(not use_password)
        self.browse_key_file_button.setVisible(not use_password)

    def toggle_shredding_options(self, state):
        """Toggle secure shredding options visibility"""
        if hasattr(self, 'secure_shredding_passes_label'):
            enabled = state == Qt.CheckState.Checked.value
            self.secure_shredding_passes_label.setEnabled(enabled)
            self.secure_shredding_passes_spinbox.setEnabled(enabled)

    def update_plugin_options(self):
        """Update algorithm dropdown with available plugins"""
        current_selection = self.algo_dropdown.currentText()
        self.algo_dropdown.clear()
        
        if hasattr(self.plugin_manager, 'get_all_plugins') and self.plugin_manager.get_all_plugins():
            plugin_names = list(self.plugin_manager.get_all_plugins().keys())
            self.algo_dropdown.addItems(plugin_names)
            
            # Restore previous selection if available
            index = self.algo_dropdown.findText(current_selection)
            if index >= 0:
                self.algo_dropdown.setCurrentIndex(index)
            else:
                # Set to saved default or first available
                default_algo = self.app_settings.get("default_encryption_algorithm", "")
                index = self.algo_dropdown.findText(default_algo)
                if index >= 0:
                    self.algo_dropdown.setCurrentIndex(index)

    def update_password_strength_label(self, password):
        """Update password strength indicator"""
        if not password:
            self.password_strength_label.setText("")
            return
        
        strength = self.get_password_strength(password)
        if strength == "weak":
            self.password_strength_label.setText("Password Strength: Weak")
            self.password_strength_label.setStyleSheet("color: red; font-size: 11px;")
        elif strength == "medium":
            self.password_strength_label.setText("Password Strength: Medium")
            self.password_strength_label.setStyleSheet("color: orange; font-size: 11px;")
        elif strength == "strong":
            self.password_strength_label.setText("Password Strength: Strong")
            self.password_strength_label.setStyleSheet("color: green; font-size: 11px;")

    def get_password_strength(self, password):
        """Evaluate password strength"""
        if len(password) < 6:
            return "weak"
        
        score = 0
        if len(password) >= 8:
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        
        if score < 3:
            return "weak"
        elif score < 5:
            return "medium"
        else:
            return "strong"

    # Event handlers
    def browse_input_file(self):
        """Browse for input file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select File to Process", 
            "", 
            "All Files (*.*)"
        )
        if file_path:
            self.input_path_entry.setText(file_path)

    def browse_input_folder(self):
        """Browse for input folder"""
        folder_path = QFileDialog.getExistingDirectory(
            self, 
            "Select Folder to Process"
        )
        if folder_path:
            self.input_path_entry.setText(folder_path)

    def browse_output(self):
        """Browse for output folder"""
        folder_path = QFileDialog.getExistingDirectory(
            self, 
            "Select Output Folder"
        )
        if folder_path:
            self.output_path_entry.setText(folder_path)

    def browse_key_file(self):
        """Browse for key file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Key File", 
            "", 
            "Key Files (*.key);;Text Files (*.txt);;All Files (*.*)"
        )
        if file_path:
            self.key_file_path_entry.setText(file_path)

    def on_file_dropped(self, file_path):
        """Handle dropped file"""
        self.input_path_entry.setText(file_path)

    def on_folder_dropped(self, folder_path):
        """Handle dropped folder"""
        self.input_path_entry.setText(folder_path)

    def on_key_file_dropped(self, file_path):
        """Handle dropped key file"""
        self.key_file_path_entry.setText(file_path)

    def start_operation(self):
        """Start encryption/decryption operation with real functionality"""
        # Validate inputs
        if not self.input_path_entry.text().strip():
            QMessageBox.warning(self, "Input Required", "Please select a file or folder to process.")
            return
        
        if not self.output_path_entry.text().strip():
            QMessageBox.warning(self, "Output Required", "Please select an output folder.")
            return
        
        if not self.algo_dropdown.currentText():
            QMessageBox.warning(self, "Algorithm Required", "Please select an encryption algorithm.")
            return
        
        if self.password_radio_button.isChecked():
            if not self.password_entry.text().strip():
                QMessageBox.warning(self, "Password Required", "Please enter a password.")
                return
        else:
            if not self.key_file_path_entry.text().strip():
                QMessageBox.warning(self, "Key File Required", "Please select a key file.")
                return
            if not os.path.exists(self.key_file_path_entry.text().strip()):
                QMessageBox.warning(self, "Key File Error", "The selected key file does not exist.")
                return
        
        # Validate input path exists
        input_path = self.input_path_entry.text().strip()
        if not os.path.exists(input_path):
            QMessageBox.warning(self, "Input Error", "The selected input file or folder does not exist.")
            return
        
        # Validate output path exists
        output_path = self.output_path_entry.text().strip()
        if not os.path.exists(output_path):
            QMessageBox.warning(self, "Output Error", "The selected output folder does not exist.")
            return
        
        # Disable UI during operation
        self.action_button.setEnabled(False)
        self.action_button.setText("Processing...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Prepare operation parameters
        operation_params = {
            'is_encrypt': self.is_encrypt_mode,
            'algorithm': self.algo_dropdown.currentText(),
            'input_path': input_path,
            'output_path': output_path,
            'use_password': self.password_radio_button.isChecked(),
            'password': self.password_entry.text() if self.password_radio_button.isChecked() else None,
            'key_file_path': self.key_file_path_entry.text().strip() if not self.password_radio_button.isChecked() else None
        }
        
        # Create worker and thread
        self.worker = CryptoWorker(self.plugin_manager, operation_params)
        self.thread = threading.Thread(target=self.worker.run)
        
        # Connect signals
        self.worker.progress_updated.connect(self.progress_bar.setValue)
        self.worker.status_updated.connect(self.update_status)
        self.worker.operation_completed.connect(self.on_operation_completed)
        
        # Start the operation
        self.thread.start()
        
        # Update status
        operation = "Encryption" if self.is_encrypt_mode else "Decryption"
        if hasattr(self.main_window, 'show_status_message'):
            self.main_window.show_status_message(f"{operation} started...", 0)
    
    def update_status(self, message):
        """Update the status message"""
        if hasattr(self.main_window, 'show_status_message'):
            self.main_window.show_status_message(message, 0)
    
    def on_operation_completed(self, success, message):
        """Handle completion of the operation"""
        # Re-enable UI
        operation = "Encrypt Files" if self.is_encrypt_mode else "Decrypt Files"
        self.action_button.setText(operation)
        self.action_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.progress_bar.setValue(0)
        
        # Show result
        if success:
            QMessageBox.information(self, "Operation Completed", message)
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(message, 5000)
        else:
            QMessageBox.critical(self, "Operation Failed", message)
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"Error: {message}", 5000)
        
        # Clean up
        self.worker = None
        self.thread = None

    def retranslate_ui(self):
        """Update UI text for localization (ready for future implementation)"""
        # This method would be called when language changes
        pass
