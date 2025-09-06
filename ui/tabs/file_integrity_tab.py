"""
File Integrity Tab Module for Sf-Encryptor

This module provides file integrity checking with hash calculation and secure password generation.
Features include:
- File hash calculation (SHA-256 and SHA-512)
- Drag & drop support for files
- Secure password generation with customizable options
- Password complexity controls (uppercase, numbers, symbols)
- Integration with animation system
"""

import os
import hashlib
import string
import secrets
import re
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, 
                             QLabel, QPushButton, QLineEdit, QCheckBox, QSpinBox, 
                             QFileDialog, QMessageBox, QGroupBox, QScrollArea, QFrame)
from PyQt6.QtCore import Qt
from utils.drag_drop_widgets import DragDropLineEdit


class FileIntegrityTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setup_ui()
        self.setup_button_animations()

    def setup_ui(self):
        """Initialize the file integrity interface with scroll area"""
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
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(15)  # Reduced spacing for better compactness
        
        # Create sections in the scrollable content
        self.create_file_integrity_section(content_layout)
        self.create_hash_comparison_section(content_layout)
        self.create_password_generator_section(content_layout)
        
        # Add stretch to push everything to top within scroll area
        content_layout.addStretch()
        
        # Set the scroll area widget
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)

    def create_file_integrity_section(self, parent_layout):
        """Create file integrity checking section"""
        integrity_group = QGroupBox("File Integrity Verification")
        integrity_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        integrity_layout = QGridLayout(integrity_group)
        integrity_layout.setSpacing(12)
        integrity_layout.setContentsMargins(15, 15, 15, 15)
        
        # Set maximum height to make it more compact
        integrity_group.setMaximumHeight(250)
        
        # File selection with improved styling and drag & drop
        self.file_to_hash_label = QLabel("File to Hash:")
        self.file_to_hash_entry = DragDropLineEdit(accept_files=True, accept_folders=False)
        self.file_to_hash_entry.setPlaceholderText("Select or drag a file here...")
        self.file_to_hash_entry.setMinimumHeight(35)
        self.file_to_hash_entry.setStyleSheet("""
            QLineEdit {
                border: 2px solid #004d40;
                border-radius: 5px;
                padding: 8px;
                font-size: 11pt;
            }
            QLineEdit:focus {
                border-color: #00695c;
            }
        """)
        
        # Connect drag & drop signal
        self.file_to_hash_entry.fileDropped.connect(self.on_file_dropped_for_hashing)
        
        self.browse_hash_file_button = QPushButton("Browse Files")
        self.browse_hash_file_button.setMinimumHeight(35)
        self.browse_hash_file_button.setStyleSheet("""
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
        self.browse_hash_file_button.clicked.connect(self.browse_hash_file)
        
        # Calculate button with improved styling
        self.calculate_hash_button = QPushButton("Calculate File Hash")
        self.calculate_hash_button.setMinimumHeight(40)
        self.calculate_hash_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 2px solid #004d40;
                border-radius: 5px;
                font-weight: bold;
                padding: 10px 20px;
                font-size: 12pt;
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
        self.calculate_hash_button.clicked.connect(self.calculate_hash)
        
        # Hash outputs with copy buttons
        self.sha256_label = QLabel("SHA-256 Hash:")
        self.sha256_output = QLineEdit()
        self.sha256_output.setReadOnly(True)
        self.sha256_output.setPlaceholderText("SHA-256 hash will appear here...")
        self.sha256_output.setStyleSheet("""
            QLineEdit {
                border: 1px solid #dee2e6;
                border-radius: 3px;
                padding: 8px;
                background-color: #f8f9fa;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10pt;
            }
        """)
        
        self.copy_sha256_button = QPushButton("Copy")
        self.copy_sha256_button.setMaximumWidth(80)
        self.copy_sha256_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 1px solid #004d40;
                border-radius: 3px;
                font-weight: bold;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #004d40;
                color: white;
            }
        """)
        self.copy_sha256_button.clicked.connect(lambda: self.copy_hash_to_clipboard(self.sha256_output.text(), "SHA-256"))
        
        self.sha512_label = QLabel("SHA-512 Hash:")
        self.sha512_output = QLineEdit()
        self.sha512_output.setReadOnly(True)
        self.sha512_output.setPlaceholderText("SHA-512 hash will appear here...")
        self.sha512_output.setStyleSheet("""
            QLineEdit {
                border: 1px solid #dee2e6;
                border-radius: 3px;
                padding: 8px;
                background-color: #f8f9fa;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10pt;
            }
        """)
        
        self.copy_sha512_button = QPushButton("Copy")
        self.copy_sha512_button.setMaximumWidth(80)
        self.copy_sha512_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 1px solid #004d40;
                border-radius: 3px;
                font-weight: bold;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #004d40;
                color: white;
            }
        """)
        self.copy_sha512_button.clicked.connect(lambda: self.copy_hash_to_clipboard(self.sha512_output.text(), "SHA-512"))
        
        # Layout the integrity section
        integrity_layout.addWidget(self.file_to_hash_label, 0, 0)
        integrity_layout.addWidget(self.file_to_hash_entry, 0, 1, 1, 2)
        integrity_layout.addWidget(self.browse_hash_file_button, 0, 3)
        integrity_layout.addWidget(self.calculate_hash_button, 1, 0, 1, 4)
        integrity_layout.addWidget(self.sha256_label, 2, 0)
        integrity_layout.addWidget(self.sha256_output, 2, 1, 1, 2)
        integrity_layout.addWidget(self.copy_sha256_button, 2, 3)
        integrity_layout.addWidget(self.sha512_label, 3, 0)
        integrity_layout.addWidget(self.sha512_output, 3, 1, 1, 2)
        integrity_layout.addWidget(self.copy_sha512_button, 3, 3)
        
        parent_layout.addWidget(integrity_group)

    def create_hash_comparison_section(self, parent_layout):
        """Create hash comparison section"""
        comparison_group = QGroupBox("Hash Comparison & Verification")
        comparison_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        comparison_layout = QGridLayout(comparison_group)
        comparison_layout.setSpacing(12)
        comparison_layout.setContentsMargins(15, 15, 15, 15)
        
        # Set maximum height to make it more compact
        comparison_group.setMaximumHeight(160)
        
        # Expected hash input
        self.expected_hash_label = QLabel("Expected Hash:")
        self.expected_hash_entry = QLineEdit()
        self.expected_hash_entry.setPlaceholderText("Paste expected hash here to compare...")
        self.expected_hash_entry.setMinimumHeight(35)
        self.expected_hash_entry.setStyleSheet("""
            QLineEdit {
                border: 2px solid #004d40;
                border-radius: 5px;
                padding: 8px;
                font-size: 11pt;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QLineEdit:focus {
                border-color: #00695c;
            }
        """)
        
        # Compare button
        self.compare_hash_button = QPushButton("Compare Hashes")
        self.compare_hash_button.setMinimumHeight(40)
        self.compare_hash_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 2px solid #004d40;
                border-radius: 5px;
                font-weight: bold;
                padding: 10px 20px;
                font-size: 12pt;
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
        self.compare_hash_button.clicked.connect(self.compare_hashes)
        
        # Comparison result
        self.comparison_result_label = QLabel("Comparison Result:")
        self.comparison_result_output = QLineEdit()
        self.comparison_result_output.setReadOnly(True)
        self.comparison_result_output.setPlaceholderText("Hash comparison result will appear here...")
        self.comparison_result_output.setMinimumHeight(35)
        self.comparison_result_output.setStyleSheet("""
            QLineEdit {
                border: 1px solid #dee2e6;
                border-radius: 3px;
                padding: 8px;
                background-color: #f8f9fa;
                font-weight: bold;
                font-size: 11pt;
            }
        """)
        
        # Layout the comparison section
        comparison_layout.addWidget(self.expected_hash_label, 0, 0)
        comparison_layout.addWidget(self.expected_hash_entry, 0, 1, 1, 2)
        comparison_layout.addWidget(self.compare_hash_button, 1, 0, 1, 3)
        comparison_layout.addWidget(self.comparison_result_label, 2, 0)
        comparison_layout.addWidget(self.comparison_result_output, 2, 1, 1, 2)
        
        parent_layout.addWidget(comparison_group)

    def create_password_generator_section(self, parent_layout):
        """Create secure password generator section"""
        password_group = QGroupBox("Secure Password Generator")
        password_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        password_layout = QGridLayout(password_group)
        password_layout.setSpacing(12)
        password_layout.setContentsMargins(15, 15, 15, 15)
        
        # Password length with better styling
        self.password_length_label = QLabel("Password Length:")
        self.password_length_spinbox = QSpinBox()
        self.password_length_spinbox.setRange(8, 128)
        self.password_length_spinbox.setValue(16)
        self.password_length_spinbox.setMinimumHeight(30)
        self.password_length_spinbox.setStyleSheet("""
            QSpinBox {
                border: 1px solid #004d40;
                border-radius: 3px;
                padding: 5px;
                font-size: 11pt;
            }
        """)
        
        # Character options with consistent styling
        checkbox_style = """
            QCheckBox {
                font-size: 11pt;
                padding: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 2px solid #004d40;
                background-color: white;
            }
            QCheckBox::indicator:checked {
                border: 2px solid #004d40;
                background-color: #004d40;
            }
        """
        
        self.include_uppercase_checkbox = QCheckBox("Include Uppercase Letters (A-Z)")
        self.include_uppercase_checkbox.setChecked(True)
        self.include_uppercase_checkbox.setStyleSheet(checkbox_style)
        
        self.include_numbers_checkbox = QCheckBox("Include Numbers (0-9)")
        self.include_numbers_checkbox.setChecked(True)
        self.include_numbers_checkbox.setStyleSheet(checkbox_style)
        
        self.include_symbols_checkbox = QCheckBox("Include Symbols (!@#$%^&*)")
        self.include_symbols_checkbox.setChecked(True)
        self.include_symbols_checkbox.setStyleSheet(checkbox_style)
        
        self.exclude_ambiguous_checkbox = QCheckBox("Exclude Ambiguous Characters (0, O, l, I)")
        self.exclude_ambiguous_checkbox.setChecked(False)
        self.exclude_ambiguous_checkbox.setStyleSheet(checkbox_style)
        
        # Generate button with enhanced styling
        self.generate_password_button = QPushButton("Generate Secure Password")
        self.generate_password_button.setMinimumHeight(40)
        self.generate_password_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 2px solid #004d40;
                border-radius: 5px;
                font-weight: bold;
                padding: 10px 20px;
                font-size: 12pt;
            }
            QPushButton:hover {
                background-color: #004d40;
                color: white;
            }
        """)
        self.generate_password_button.clicked.connect(self.generate_password)
        
        # Generated password output with copy functionality
        self.generated_password_label = QLabel("Generated Password:")
        self.generated_password_output = QLineEdit()
        self.generated_password_output.setReadOnly(True)
        self.generated_password_output.setPlaceholderText("Generated password will appear here...")
        self.generated_password_output.setMinimumHeight(35)
        self.generated_password_output.setStyleSheet("""
            QLineEdit {
                border: 1px solid #dee2e6;
                border-radius: 3px;
                padding: 8px;
                background-color: #f8f9fa;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11pt;
                font-weight: bold;
            }
        """)
        
        # Copy password button
        self.copy_password_button = QPushButton("Copy Password")
        self.copy_password_button.setMaximumWidth(120)
        self.copy_password_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 1px solid #004d40;
                border-radius: 3px;
                font-weight: bold;
                padding: 8px 12px;
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
        self.copy_password_button.clicked.connect(self.copy_password)
        self.copy_password_button.setEnabled(False)
        
        # Password strength indicator
        self.strength_label = QLabel("Password Strength:")
        self.strength_indicator = QLineEdit()
        self.strength_indicator.setReadOnly(True)
        self.strength_indicator.setPlaceholderText("Generate a password to see strength assessment...")
        self.strength_indicator.setMinimumHeight(30)
        self.strength_indicator.setStyleSheet("""
            QLineEdit {
                border: 1px solid #dee2e6;
                border-radius: 3px;
                padding: 8px;
                background-color: #f8f9fa;
                font-weight: bold;
            }
        """)
        
        # Layout the password generator section with more compact spacing and two-column layout
        password_layout.addWidget(self.password_length_label, 0, 0)
        password_layout.addWidget(self.password_length_spinbox, 0, 1)
        
        # Organize checkboxes in two columns for better space utilization
        password_layout.addWidget(self.include_uppercase_checkbox, 1, 0, 1, 2)
        password_layout.addWidget(self.include_numbers_checkbox, 1, 2, 1, 2)
        password_layout.addWidget(self.include_symbols_checkbox, 2, 0, 1, 2)
        password_layout.addWidget(self.exclude_ambiguous_checkbox, 2, 2, 1, 2)
        
        password_layout.addWidget(self.generate_password_button, 3, 0, 1, 4)
        password_layout.addWidget(self.generated_password_label, 4, 0)
        password_layout.addWidget(self.generated_password_output, 4, 1, 1, 2)
        password_layout.addWidget(self.copy_password_button, 4, 3)
        password_layout.addWidget(self.strength_label, 5, 0)
        password_layout.addWidget(self.strength_indicator, 5, 1, 1, 3)
        
        # Set maximum height to make it more compact
        password_group.setMaximumHeight(320)
        
        parent_layout.addWidget(password_group)

    def setup_button_animations(self):
        """Setup button press animations"""
        buttons = [
            self.browse_hash_file_button,
            self.calculate_hash_button,
            self.copy_sha256_button,
            self.copy_sha512_button,
            self.compare_hash_button,
            self.generate_password_button,
            self.copy_password_button
        ]
        
        for button in buttons:
            button.pressed.connect(lambda b=button: self.animate_button_press(b))

    def animate_button_press(self, button):
        """Animate button press if animation manager is available"""
        if hasattr(self.main_window, 'animation_manager'):
            self.main_window.animation_manager.animate_button_press(button)

    def browse_hash_file(self):
        """Browse for file to hash"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select File to Hash", 
            "", 
            "All files (*)"
        )
        if file_path:
            self.file_to_hash_entry.setText(file_path)

    def calculate_hash(self):
        """Calculate SHA-256 and SHA-512 hashes for the selected file"""
        file_path = self.file_to_hash_entry.text().strip()
        
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select a file first.")
            return
        
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "File not found.")
            return

        try:
            # Initialize hash objects
            hasher_256 = hashlib.sha256()
            hasher_512 = hashlib.sha512()
            
            # Read file in chunks to handle large files
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    hasher_256.update(chunk)
                    hasher_512.update(chunk)
            
            # Display results
            self.sha256_output.setText(hasher_256.hexdigest())
            self.sha512_output.setText(hasher_512.hexdigest())
            
            # Show success message
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message("Hash calculation completed successfully", 3000)
                
        except Exception as e:
            # Handle errors
            error_msg = f"An error occurred during hashing: {str(e)}"
            self.sha256_output.setText("Error")
            self.sha512_output.setText("Error")
            
            QMessageBox.critical(self, "Hashing Error", error_msg)
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"Hashing failed: {str(e)}", 5000)

    def copy_hash_to_clipboard(self, hash_value, hash_type):
        """Copy hash value to clipboard"""
        if hash_value and hash_value != "Error":
            try:
                from PyQt6.QtWidgets import QApplication
                clipboard = QApplication.clipboard()
                clipboard.setText(hash_value)
                
                QMessageBox.information(
                    self, 
                    "Copied", 
                    f"{hash_type} hash copied to clipboard!"
                )
                
                if hasattr(self.main_window, 'show_status_message'):
                    self.main_window.show_status_message(f"{hash_type} hash copied to clipboard", 3000)
                    
            except Exception as e:
                QMessageBox.warning(
                    self, 
                    "Copy Error", 
                    f"Failed to copy {hash_type} hash: {str(e)}"
                )
        else:
            QMessageBox.warning(self, "Warning", f"No {hash_type} hash to copy.")

    def compare_hashes(self):
        """Compare calculated hash with expected hash"""
        expected_hash = self.expected_hash_entry.text().strip().lower()
        
        if not expected_hash:
            QMessageBox.warning(self, "Warning", "Please enter an expected hash to compare.")
            return
        
        # Get calculated hashes
        sha256_hash = self.sha256_output.text().strip().lower()
        sha512_hash = self.sha512_output.text().strip().lower()
        
        if not sha256_hash and not sha512_hash:
            QMessageBox.warning(self, "Warning", "Please calculate a hash first.")
            return
        
        # Determine hash type based on length
        expected_length = len(expected_hash)
        
        if expected_length == 64:  # SHA-256
            if sha256_hash == expected_hash:
                self.comparison_result_output.setText("MATCH - File integrity verified (SHA-256)")
                self.comparison_result_output.setStyleSheet("""
                    QLineEdit {
                        border: 1px solid #28a745;
                        border-radius: 3px;
                        padding: 8px;
                        background-color: #d4edda;
                        color: #155724;
                        font-weight: bold;
                        font-size: 11pt;
                    }
                """)
                QMessageBox.information(self, "Hash Match", "File integrity verified! The hashes match.")
            else:
                self.comparison_result_output.setText("MISMATCH - File may be corrupted or modified (SHA-256)")
                self.comparison_result_output.setStyleSheet("""
                    QLineEdit {
                        border: 1px solid #dc3545;
                        border-radius: 3px;
                        padding: 8px;
                        background-color: #f8d7da;
                        color: #721c24;
                        font-weight: bold;
                        font-size: 11pt;
                    }
                """)
                QMessageBox.warning(self, "Hash Mismatch", "File integrity check failed! The hashes do not match.")
        
        elif expected_length == 128:  # SHA-512
            if sha512_hash == expected_hash:
                self.comparison_result_output.setText("MATCH - File integrity verified (SHA-512)")
                self.comparison_result_output.setStyleSheet("""
                    QLineEdit {
                        border: 1px solid #28a745;
                        border-radius: 3px;
                        padding: 8px;
                        background-color: #d4edda;
                        color: #155724;
                        font-weight: bold;
                        font-size: 11pt;
                    }
                """)
                QMessageBox.information(self, "Hash Match", "File integrity verified! The hashes match.")
            else:
                self.comparison_result_output.setText("MISMATCH - File may be corrupted or modified (SHA-512)")
                self.comparison_result_output.setStyleSheet("""
                    QLineEdit {
                        border: 1px solid #dc3545;
                        border-radius: 3px;
                        padding: 8px;
                        background-color: #f8d7da;
                        color: #721c24;
                        font-weight: bold;
                        font-size: 11pt;
                    }
                """)
                QMessageBox.warning(self, "Hash Mismatch", "File integrity check failed! The hashes do not match.")
        
        else:
            self.comparison_result_output.setText("UNKNOWN - Hash format not recognized")
            self.comparison_result_output.setStyleSheet("""
                QLineEdit {
                    border: 1px solid #ffc107;
                    border-radius: 3px;
                    padding: 8px;
                    background-color: #fff3cd;
                    color: #856404;
                    font-weight: bold;
                    font-size: 11pt;
                }
            """)
            QMessageBox.warning(
                self, 
                "Unknown Hash Format", 
                f"The expected hash length ({expected_length} characters) doesn't match SHA-256 (64) or SHA-512 (128)."
            )

    def generate_password(self):
        """Generate a secure password based on selected criteria"""
        length = self.password_length_spinbox.value()
        
        # Build character set based on selections
        chars = string.ascii_lowercase  # Always include lowercase
        
        if self.include_uppercase_checkbox.isChecked():
            chars += string.ascii_uppercase
        if self.include_numbers_checkbox.isChecked():
            chars += string.digits
        if self.include_symbols_checkbox.isChecked():
            chars += string.punctuation

        # Exclude ambiguous characters if requested
        if self.exclude_ambiguous_checkbox.isChecked():
            ambiguous_chars = "0Ol1iI"
            chars = ''.join(c for c in chars if c not in ambiguous_chars)

        # Validate character set selection
        if not chars or chars == string.ascii_lowercase:
            if not self.include_uppercase_checkbox.isChecked() and \
               not self.include_numbers_checkbox.isChecked() and \
               not self.include_symbols_checkbox.isChecked():
                # If nothing is checked, use secure defaults
                chars = string.ascii_letters + string.digits + string.punctuation
                if self.exclude_ambiguous_checkbox.isChecked():
                    ambiguous_chars = "0Ol1iI"
                    chars = ''.join(c for c in chars if c not in ambiguous_chars)
                QMessageBox.information(
                    self, 
                    "Default Settings Applied", 
                    "No character types selected. Using secure default (letters, numbers, symbols)."
                )

        try:
            # Generate secure password using secrets module
            password = ''.join(secrets.choice(chars) for _ in range(length))
            self.generated_password_output.setText(password)
            self.copy_password_button.setEnabled(True)
            
            # Assess password strength
            strength = self.assess_password_strength(password)
            self.update_strength_indicator(strength)
            
            # Show success message
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message("Secure password generated successfully", 3000)
                
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Password Generation Error", 
                f"Failed to generate password: {str(e)}"
            )

    def assess_password_strength(self, password):
        """Assess the strength of a password"""
        if not password:
            return {"score": 0, "level": "No Password", "feedback": ""}
        
        score = 0
        feedback = []
        
        # Length assessment
        length = len(password)
        if length >= 16:
            score += 25
        elif length >= 12:
            score += 20
        elif length >= 8:
            score += 15
        else:
            score += 5
            feedback.append("Consider longer password")
        
        # Character variety assessment
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        char_types = sum([has_lower, has_upper, has_digit, has_symbol])
        score += char_types * 15
        
        if char_types < 3:
            feedback.append("Use more character types")
        
        # Repetition check
        if len(set(password)) < len(password) * 0.7:
            score -= 10
            feedback.append("Avoid repetitive characters")
        
        # Determine strength level
        if score >= 80:
            level = "Very Strong"
        elif score >= 60:
            level = "Strong"
        elif score >= 40:
            level = "Moderate"
        elif score >= 20:
            level = "Weak"
        else:
            level = "Very Weak"
        
        return {
            "score": max(0, min(100, score)),
            "level": level,
            "feedback": " • ".join(feedback) if feedback else "Excellent password!"
        }

    def update_strength_indicator(self, strength):
        """Update the password strength indicator"""
        score = strength["score"]
        level = strength["level"]
        
        if score >= 80:
            color = "#28a745"  # Green
            bg_color = "#d4edda"
        elif score >= 60:
            color = "#28a745"  # Green
            bg_color = "#d4edda"
        elif score >= 40:
            color = "#ffc107"  # Yellow
            bg_color = "#fff3cd"
        elif score >= 20:
            color = "#fd7e14"  # Orange
            bg_color = "#ffeaa7"
        else:
            color = "#dc3545"  # Red
            bg_color = "#f8d7da"
        
        self.strength_indicator.setText(f"{level} ({score}%)")
        self.strength_indicator.setStyleSheet(f"""
            QLineEdit {{
                border: 1px solid {color};
                border-radius: 3px;
                padding: 8px;
                background-color: {bg_color};
                color: {color};
                font-weight: bold;
            }}
        """)

    def copy_password(self):
        """Copy generated password to clipboard"""
        password = self.generated_password_output.text()
        
        if password:
            try:
                # Get clipboard from QApplication
                from PyQt6.QtWidgets import QApplication
                clipboard = QApplication.clipboard()
                clipboard.setText(password)
                
                QMessageBox.information(
                    self, 
                    "Copied", 
                    "Password copied to clipboard!"
                )
                
                if hasattr(self.main_window, 'show_status_message'):
                    self.main_window.show_status_message("Password copied to clipboard", 3000)
                    
            except Exception as e:
                QMessageBox.warning(
                    self, 
                    "Copy Error", 
                    f"Failed to copy password: {str(e)}"
                )
        else:
            QMessageBox.warning(self, "Warning", "No password to copy.")

    def on_file_dropped_for_hashing(self, file_path):
        """Handle file dropped for hashing"""
        try:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                self.file_to_hash_entry.setText(file_path)
                # Auto-calculate hash if file is dropped
                self.calculate_hash()
                
                if hasattr(self.main_window, 'show_status_message'):
                    self.main_window.show_status_message(f"File dropped and hashed: {os.path.basename(file_path)}", 3000)
            else:
                QMessageBox.warning(self, "Invalid File", "Please drop a valid file for hashing.")
                
        except Exception as e:
            QMessageBox.critical(self, "File Drop Error", f"Error processing dropped file: {str(e)}")
