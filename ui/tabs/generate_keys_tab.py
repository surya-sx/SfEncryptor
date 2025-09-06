"""
Generate Keys Tab Module for Sf-Encryptor

This module provides key generation functionality with features including:
- Cryptographically secure key generation
- Support for all available encryption algorithms
- Base64 encoded key output
- Key length detection based on algorithm
- Copy to clipboard functionality
- Save keys to file with automatic key management integration
"""

import os
import secrets
import datetime
from base64 import b64encode
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QTextEdit, QComboBox, QGroupBox,
                             QFileDialog, QMessageBox, QScrollArea, QFrame)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QIcon


class GenerateKeysTab(QWidget):
    def __init__(self, plugin_manager, key_manager, app_settings, main_window):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.key_manager = key_manager
        self.app_settings = app_settings
        self.main_window = main_window
        self.symmetric_key_b64 = None
        self.setup_ui()
        self.setup_button_animations()
        self.update_plugin_options()

    def setup_ui(self):
        """Initialize the key generation interface with scrolling"""
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
        
        # Create key generation section
        self.create_key_generation_section(content_layout)
        
        # Add stretch to push everything to top
        content_layout.addStretch()
        
        # Set the scroll area widget
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)

    def create_key_generation_section(self, parent_layout):
        """Create the key generation interface"""
        # Main key generation group
        key_gen_group = QGroupBox("Cryptographic Key Generation")
        key_gen_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        key_gen_layout = QVBoxLayout(key_gen_group)
        key_gen_layout.setSpacing(20)
        key_gen_layout.setContentsMargins(20, 20, 20, 20)
        
        # Algorithm selection with key info
        algo_layout = QHBoxLayout()
        algo_layout.setSpacing(15)
        
        self.algo_label = QLabel("Algorithm for Key Generation:")
        self.algo_label.setMinimumWidth(200)
        self.algo_label.setStyleSheet("font-weight: bold;")
        
        self.algo_dropdown = QComboBox()
        self.algo_dropdown.setMinimumHeight(35)
        self.algo_dropdown.setMinimumWidth(200)
        self.algo_dropdown.currentTextChanged.connect(self.on_algorithm_changed)
        
        # Key info label
        self.key_info_label = QLabel("")
        self.key_info_label.setStyleSheet("color: #666; font-style: italic; margin-left: 10px;")
        
        algo_layout.addWidget(self.algo_label)
        algo_layout.addWidget(self.algo_dropdown)
        algo_layout.addWidget(self.key_info_label)
        algo_layout.addStretch()
        
        # Generate button
        self.generate_button = QPushButton("Generate Cryptographic Key")
        self.generate_button.setMinimumHeight(45)
        self.generate_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 2px solid #004d40;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #004d40;
                color: white;
            }
            QPushButton:pressed {
                background-color: #00695c;
            }
            QPushButton:disabled {
                background-color: #e9ecef;
                color: #6c757d;
                border-color: #dee2e6;
            }
        """)
        
        # Key output section
        output_label = QLabel("Generated Key (Base64 Encoded):")
        output_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        
        self.key_output_textbox = QTextEdit()
        self.key_output_textbox.setReadOnly(True)
        self.key_output_textbox.setMinimumHeight(120)
        self.key_output_textbox.setMaximumHeight(120)
        self.key_output_textbox.setPlaceholderText("Generated key will appear here...")
        
        # Set monospace font for key display
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.TypeWriter)
        self.key_output_textbox.setFont(font)
        
        # Action buttons with icons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(15)
        
        # Copy to clipboard button with icon
        self.copy_key_button = QPushButton("Copy to Clipboard")
        self.copy_key_button.setMinimumHeight(40)
        self.copy_key_button.setMinimumWidth(150)
        self.copy_key_button.setEnabled(False)
        self.copy_key_button.setStyleSheet("""
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
        
        # Save key button with icon
        self.save_key_button = QPushButton("Save Key to File")
        self.save_key_button.setMinimumHeight(40)
        self.save_key_button.setMinimumWidth(150)
        self.save_key_button.setEnabled(False)
        self.save_key_button.setStyleSheet("""
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
        
        # Clear button with icon
        self.clear_button = QPushButton("Clear Output")
        self.clear_button.setMinimumHeight(40)
        self.clear_button.setMinimumWidth(120)
        self.clear_button.setEnabled(False)
        self.clear_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                color: #495057;
                border: 2px solid #dc3545;
                border-radius: 5px;
                font-weight: bold;
                padding: 8px 15px;
            }
            QPushButton:hover {
                background-color: #dc3545;
                color: white;
            }
            QPushButton:disabled {
                background-color: #e9ecef;
                color: #6c757d;
                border-color: #dee2e6;
            }
        """)
        
        # Set icons for buttons
        self.set_button_icons()
        
        buttons_layout.addWidget(self.copy_key_button)
        buttons_layout.addWidget(self.save_key_button)
        buttons_layout.addWidget(self.clear_button)
        buttons_layout.addStretch()
        
        # Add all elements to the group
        key_gen_layout.addLayout(algo_layout)
        key_gen_layout.addWidget(self.generate_button)
        key_gen_layout.addWidget(output_label)
        key_gen_layout.addWidget(self.key_output_textbox)
        key_gen_layout.addLayout(buttons_layout)
        
        # Add info section
        self.create_info_section(key_gen_layout)
        
        parent_layout.addWidget(key_gen_group)

    def create_info_section(self, parent_layout):
        """Create information section about key generation"""
        info_group = QGroupBox("Key Generation Information")
        info_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 15px; padding-top: 15px; }")
        info_layout = QVBoxLayout(info_group)
        info_layout.setSpacing(10)
        info_layout.setContentsMargins(15, 15, 15, 15)
        
        info_text = QLabel("""
<b>Security Notes:</b><br>
• Keys are generated using cryptographically secure random number generation<br>
• Key length is automatically determined based on the selected algorithm<br>
• Generated keys are displayed in Base64 format for easy storage and transmission<br>
• Store your keys securely - anyone with access to the key can decrypt your files<br>
• Consider using key files instead of passwords for enhanced security<br>
<br>
<b>Usage:</b><br>
1. Select an encryption algorithm from the dropdown<br>
2. Click "Generate Cryptographic Key" to create a new key<br>
3. Copy the key to clipboard or save to a secure file<br>
4. Use the generated key in the encryption/decryption tabs
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
        
        info_layout.addWidget(info_text)
        parent_layout.addWidget(info_group)

    def set_button_icons(self):
        """Set icons for action buttons using available assets"""
        try:
            # Get assets directory path
            if hasattr(self.main_window, 'directories') and 'assets' in self.main_window.directories:
                assets_dir = self.main_window.directories['assets']
            else:
                # Fallback to finding assets directory
                current_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                assets_dir = os.path.join(current_dir, 'assets')
            
            # Set proper icon size (24x24 pixels)
            icon_size = QSize(24, 24)
            
            # Set clipboard icon
            clipboard_icon_path = os.path.join(assets_dir, 'clipboard_icon.png')
            if os.path.exists(clipboard_icon_path):
                self.copy_key_button.setIcon(QIcon(clipboard_icon_path))
                self.copy_key_button.setIconSize(icon_size)
                
            # Set save icon
            save_icon_path = os.path.join(assets_dir, 'import_save_down_storage_icon.png')
            if os.path.exists(save_icon_path):
                self.save_key_button.setIcon(QIcon(save_icon_path))
                self.save_key_button.setIconSize(icon_size)
                
            # Set trash/delete icon
            trash_icon_path = os.path.join(assets_dir, 'trash_can_delete_remove_icon.png')
            if os.path.exists(trash_icon_path):
                self.clear_button.setIcon(QIcon(trash_icon_path))
                self.clear_button.setIconSize(icon_size)
                
        except Exception as e:
            # Icons are optional, so just log the error if any
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"Could not load button icons: {str(e)}", 3000)

    def on_algorithm_changed(self):
        """Update key info when algorithm changes"""
        try:
            algo_name = self.algo_dropdown.currentText()
            if not algo_name:
                self.key_info_label.setText("")
                return
            
            plugin = self.plugin_manager.get_plugin(algo_name)
            if plugin:
                key_length = getattr(plugin, 'key_length', 256)
                key_bytes = key_length // 8
                
                # Update info label with key details
                info_text = f"Key Length: {key_length} bits ({key_bytes} bytes)"
                
                # Add algorithm-specific info
                if hasattr(plugin, 'cipher_mode'):
                    info_text += f" | Mode: {plugin.cipher_mode}"
                
                self.key_info_label.setText(info_text)
            else:
                self.key_info_label.setText("Algorithm information not available")
                
        except Exception as e:
            self.key_info_label.setText(f"Error: {str(e)}")
            
    def update_key_display_format(self):
        """Improve key display with better formatting"""
        if not self.symmetric_key_b64:
            return
            
        # Format the key for better readability
        key_text = self.symmetric_key_b64
        
        # Add line breaks every 64 characters for better readability
        formatted_key = ""
        line_length = 64
        for i in range(0, len(key_text), line_length):
            formatted_key += key_text[i:i + line_length] + "\n"
        
        # Update the text box
        self.key_output_textbox.setPlainText(formatted_key.strip())
        
        # Update status
        algo_name = self.algo_dropdown.currentText()
        key_bytes = len(self.symmetric_key_b64.encode()) * 3 // 4  # Approximate bytes from base64
        
        if hasattr(self.main_window, 'show_status_message'):
            self.main_window.show_status_message(
                f"Generated {key_bytes}-byte key for {algo_name}", 3000
            )

    def setup_button_animations(self):
        """Setup button press animations"""
        buttons = [
            self.generate_button,
            self.copy_key_button,
            self.save_key_button,
            self.clear_button
        ]
        
        for button in buttons:
            button.pressed.connect(lambda b=button: self.animate_button_press(b))

    def animate_button_press(self, button):
        """Animate button press if animation manager is available"""
        if hasattr(self.main_window, 'animation_manager'):
            self.main_window.animation_manager.animate_button_press(button)

    def update_plugin_options(self):
        """Update algorithm dropdown with available plugins"""
        current_algo = self.algo_dropdown.currentText()
        self.algo_dropdown.clear()
        
        if hasattr(self.plugin_manager, 'get_all_plugins') and self.plugin_manager.get_all_plugins():
            plugin_names = list(self.plugin_manager.get_all_plugins().keys())
            self.algo_dropdown.addItems(plugin_names)
            
            # Restore previous selection if available
            index = self.algo_dropdown.findText(current_algo)
            if index >= 0:
                self.algo_dropdown.setCurrentIndex(index)
            
            # Enable controls
            self.generate_button.setEnabled(True)
            
            # Connect signals after populating
            self.generate_button.clicked.connect(self.generate_keys)
            self.copy_key_button.clicked.connect(self.copy_to_clipboard)
            self.save_key_button.clicked.connect(self.save_key_to_file)
            self.clear_button.clicked.connect(self.clear_output)
            
        else:
            self.algo_dropdown.addItem("No encryption plugins available")
            self.generate_button.setEnabled(False)

    def generate_keys(self):
        """Generate a new cryptographic key"""
        algo_name = self.algo_dropdown.currentText()
        
        if not algo_name or algo_name == "No encryption plugins available":
            QMessageBox.warning(self, "Algorithm Required", "Please select a valid encryption algorithm.")
            return
        
        try:
            # Clear previous output
            self.symmetric_key_b64 = None
            self.key_output_textbox.clear()
            
            # Show generation in progress
            self.generate_button.setEnabled(False)
            self.generate_button.setText("🔄 Generating Key...")
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message("Generating cryptographic key...", 0)
            
            # Get key length from plugin manager
            try:
                key_length_bits = self.plugin_manager.get_plugin_key_length(algo_name)
            except:
                # Default key lengths for common algorithms
                key_length_map = {
                    'AES': 256,
                    'ChaCha20-Poly1305': 256,
                    'Fernet': 256
                }
                key_length_bits = key_length_map.get(algo_name, 256)
            
            key_length_bytes = key_length_bits // 8
            
            # Generate cryptographically secure key
            key = secrets.token_bytes(key_length_bytes)
            self.symmetric_key_b64 = b64encode(key).decode()
            
            # Display the generated key with improved formatting
            import datetime
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            key_display = f"""╔══════════════════════════════════════════════╗
║              ENCRYPTION KEY                  ║
╠══════════════════════════════════════════════╣
║ Algorithm: {algo_name:<29} ║
║ Key Length: {key_length_bits} bits ({key_length_bytes} bytes){' ' * (18 - len(str(key_length_bits)) - len(str(key_length_bytes)))}║
║ Generated: {current_time:<30} ║
╠══════════════════════════════════════════════╣
║                                              ║"""
            
            # Format key with line breaks every 44 characters to fit in the box
            formatted_key_lines = []
            line_length = 44
            for i in range(0, len(self.symmetric_key_b64), line_length):
                line = self.symmetric_key_b64[i:i + line_length]
                formatted_key_lines.append(f"║ {line:<44} ║")
            
            key_display += "\n" + "\n".join(formatted_key_lines)
            key_display += f"""
║                                              ║
╚══════════════════════════════════════════════╝

⚠ SECURITY WARNING:
• Store this key securely - anyone with access can decrypt your files
• Consider using a password manager or secure key storage
• Do not share this key over insecure channels
• Keep backups in multiple secure locations"""
            
            self.key_output_textbox.setPlainText(key_display)
            
            # Enable action buttons
            self.copy_key_button.setEnabled(True)
            self.save_key_button.setEnabled(True)
            self.clear_button.setEnabled(True)
            
            # Show success message
            QMessageBox.information(
                self, 
                "Key Generation Successful", 
                f"Successfully generated a {key_length_bits}-bit {algo_name} key.\n\n"
                f"The key has been displayed in the output area and is ready to use."
            )
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"{algo_name} key generated successfully", 3000)
            
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Key Generation Error", 
                f"An error occurred while generating the key:\n\n{str(e)}"
            )
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"Key generation failed: {str(e)}", 5000)
        
        finally:
            # Reset generate button
            self.generate_button.setEnabled(True)
            self.generate_button.setText("Generate Cryptographic Key")

    def copy_to_clipboard(self):
        """Copy the generated key to clipboard with options"""
        if not self.symmetric_key_b64:
            QMessageBox.warning(self, "No Key", "No key has been generated yet.")
            return
        
        try:
            # Ask user what to copy
            reply = QMessageBox.question(
                self, 
                "Copy Options",
                "What would you like to copy to clipboard?\n\n"
                "• Key Only: Just the Base64 encoded key\n"
                "• Full Display: Complete formatted output",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Yes
            )
            
            copy_text = ""
            if reply == QMessageBox.StandardButton.Yes:
                # Copy key only
                copy_text = self.symmetric_key_b64
                copy_type = "Key"
            elif reply == QMessageBox.StandardButton.No:
                # Copy full display
                copy_text = self.key_output_textbox.toPlainText()
                copy_type = "Full display"
            else:
                # User cancelled
                return
            
            # Copy to clipboard
            if hasattr(self.main_window, 'copy_to_clipboard'):
                self.main_window.copy_to_clipboard(copy_text)
            else:
                # Fallback clipboard copy
                from PyQt6.QtWidgets import QApplication
                clipboard = QApplication.clipboard()
                clipboard.setText(copy_text)
            
            QMessageBox.information(
                self, 
                "Copied Successfully", 
                f"{copy_type} copied to clipboard successfully!\n\n"
                f"Characters copied: {len(copy_text)}"
            )
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"{copy_type} copied to clipboard", 2000)
                
        except Exception as e:
            QMessageBox.critical(self, "Copy Error", f"Failed to copy to clipboard:\n\n{str(e)}")

    def save_key_to_file(self):
        """Save the generated key to a file with enhanced options"""
        if not self.symmetric_key_b64:
            QMessageBox.warning(self, "No Key", "No key has been generated to save.")
            return
        
        try:
            algo_name = self.algo_dropdown.currentText()
            current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"{algo_name.lower().replace('-', '_').replace(' ', '_')}_key_{current_time}.key"
            
            # Get save location
            file_path, selected_filter = QFileDialog.getSaveFileName(
                self,
                "Save Cryptographic Key",
                default_name,
                "Key Files (*.key);;Text Files (*.txt);;JSON Files (*.json);;All Files (*.*)"
            )
            
            if not file_path:
                return
            
            # Determine save format based on file extension or filter
            file_ext = os.path.splitext(file_path)[1].lower()
            
            key_data = {}
            if file_ext == '.json' or 'JSON' in selected_filter:
                # Save as JSON with metadata
                import json
                key_data = {
                    "algorithm": algo_name,
                    "key_length_bits": self.plugin_manager.get_plugin_key_length(algo_name),
                    "key_format": "base64",
                    "key_data": self.symmetric_key_b64,
                    "generated_timestamp": datetime.datetime.now().isoformat(),
                    "application": "SF-Encryptor",
                    "version": "1.3.0.0"
                }
                
                with open(file_path, 'w') as f:
                    json.dump(key_data, f, indent=2)
                    
            else:
                # Save as plain text
                key_header = f"""# SF-Encryptor Generated Key
# Algorithm: {algo_name}
# Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Key Length: {self.plugin_manager.get_plugin_key_length(algo_name)} bits
# Format: Base64
# 
# WARNING: Keep this key secure! Anyone with access can decrypt your files.
#
{self.symmetric_key_b64}"""
                
                with open(file_path, 'w') as f:
                    f.write(key_header)
            
            # Add to key manager if available
            if hasattr(self.key_manager, 'add_key'):
                try:
                    self.key_manager.add_key(
                        name=os.path.basename(file_path),
                        algorithm=algo_name,
                        key_data=self.symmetric_key_b64,
                        file_path=file_path
                    )
                except Exception as key_mgr_error:
                    # Key manager error shouldn't stop the save
                    print(f"Warning: Could not add key to key manager: {key_mgr_error}")
            
            QMessageBox.information(
                self, 
                "Key Saved Successfully", 
                f"Key saved to:\n{file_path}\n\n"
                f"Format: {file_ext.upper() if file_ext else 'TEXT'}\n"
                f"Algorithm: {algo_name}\n"
                f"Size: {os.path.getsize(file_path)} bytes"
            )
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message("Key saved successfully", 3000)
                
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Save Error", 
                f"Failed to save key to file:\n\n{str(e)}"
            )

    def clear_output(self):
        """Clear the key output"""
        self.key_output_textbox.clear()
        self.symmetric_key_b64 = None
        
        # Disable action buttons
        self.copy_key_button.setEnabled(False)
        self.save_key_button.setEnabled(False)
        self.clear_button.setEnabled(False)
        
        if hasattr(self.main_window, 'show_status_message'):
            self.main_window.show_status_message("Key output cleared", 2000)

    def retranslate_ui(self):
        """Update UI text for localization (ready for future implementation)"""
        # This method would be called when language changes
        pass
