"""
Key Management Tab Module for Sf-Encryptor

This module provides comprehensive key management functionality including:
- View and manage stored encryption keys
- Import keys from files
- Export keys to secure locations
- Delete keys from storage
- Key validation and information display
- Integration with the key manager system
"""

import os
from datetime import datetime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QListWidget, QListWidgetItem,
                             QGroupBox, QFileDialog, QMessageBox, QScrollArea,
                             QFrame, QTextEdit, QSplitter, QInputDialog)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QFont


class KeyManagementTab(QWidget):
    def __init__(self, key_manager, app_settings, main_window):
        super().__init__()
        self.key_manager = key_manager
        self.app_settings = app_settings
        self.main_window = main_window
        self.ignored_key_paths = set()  # Track paths to ignore during scanning
        self.setup_ui()
        self.setup_button_animations()
        self.load_keys()

    def setup_ui(self):
        """Initialize the key management interface"""
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
        
        # Create key management sections
        self.create_key_actions_section(content_layout)
        self.create_key_list_section(content_layout)
        self.create_key_details_section(content_layout)
        self.create_key_info_section(content_layout)
        
        # Set the scroll area widget
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)

    def create_key_actions_section(self, parent_layout):
        """Create key management actions section"""
        actions_group = QGroupBox("Key Management Actions")
        actions_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        actions_layout = QHBoxLayout(actions_group)
        actions_layout.setSpacing(15)
        actions_layout.setContentsMargins(20, 20, 20, 20)
        
        # Import key button
        self.import_key_button = QPushButton("Import Key from File")
        self.import_key_button.setMinimumHeight(40)
        self.import_key_button.setMinimumWidth(160)
        self.import_key_button.setStyleSheet("""
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
        
        # Export key button
        self.export_key_button = QPushButton("Export Selected Key")
        self.export_key_button.setMinimumHeight(40)
        self.export_key_button.setMinimumWidth(160)
        self.export_key_button.setEnabled(False)
        self.export_key_button.setStyleSheet("""
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
        
        # Delete key button
        self.delete_key_button = QPushButton("Delete Selected Key")
        self.delete_key_button.setMinimumHeight(40)
        self.delete_key_button.setMinimumWidth(160)
        self.delete_key_button.setEnabled(False)
        self.delete_key_button.setStyleSheet("""
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
        
        # Refresh button
        self.refresh_button = QPushButton("Refresh Key List")
        self.refresh_button.setMinimumHeight(40)
        self.refresh_button.setMinimumWidth(140)
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
        
        # Add buttons to layout
        actions_layout.addWidget(self.import_key_button)
        actions_layout.addWidget(self.export_key_button)
        actions_layout.addWidget(self.delete_key_button)
        actions_layout.addWidget(self.refresh_button)
        actions_layout.addStretch()
        
        parent_layout.addWidget(actions_group)

    def create_key_list_section(self, parent_layout):
        """Create key list section"""
        list_group = QGroupBox("Stored Encryption Keys")
        list_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        list_layout = QVBoxLayout(list_group)
        list_layout.setSpacing(15)
        list_layout.setContentsMargins(20, 20, 20, 20)
        
        # Key list widget
        self.key_list_widget = QListWidget()
        self.key_list_widget.setMinimumHeight(200)
        self.key_list_widget.setAlternatingRowColors(True)
        self.key_list_widget.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        
        # Set font for the list
        list_font = QFont()
        list_font.setPointSize(10)
        self.key_list_widget.setFont(list_font)
        
        # Status label
        self.key_status_label = QLabel("Loading keys...")
        self.key_status_label.setStyleSheet("color: #666; font-style: italic;")
        
        list_layout.addWidget(self.key_list_widget)
        list_layout.addWidget(self.key_status_label)
        
        parent_layout.addWidget(list_group)

    def create_key_details_section(self, parent_layout):
        """Create key details section"""
        details_group = QGroupBox("Key Information")
        details_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        details_layout = QVBoxLayout(details_group)
        details_layout.setSpacing(15)
        details_layout.setContentsMargins(20, 20, 20, 20)
        
        # Key details text area
        self.key_details_text = QTextEdit()
        self.key_details_text.setReadOnly(True)
        self.key_details_text.setMaximumHeight(150)
        self.key_details_text.setPlaceholderText("Select a key from the list above to view its details...")
        
        # Set monospace font for details
        details_font = QFont("Consolas", 9)
        details_font.setStyleHint(QFont.StyleHint.TypeWriter)
        self.key_details_text.setFont(details_font)
        
        details_layout.addWidget(self.key_details_text)
        parent_layout.addWidget(details_group)

    def create_key_info_section(self, parent_layout):
        """Create key management information section"""
        info_group = QGroupBox("Key Management Information")
        info_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 15px; padding-top: 15px; }")
        info_layout = QVBoxLayout(info_group)
        info_layout.setSpacing(10)
        info_layout.setContentsMargins(15, 15, 15, 15)
        
        info_text = QLabel("""
<b>Security Best Practices:</b><br>
• Store encryption keys in secure, password-protected locations<br>
• Keep multiple backups of important keys in different secure locations<br>
• Never share keys over unencrypted communication channels<br>
• Use strong, unique passwords for key file protection<br>
• Regularly audit and rotate encryption keys for sensitive data<br>
• Consider using hardware security modules (HSMs) for high-value keys<br>
<br>
<b>Key Management Tips:</b><br>
1. Import keys from secure files or generate new ones in the Generate Keys tab<br>
2. Export keys to encrypted files with strong passwords for backup<br>
3. Delete old or compromised keys from storage immediately<br>
4. Use descriptive names when saving keys to identify their purpose<br>
5. Test key functionality after import to ensure integrity<br>
<br>
<b>Key File Formats:</b><br>
• Base64 encoded keys (recommended for portability)<br>
• Binary key files (for direct plugin usage)<br>
• Password-protected key containers (maximum security)
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

    def setup_button_animations(self):
        """Setup button press animations"""
        buttons = [
            self.import_key_button,
            self.export_key_button,
            self.delete_key_button,
            self.refresh_button
        ]
        
        for button in buttons:
            button.pressed.connect(lambda b=button: self.animate_button_press(b))
        
        # Connect button actions
        self.import_key_button.clicked.connect(self.import_key)
        self.export_key_button.clicked.connect(self.export_key)
        self.delete_key_button.clicked.connect(self.delete_key)
        self.refresh_button.clicked.connect(self.load_keys)
        
        # Connect list selection
        self.key_list_widget.itemSelectionChanged.connect(self.on_key_selection_changed)

    def animate_button_press(self, button):
        """Animate button press if animation manager is available"""
        if hasattr(self.main_window, 'animation_manager'):
            self.main_window.animation_manager.animate_button_press(button)

    def scan_for_key_files(self):
        """Scan for existing key files in common locations"""
        found_keys = []
        
        # Common key file extensions
        key_extensions = ['.key', '.pem', '.der', '.p12', '.pfx', '.crt', '.cert']
        
        # Common locations to search for key files
        search_locations = []
        
        # Add user directories
        user_home = os.path.expanduser("~")
        search_locations.extend([
            user_home,
            os.path.join(user_home, "Documents"),
            os.path.join(user_home, "Desktop"),
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, ".ssh"),  # SSH keys
        ])
        
        # Add application-specific directories
        if os.name == 'nt':  # Windows
            app_data = os.environ.get("LOCALAPPDATA", 
                                    os.path.join(user_home, "AppData", "Local"))
            search_locations.append(os.path.join(app_data, "SF FileManager", "keys"))
        else:  # Unix-like systems
            search_locations.append(os.path.join(user_home, ".sf_filemanager", "keys"))
        
        # Current project directory
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        search_locations.append(project_root)
        
        for location in search_locations:
            if not os.path.exists(location):
                continue
                
            try:
                # Search in the directory (not recursive to avoid performance issues)
                for file_name in os.listdir(location):
                    file_path = os.path.join(location, file_name)
                    
                    # Skip directories
                    if os.path.isdir(file_path):
                        continue
                    
                    # Check if it's a key file by extension
                    file_ext = os.path.splitext(file_name)[1].lower()
                    if file_ext in key_extensions:
                        # Skip if this path is in the ignored list
                        if file_path in self.ignored_key_paths:
                            continue
                            
                        # Try to determine key type by reading the file
                        key_type = self.detect_key_type(file_path)
                        
                        # Get file stats
                        stat = os.stat(file_path)
                        created_date = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d")
                        
                        found_keys.append({
                            'name': file_name,
                            'type': key_type,
                            'path': file_path,
                            'created': created_date,
                            'size': stat.st_size,
                            'status': 'Found on disk'
                        })
                        
            except (PermissionError, OSError):
                # Skip directories we can't access
                continue
        
        return found_keys

    def detect_key_type(self, file_path):
        """Detect the type of key file by examining its content"""
        try:
            # Try to read first few lines to detect format
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024)  # Read first 1KB
                
            content_upper = content.upper()
            
            # Detect common key formats
            if '-----BEGIN RSA PRIVATE KEY-----' in content or '-----BEGIN RSA PUBLIC KEY-----' in content:
                return 'RSA'
            elif '-----BEGIN PRIVATE KEY-----' in content or '-----BEGIN PUBLIC KEY-----' in content:
                return 'Private/Public Key'
            elif '-----BEGIN CERTIFICATE-----' in content:
                return 'Certificate'
            elif '-----BEGIN ENCRYPTED PRIVATE KEY-----' in content:
                return 'Encrypted Private Key'
            elif 'ssh-rsa' in content or 'ssh-dss' in content:
                return 'SSH Key'
            elif len(content) > 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r\t ' for c in content):
                return 'Base64 Key'
            else:
                return 'Binary/Symmetric Key'
                
        except Exception:
            # If we can't read the file, assume it's a binary key
            return 'Binary Key'

    def load_keys(self):
        """Load and display stored keys"""
        try:
            self.key_list_widget.clear()
            
            # Get keys from key manager
            keys = []
            if hasattr(self.key_manager, 'get_all_keys'):
                keys = self.key_manager.get_all_keys()
            
            # Also scan for existing key files in common locations
            scanned_keys = self.scan_for_key_files()
            
            # Combine stored keys with scanned keys (avoid duplicates)
            existing_paths = {key.get('path', '') for key in keys}
            for scanned_key in scanned_keys:
                if scanned_key['path'] not in existing_paths:
                    keys.append(scanned_key)
            
            if not keys:
                self.key_status_label.setText("No keys found. Import or generate keys to get started.")
                self.key_details_text.clear()
                return
            
            # Add keys to the list
            for key_info in keys:
                item = QListWidgetItem()
                
                # Create display text
                name = key_info.get('name', 'Unknown')
                key_type = key_info.get('type', 'Unknown')
                path = key_info.get('path', '')
                
                # Display format: "key_name.key (Symmetric) - /path/to/file"
                display_text = f"[KEY] {name} ({key_type})"
                if path and len(path) > 50:
                    display_text += f" - ...{path[-47:]}"
                elif path:
                    display_text += f" - {path}"
                
                item.setText(display_text)
                item.setData(Qt.ItemDataRole.UserRole, key_info)  # Store full key info
                
                self.key_list_widget.addItem(item)
            
            self.key_status_label.setText(f"Found {len(keys)} stored key(s)")
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"Loaded {len(keys)} keys", 2000)
                
        except Exception as e:
            self.key_status_label.setText(f"Error loading keys: {str(e)}")
            QMessageBox.critical(self, "Key Loading Error", f"Failed to load keys:\n\n{str(e)}")

    def on_key_selection_changed(self):
        """Handle key selection change"""
        selected_items = self.key_list_widget.selectedItems()
        
        if not selected_items:
            # No selection
            self.export_key_button.setEnabled(False)
            self.delete_key_button.setEnabled(False)
            self.key_details_text.clear()
            return
        
        # Enable action buttons
        self.export_key_button.setEnabled(True)
        self.delete_key_button.setEnabled(True)
        
        # Get selected key info
        item = selected_items[0]
        key_info = item.data(Qt.ItemDataRole.UserRole)
        
        if not key_info:
            self.key_details_text.setText("No detailed information available for this key.")
            return
        
        # Display key details
        details = f"""Key Details:

Name: {key_info.get('name', 'Unknown')}
Type: {key_info.get('type', 'Unknown')}
File Path: {key_info.get('path', 'Not specified')}
Created: {key_info.get('created', 'Unknown')}

File Status: {"Exists" if os.path.exists(key_info.get('path', '')) else "Not found"}
File Size: {self.get_file_size(key_info.get('path', '')) if os.path.exists(key_info.get('path', '')) else "N/A"}

Usage Notes:
- This key can be used in the encryption/decryption tabs
- Keep this key file secure and backed up
- Anyone with access to this key can decrypt your files
"""
        
        self.key_details_text.setText(details)

    def get_file_size(self, file_path):
        """Get human readable file size"""
        try:
            size = os.path.getsize(file_path)
            if size < 1024:
                return f"{size} bytes"
            elif size < 1024 * 1024:
                return f"{size / 1024:.1f} KB"
            else:
                return f"{size / (1024 * 1024):.1f} MB"
        except:
            return "Unknown"

    def import_key(self):
        """Import a key from file"""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Import Encryption Key",
                "",
                "Key Files (*.key);;Text Files (*.txt);;All Files (*.*)"
            )
            
            if not file_path:
                return
            
            # Ask for key name
            key_name, ok = QInputDialog.getText(
                self,
                "Key Name",
                "Enter a name for this key:",
                text=os.path.basename(file_path)
            )
            
            if not ok or not key_name.strip():
                return
            
            # Try to add the key
            if hasattr(self.key_manager, 'add_key'):
                self.key_manager.add_key(
                    name=key_name.strip(),
                    key_type="Symmetric",  # Default type
                    path=file_path
                )
            
            # Refresh the list
            self.load_keys()
            
            QMessageBox.information(
                self,
                "Key Imported",
                f"Successfully imported key: {key_name}"
            )
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"Key imported: {key_name}", 3000)
                
        except Exception as e:
            QMessageBox.critical(self, "Import Error", f"Failed to import key:\n\n{str(e)}")

    def export_key(self):
        """Export selected key to a new location"""
        selected_items = self.key_list_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a key to export.")
            return
        
        try:
            key_info = selected_items[0].data(Qt.ItemDataRole.UserRole)
            source_path = key_info.get('path', '')
            
            if not source_path or not os.path.exists(source_path):
                QMessageBox.warning(self, "Key Not Found", "The selected key file could not be found.")
                return
            
            # Get export location
            default_name = key_info.get('name', 'exported_key.key')
            export_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Key To",
                default_name,
                "Key Files (*.key);;Text Files (*.txt);;All Files (*.*)"
            )
            
            if not export_path:
                return
            
            # Copy the key file
            import shutil
            shutil.copy2(source_path, export_path)
            
            QMessageBox.information(
                self,
                "Key Exported",
                f"Key successfully exported to:\n{export_path}"
            )
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message("Key exported successfully", 3000)
                
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export key:\n\n{str(e)}")

    def delete_key(self):
        """Delete selected key"""
        selected_items = self.key_list_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a key to delete.")
            return
        
        key_info = selected_items[0].data(Qt.ItemDataRole.UserRole)
        key_name = key_info.get('name', 'Unknown Key')
        key_path = key_info.get('path', '')
        
        # Determine if this is a managed key or a scanned key
        is_managed_key = key_info.get('status') != 'Found on disk'
        
        # Create appropriate confirmation message
        if is_managed_key:
            message = f"Are you sure you want to delete the key '{key_name}'?\n\n" \
                     f"This will remove the key from the key manager permanently."
        else:
            message = f"Are you sure you want to delete the key '{key_name}'?\n\n" \
                     f"Options:\n" \
                     f"• Remove from list only (file remains on disk)\n" \
                     f"• Delete the actual key file from disk\n\n" \
                     f"Choose your action below:"
        
        if not is_managed_key:
            # For scanned keys, give user choice
            reply = QMessageBox.question(
                self,
                "Delete Key Options",
                message,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel
            )
            
            if reply == QMessageBox.StandardButton.Cancel:
                return
            elif reply == QMessageBox.StandardButton.Yes:
                # Ask if they want to delete the file or just remove from list
                file_delete_reply = QMessageBox.question(
                    self,
                    "Delete File?",
                    f"Do you want to delete the actual key file from disk?\n\n"
                    f"File: {key_path}\n\n"
                    f"Yes = Delete file permanently\n"
                    f"No = Remove from list only",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                
                if file_delete_reply == QMessageBox.StandardButton.Yes:
                    # Delete the actual file
                    try:
                        if os.path.exists(key_path):
                            os.remove(key_path)
                            QMessageBox.information(
                                self, 
                                "File Deleted", 
                                f"Key file '{key_name}' has been permanently deleted from disk."
                            )
                        else:
                            QMessageBox.warning(
                                self,
                                "File Not Found",
                                f"Key file not found at: {key_path}"
                            )
                    except Exception as e:
                        QMessageBox.critical(
                            self,
                            "Delete Error", 
                            f"Failed to delete key file:\n\n{str(e)}"
                        )
                        return
        else:
            # For managed keys, simple confirmation
            reply = QMessageBox.question(
                self,
                "Confirm Deletion",
                message,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        try:
            # Remove from key manager if it's a managed key
            if is_managed_key and hasattr(self.key_manager, 'remove_key'):
                success = self.key_manager.remove_key(key_name)
                if not success:
                    QMessageBox.warning(
                        self, 
                        "Key Not Found", 
                        f"Key '{key_name}' was not found in the key manager."
                    )
            
            # Refresh the list to reflect changes
            self.load_keys()
            
            # Clear selection and details
            self.key_list_widget.clearSelection()
            self.key_details_text.clear()
            self.export_key_button.setEnabled(False)
            self.delete_key_button.setEnabled(False)
            
            QMessageBox.information(
                self, 
                "Key Removed", 
                f"Key '{key_name}' has been removed from the list."
            )
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message(f"Key removed: {key_name}", 3000)
                
        except Exception as e:
            QMessageBox.critical(self, "Delete Error", f"Failed to delete key:\n\n{str(e)}")

    def retranslate_ui(self):
        """Update UI text for localization (ready for future implementation)"""
        # This method would be called when language changes
        pass
