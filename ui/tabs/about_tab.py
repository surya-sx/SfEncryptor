"""
About Tab Module for Sf-Encryptor

This module provides application information including:
- Application details and version
- Developer information
- License information
- System information
- Credits and acknowledgments
"""

import sys
import platform
import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
                             QTextEdit, QScrollArea, QFrame, QGroupBox, QSizePolicy)
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QFont, QPixmap, QDesktopServices


class AboutTab(QWidget):
    def __init__(self, app_settings, main_window):
        super().__init__()
        self.app_settings = app_settings
        self.main_window = main_window
        self.setup_ui()
        self.setup_button_animations()

    def setup_ui(self):
        """Initialize the about interface"""
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
        
        # Create about sections
        self.create_app_info_section(content_layout)
        self.create_developer_info_section(content_layout)
        self.create_system_info_section(content_layout)
        self.create_license_section(content_layout)
        self.create_credits_section(content_layout)
        
        # Set the scroll area widget
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)

    def create_app_info_section(self, parent_layout):
        """Create application information section"""
        app_group = QGroupBox("Application Information")
        app_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        app_layout = QVBoxLayout(app_group)
        app_layout.setSpacing(15)
        app_layout.setContentsMargins(20, 20, 20, 20)
        
        # Create header layout with logo and title
        header_layout = QHBoxLayout()
        header_layout.setSpacing(20)
        
        # Try to load application logo
        logo_label = QLabel()
        logo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "assets", "Sf_encryptor.png")
        
        if os.path.exists(logo_path):
            pixmap = QPixmap(logo_path)
            if not pixmap.isNull():
                # Scale logo to appropriate size
                scaled_pixmap = pixmap.scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                logo_label.setPixmap(scaled_pixmap)
            else:
                logo_label.setText("SF")
                logo_label.setStyleSheet("font-size: 48px; font-weight: bold; color: #004d40;")
        else:
            logo_label.setText("SF")
            logo_label.setStyleSheet("font-size: 48px; font-weight: bold; color: #004d40;")
        
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setFixedSize(80, 80)
        
        # Application title and version
        title_layout = QVBoxLayout()
        
        app_title = QLabel("SF-Encryptor")
        app_title.setStyleSheet("font-size: 24px; font-weight: bold; color: #2563eb;")
        
        app_version = QLabel("Version 3.0.0")
        app_version.setStyleSheet("font-size: 14px; color: #666;")
        
        app_tagline = QLabel("Secure File Encryption & Management Tool")
        app_tagline.setStyleSheet("font-size: 12px; font-style: italic; color: #888;")
        
        title_layout.addWidget(app_title)
        title_layout.addWidget(app_version)
        title_layout.addWidget(app_tagline)
        title_layout.addStretch()
        
        header_layout.addWidget(logo_label)
        header_layout.addLayout(title_layout)
        header_layout.addStretch()
        
        # Application description
        description = QLabel(
            "SF-Encryptor is a powerful and user-friendly file encryption tool that provides "
            "military-grade encryption for your sensitive files and folders. With support for "
            "multiple encryption algorithms including AES-256, ChaCha20-Poly1305, and Fernet, "
            "you can secure your data with confidence."
        )
        description.setWordWrap(True)
        description.setStyleSheet("font-size: 11px; line-height: 1.4; margin: 10px 0;")
        
        # Application features
        features_text = """
Key Features:
• Multiple encryption algorithms (AES-256, ChaCha20-Poly1305, Fernet)
• Secure key generation and management
• Plugin-based architecture for extensibility
• Batch file and folder encryption/decryption
• Drag and drop support for ease of use
• Secure file deletion options
• Comprehensive logging and monitoring
• Modern and intuitive user interface
        """
        
        features_label = QLabel(features_text)
        features_label.setStyleSheet("font-size: 10px; font-family: 'Consolas', monospace; background: #f8f9fa; padding: 10px; border-radius: 5px;")
        features_label.setWordWrap(True)
        
        app_layout.addLayout(header_layout)
        app_layout.addWidget(description)
        app_layout.addWidget(features_label)
        
        parent_layout.addWidget(app_group)

    def create_developer_info_section(self, parent_layout):
        """Create developer information section"""
        dev_group = QGroupBox("Developer Information")
        dev_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        dev_layout = QVBoxLayout(dev_group)
        dev_layout.setSpacing(15)
        dev_layout.setContentsMargins(20, 20, 20, 20)
        
        # Developer details
        dev_info_layout = QVBoxLayout()
        dev_info_layout.setSpacing(8)
        
        dev_name = QLabel("Developed by: SF Development Team")
        dev_name.setStyleSheet("font-weight: bold; font-size: 12px;")
        
        dev_email = QLabel("Contact: sfencryptor@gmail.com")
        dev_email.setStyleSheet("font-size: 11px; color: #666;")
        
        dev_website = QLabel("Website: https://sfencryptor.dev/")
        dev_website.setStyleSheet("font-size: 11px; color: #666;")
        
        # Action buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(15)
        
        self.github_button = QPushButton("View on GitHub")
        self.github_button.setMinimumHeight(35)
        self.github_button.setMinimumWidth(140)
        self.github_button.setStyleSheet("""
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
        
        self.email_button = QPushButton("Send Feedback")
        self.email_button.setMinimumHeight(35)
        self.email_button.setMinimumWidth(140)
        self.email_button.setStyleSheet("""
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
        
        buttons_layout.addWidget(self.github_button)
        buttons_layout.addWidget(self.email_button)
        buttons_layout.addStretch()
        
        dev_info_layout.addWidget(dev_name)
        dev_info_layout.addWidget(dev_email)
        dev_info_layout.addWidget(dev_website)
        
        dev_layout.addLayout(dev_info_layout)
        dev_layout.addLayout(buttons_layout)
        
        parent_layout.addWidget(dev_group)

    def create_system_info_section(self, parent_layout):
        """Create system information section"""
        system_group = QGroupBox("System Information")
        system_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        system_layout = QVBoxLayout(system_group)
        system_layout.setSpacing(15)
        system_layout.setContentsMargins(20, 20, 20, 20)
        
        # Get system information
        system_info = self.get_system_info()
        
        system_text = QTextEdit()
        system_text.setPlainText(system_info)
        system_text.setReadOnly(True)
        system_text.setMaximumHeight(150)
        
        # Set monospace font for system info
        system_font = QFont("Consolas", 9)
        system_font.setStyleHint(QFont.StyleHint.TypeWriter)
        system_text.setFont(system_font)
        
        system_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        
        system_layout.addWidget(system_text)
        parent_layout.addWidget(system_group)

    def create_license_section(self, parent_layout):
        """Create license information section"""
        license_group = QGroupBox("License Information")
        license_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        license_layout = QVBoxLayout(license_group)
        license_layout.setSpacing(15)
        license_layout.setContentsMargins(20, 20, 20, 20)
        
        license_text = """
MIT License

Copyright (c) 2024 SF Development Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
        """
        
        license_display = QTextEdit()
        license_display.setPlainText(license_text.strip())
        license_display.setReadOnly(True)
        license_display.setMaximumHeight(200)
        
        # Set appropriate font
        license_font = QFont("Consolas", 8)
        license_font.setStyleHint(QFont.StyleHint.TypeWriter)
        license_display.setFont(license_font)
        
        license_display.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        
        license_layout.addWidget(license_display)
        parent_layout.addWidget(license_group)

    def create_credits_section(self, parent_layout):
        """Create credits and acknowledgments section"""
        credits_group = QGroupBox("Credits & Acknowledgments")
        credits_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        credits_layout = QVBoxLayout(credits_group)
        credits_layout.setSpacing(15)
        credits_layout.setContentsMargins(20, 20, 20, 20)
        
        credits_text = """
This application is built using the following open-source libraries and technologies:

• PyQt6 - Cross-platform GUI toolkit for Python
• cryptography - A comprehensive cryptographic library for Python
• secrets - Secure random number generation for Python
• hashlib - Secure hash and message digest algorithms
• pathlib - Object-oriented filesystem paths

Special thanks to:
• All beta testers and users who provided feedback

Icons and graphics are sourced from:
• Feather Icons - Beautiful open-source icons
• Material Design Icons - Google's design system icons
        """
        
        credits_display = QTextEdit()
        credits_display.setPlainText(credits_text.strip())
        credits_display.setReadOnly(True)
        credits_display.setMaximumHeight(200)
        
        credits_font = QFont("Segoe UI", 9)
        credits_display.setFont(credits_font)
        
        credits_display.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        
        credits_layout.addWidget(credits_display)
        parent_layout.addWidget(credits_group)

    def get_system_info(self):
        """Get comprehensive system information"""
        try:
            info_lines = []
            
            # Basic system information
            info_lines.append(f"Operating System: {platform.system()} {platform.release()}")
            info_lines.append(f"OS Version: {platform.version()}")
            info_lines.append(f"Architecture: {platform.architecture()[0]}")
            info_lines.append(f"Machine: {platform.machine()}")
            info_lines.append(f"Processor: {platform.processor()}")
            info_lines.append(f"Python Version: {sys.version.split()[0]}")
            info_lines.append(f"Python Implementation: {platform.python_implementation()}")
            
            # PyQt version
            try:
                from PyQt6.QtCore import QT_VERSION_STR, PYQT_VERSION_STR
                info_lines.append(f"Qt Version: {QT_VERSION_STR}")
                info_lines.append(f"PyQt6 Version: {PYQT_VERSION_STR}")
            except ImportError:
                info_lines.append("Qt Version: Not available")
            
            # Memory information (if available)
            try:
                import psutil
                memory = psutil.virtual_memory()
                info_lines.append(f"Total Memory: {self.format_bytes(memory.total)}")
                info_lines.append(f"Available Memory: {self.format_bytes(memory.available)}")
            except ImportError:
                info_lines.append("Memory Info: psutil not installed")
            
            # Disk space (current drive)
            try:
                import shutil
                current_drive = os.path.splitdrive(os.getcwd())[0] + os.sep
                total, used, free = shutil.disk_usage(current_drive)
                info_lines.append(f"Disk Space (Free): {self.format_bytes(free)}")
            except Exception:
                pass
            
            return "\n".join(info_lines)
            
        except Exception as e:
            return f"Error retrieving system information: {str(e)}"

    def format_bytes(self, bytes_value):
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"

    def setup_button_animations(self):
        """Setup button press animations"""
        buttons = [self.github_button, self.email_button]
        
        for button in buttons:
            button.pressed.connect(lambda b=button: self.animate_button_press(b))
        
        # Connect button actions
        self.github_button.clicked.connect(self.open_github)
        self.email_button.clicked.connect(self.send_feedback)

    def animate_button_press(self, button):
        """Animate button press if animation manager is available"""
        if hasattr(self.main_window, 'animation_manager'):
            self.main_window.animation_manager.animate_button_press(button)

    def open_github(self):
        """Open GitHub repository"""
        github_url = "https://github.com/sf-development/sf-encryptor"
        QDesktopServices.openUrl(QUrl(github_url))
        
        if hasattr(self.main_window, 'show_status_message'):
            self.main_window.show_status_message("Opening GitHub repository...", 2000)

    def send_feedback(self):
        """Open email client for feedback"""
        email_url = "mailto:sfencryptor@gmail.com?subject=SF-Encryptor Feedback&body=Hi SF Team,%0A%0AApplication Version: 3.0.0%0AOperating System: " + platform.system() + "%0A%0AFeedback:%0A"
        QDesktopServices.openUrl(QUrl(email_url))
        
        if hasattr(self.main_window, 'show_status_message'):
            self.main_window.show_status_message("Opening email client...", 2000)

    def retranslate_ui(self):
        """Update UI text for localization (ready for future implementation)"""
        # This method would be called when language changes
        pass
