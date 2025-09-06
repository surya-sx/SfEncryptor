"""
Logs Tab Module for Sf-Encryptor

This module provides log viewing and management functionality including:
- Real-time log display
- Log level filtering
- Log file management
- Export logs capability
- Clear logs functionality
"""

import os
import logging
import datetime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QLabel, QPushButton, QTextEdit, QComboBox, QGroupBox,
                             QFileDialog, QMessageBox, QScrollArea, QFrame, QCheckBox)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QTextCursor


class LogsTab(QWidget):
    def __init__(self, app_settings, main_window):
        super().__init__()
        self.app_settings = app_settings
        self.main_window = main_window
        self.log_file_path = None
        self.auto_refresh_timer = QTimer()
        self.setup_ui()
        self.setup_button_animations()
        self.setup_auto_refresh()
        self.load_logs()

    def setup_ui(self):
        """Initialize the logs interface"""
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
        
        # Create log management sections
        self.create_log_controls_section(content_layout)
        self.create_log_display_section(content_layout)
        
        # Set the scroll area widget
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)

    def create_log_controls_section(self, parent_layout):
        """Create log control section"""
        controls_group = QGroupBox("Log Management")
        controls_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        controls_layout = QVBoxLayout(controls_group)
        controls_layout.setSpacing(15)
        controls_layout.setContentsMargins(20, 20, 20, 20)
        
        # First row: Level filter and auto-refresh
        first_row_layout = QHBoxLayout()
        first_row_layout.setSpacing(15)
        
        # Log level filter
        level_label = QLabel("Log Level Filter:")
        level_label.setMinimumWidth(120)
        self.level_filter = QComboBox()
        self.level_filter.addItems(["All Levels", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.level_filter.setCurrentText("All Levels")
        self.level_filter.setMinimumHeight(30)
        self.level_filter.currentTextChanged.connect(self.filter_logs)
        
        # Auto refresh checkbox
        self.auto_refresh_checkbox = QCheckBox("Auto-refresh (5s)")
        self.auto_refresh_checkbox.setChecked(True)
        self.auto_refresh_checkbox.stateChanged.connect(self.toggle_auto_refresh)
        
        first_row_layout.addWidget(level_label)
        first_row_layout.addWidget(self.level_filter)
        first_row_layout.addWidget(self.auto_refresh_checkbox)
        first_row_layout.addStretch()
        
        # Second row: Action buttons
        second_row_layout = QHBoxLayout()
        second_row_layout.setSpacing(15)
        
        self.refresh_button = QPushButton("Refresh Logs")
        self.refresh_button.setMinimumHeight(35)
        self.refresh_button.setMinimumWidth(120)
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
        
        self.export_button = QPushButton("Export Logs")
        self.export_button.setMinimumHeight(35)
        self.export_button.setMinimumWidth(120)
        self.export_button.setStyleSheet("""
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
        
        self.clear_button = QPushButton("Clear Display")
        self.clear_button.setMinimumHeight(35)
        self.clear_button.setMinimumWidth(120)
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
        """)
        
        self.open_log_folder_button = QPushButton("Open Log Folder")
        self.open_log_folder_button.setMinimumHeight(35)
        self.open_log_folder_button.setMinimumWidth(140)
        self.open_log_folder_button.setStyleSheet("""
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
        
        second_row_layout.addWidget(self.refresh_button)
        second_row_layout.addWidget(self.export_button)
        second_row_layout.addWidget(self.clear_button)
        second_row_layout.addWidget(self.open_log_folder_button)
        second_row_layout.addStretch()
        
        controls_layout.addLayout(first_row_layout)
        controls_layout.addLayout(second_row_layout)
        
        parent_layout.addWidget(controls_group)

    def create_log_display_section(self, parent_layout):
        """Create log display section"""
        display_group = QGroupBox("Application Logs")
        display_group.setStyleSheet("QGroupBox { font-weight: bold; margin-top: 10px; padding-top: 15px; }")
        display_layout = QVBoxLayout(display_group)
        display_layout.setSpacing(15)
        display_layout.setContentsMargins(20, 20, 20, 20)
        
        # Log display text area
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setMinimumHeight(400)
        
        # Set monospace font for logs
        log_font = QFont("Consolas", 9)
        log_font.setStyleHint(QFont.StyleHint.TypeWriter)
        self.log_display.setFont(log_font)
        
        # Style the log display
        self.log_display.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 5px;
            }
        """)
        
        # Status label
        self.log_status_label = QLabel("Loading logs...")
        self.log_status_label.setStyleSheet("color: #666; font-style: italic;")
        
        display_layout.addWidget(self.log_display)
        display_layout.addWidget(self.log_status_label)
        
        parent_layout.addWidget(display_group)

    def setup_button_animations(self):
        """Setup button press animations"""
        buttons = [
            self.refresh_button,
            self.export_button,
            self.clear_button,
            self.open_log_folder_button
        ]
        
        for button in buttons:
            button.pressed.connect(lambda b=button: self.animate_button_press(b))
        
        # Connect button actions
        self.refresh_button.clicked.connect(self.load_logs)
        self.export_button.clicked.connect(self.export_logs)
        self.clear_button.clicked.connect(self.clear_display)
        self.open_log_folder_button.clicked.connect(self.open_log_folder)

    def animate_button_press(self, button):
        """Animate button press if animation manager is available"""
        if hasattr(self.main_window, 'animation_manager'):
            self.main_window.animation_manager.animate_button_press(button)

    def setup_auto_refresh(self):
        """Setup automatic log refresh"""
        self.auto_refresh_timer.timeout.connect(self.load_logs)
        self.auto_refresh_timer.start(5000)  # Refresh every 5 seconds

    def toggle_auto_refresh(self, state):
        """Toggle auto-refresh functionality"""
        if state == Qt.CheckState.Checked:
            self.auto_refresh_timer.start(5000)
            self.log_status_label.setText("Auto-refresh enabled (5 second intervals)")
        else:
            self.auto_refresh_timer.stop()
            self.log_status_label.setText("Auto-refresh disabled")

    def get_log_file_path(self):
        """Get the current log file path"""
        if self.log_file_path:
            return self.log_file_path
        
        # Try to find the log file
        try:
            import tempfile
            import platform
            
            # Common log locations
            possible_paths = []
            
            if platform.system() == "Windows":
                possible_paths.extend([
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'SF FileManager', 'logs', 'sf_filemanager.log'),
                    os.path.join(os.environ.get('APPDATA', ''), 'SF FileManager', 'logs', 'sf_filemanager.log'),
                    os.path.join(tempfile.gettempdir(), 'sf_filemanager.log')
                ])
            else:
                possible_paths.extend([
                    os.path.join(os.path.expanduser('~'), '.sf_filemanager', 'logs', 'sf_filemanager.log'),
                    os.path.join(tempfile.gettempdir(), 'sf_filemanager.log')
                ])
            
            # Check for existing log files
            for path in possible_paths:
                if os.path.exists(path):
                    self.log_file_path = path
                    return path
            
            # If no log file found, return the first expected path
            if possible_paths:
                self.log_file_path = possible_paths[0]
                return possible_paths[0]
            
        except Exception:
            pass
        
        return None

    def load_logs(self):
        """Load and display logs"""
        try:
            log_path = self.get_log_file_path()
            
            if not log_path or not os.path.exists(log_path):
                # Generate sample logs for demonstration
                sample_logs = self.generate_sample_logs()
                self.log_display.setPlainText(sample_logs)
                self.log_status_label.setText("Displaying sample logs (log file not found)")
                return
            
            # Read the actual log file
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
            
            # Apply filtering if needed
            if self.level_filter.currentText() != "All Levels":
                log_content = self.filter_log_content(log_content, self.level_filter.currentText())
            
            # Update display
            self.log_display.setPlainText(log_content)
            
            # Auto-scroll to bottom
            cursor = self.log_display.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.log_display.setTextCursor(cursor)
            
            # Update status
            line_count = len(log_content.split('\n')) if log_content else 0
            file_size = os.path.getsize(log_path) if os.path.exists(log_path) else 0
            size_str = self.format_file_size(file_size)
            
            self.log_status_label.setText(f"Log file: {os.path.basename(log_path)} | Lines: {line_count} | Size: {size_str}")
            
        except Exception as e:
            error_msg = f"Error loading logs: {str(e)}"
            self.log_display.setPlainText(error_msg)
            self.log_status_label.setText("Error loading log file")

    def generate_sample_logs(self):
        """Generate sample log entries for demonstration"""
        import datetime
        
        current_time = datetime.datetime.now()
        sample_logs = []
        
        # Sample log entries
        log_entries = [
            ("INFO", "Application initialized successfully"),
            ("INFO", "Loading encryption plugins..."),
            ("INFO", "Loaded 3 encryption plugins: AES, ChaCha20-Poly1305, Fernet"),
            ("INFO", "Settings loaded from configuration file"),
            ("DEBUG", "Plugin manager initialized"),
            ("DEBUG", "Key manager initialized"),
            ("INFO", "Main window displayed"),
            ("INFO", "Ready for user operations"),
            ("DEBUG", "Auto-refresh timer started"),
            ("INFO", "Log viewer opened")
        ]
        
        for i, (level, message) in enumerate(log_entries):
            timestamp = (current_time - datetime.timedelta(minutes=10-i)).strftime("%Y-%m-%d %H:%M:%S")
            log_line = f"{timestamp} - SF FileManager - {level} - {message}"
            sample_logs.append(log_line)
        
        return "\n".join(sample_logs)

    def filter_log_content(self, content, level):
        """Filter log content by level"""
        if not content or level == "All Levels":
            return content
        
        lines = content.split('\n')
        filtered_lines = []
        
        for line in lines:
            if f" - {level} - " in line:
                filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)

    def filter_logs(self):
        """Apply log level filter"""
        self.load_logs()

    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"

    def export_logs(self):
        """Export logs to a file"""
        try:
            # Get export location
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Logs",
                f"sf_encryptor_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                "Text Files (*.txt);;All Files (*.*)"
            )
            
            if not file_path:
                return
            
            # Export current display content
            log_content = self.log_display.toPlainText()
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"SF-Encryptor Log Export\n")
                f.write(f"Exported on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Filter Level: {self.level_filter.currentText()}\n")
                f.write("-" * 80 + "\n\n")
                f.write(log_content)
            
            QMessageBox.information(
                self,
                "Export Successful",
                f"Logs exported successfully to:\n{file_path}"
            )
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message("Logs exported successfully", 3000)
                
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export logs:\n\n{str(e)}")

    def clear_display(self):
        """Clear the log display"""
        self.log_display.clear()
        self.log_status_label.setText("Log display cleared")
        
        if hasattr(self.main_window, 'show_status_message'):
            self.main_window.show_status_message("Log display cleared", 2000)

    def open_log_folder(self):
        """Open the log folder in file explorer"""
        try:
            import subprocess
            import platform
            
            log_path = self.get_log_file_path()
            if not log_path:
                QMessageBox.warning(
                    self,
                    "Log Folder Not Found",
                    "Could not locate the log folder."
                )
                return
            
            log_dir = os.path.dirname(log_path)
            
            if not os.path.exists(log_dir):
                QMessageBox.warning(
                    self,
                    "Folder Not Found",
                    f"Log folder not found:\n{log_dir}"
                )
                return
            
            # Open folder based on OS
            system = platform.system()
            if system == "Windows":
                os.startfile(log_dir)
            elif system == "Darwin":  # macOS
                subprocess.run(["open", log_dir])
            else:  # Linux and others
                subprocess.run(["xdg-open", log_dir])
            
            if hasattr(self.main_window, 'show_status_message'):
                self.main_window.show_status_message("Log folder opened", 2000)
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error Opening Folder",
                f"Could not open log folder:\n\n{str(e)}"
            )

    def retranslate_ui(self):
        """Update UI text for localization (ready for future implementation)"""
        # This method would be called when language changes
        pass
