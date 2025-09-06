"""
Drag and Drop Widgets - Custom PyQt6 widgets with drag and drop support.

This module provides custom widgets that support drag and drop operations:
- DragDropLineEdit: Line edit widget that accepts file/folder drops
- DragDropLabel: Label widget for drop targets
- Custom styling and visual feedback
"""

import os
import logging
from PyQt6.QtWidgets import QLineEdit, QLabel
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QDragEnterEvent, QDropEvent

logger = logging.getLogger(__name__)

class DragDropLineEdit(QLineEdit):
    """
    Line edit widget with drag and drop support for files and folders.
    
    Signals:
        fileDropped (str): Emitted when a file is dropped
        folderDropped (str): Emitted when a folder is dropped
        pathDropped (str): Emitted when any path is dropped
    """
    
    fileDropped = pyqtSignal(str)
    folderDropped = pyqtSignal(str)
    pathDropped = pyqtSignal(str)
    
    def __init__(self, parent=None, accept_files=True, accept_folders=True):
        """
        Initialize the drag and drop line edit.
        
        Args:
            parent: Parent widget
            accept_files (bool): Whether to accept file drops
            accept_folders (bool): Whether to accept folder drops
        """
        super().__init__(parent)
        self.accept_files = accept_files
        self.accept_folders = accept_folders
        self.setAcceptDrops(True)
        
        # Store original stylesheet for restoration
        self.original_style = self.styleSheet()
        
        # Drag feedback styles
        self.drag_hover_style = """
            QLineEdit {
                border: 2px dashed #00bcd4;
                background-color: #e0f7fa;
            }
        """
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter events."""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                path = urls[0].toLocalFile()
                
                # Check if we accept this type of drop
                if os.path.isfile(path) and self.accept_files:
                    event.acceptProposedAction()
                    self.setStyleSheet(self.drag_hover_style)
                    return
                elif os.path.isdir(path) and self.accept_folders:
                    event.acceptProposedAction()
                    self.setStyleSheet(self.drag_hover_style)
                    return
        
        event.ignore()
    
    def dragLeaveEvent(self, event):
        """Handle drag leave events."""
        self.setStyleSheet(self.original_style)
        super().dragLeaveEvent(event)
    
    def dropEvent(self, event: QDropEvent):
        """Handle drop events."""
        self.setStyleSheet(self.original_style)
        
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                path = urls[0].toLocalFile()
                
                # Validate the dropped path
                if not os.path.exists(path):
                    logger.warning(f"Dropped path does not exist: {path}")
                    event.ignore()
                    return
                
                # Set the text and emit appropriate signals
                self.setText(path)
                self.pathDropped.emit(path)
                
                if os.path.isdir(path):
                    if self.accept_folders:
                        self.folderDropped.emit(path)
                        event.acceptProposedAction()
                        logger.debug(f"Folder dropped: {path}")
                    else:
                        event.ignore()
                else:
                    if self.accept_files:
                        self.fileDropped.emit(path)
                        event.acceptProposedAction()
                        logger.debug(f"File dropped: {path}")
                    else:
                        event.ignore()
                return
        
        event.ignore()
    
    def set_accept_files(self, accept):
        """
        Set whether to accept file drops.
        
        Args:
            accept (bool): Whether to accept files
        """
        self.accept_files = accept
    
    def set_accept_folders(self, accept):
        """
        Set whether to accept folder drops.
        
        Args:
            accept (bool): Whether to accept folders
        """
        self.accept_folders = accept
    
    def set_placeholder_text(self, text):
        """
        Set placeholder text with drag and drop hint.
        
        Args:
            text (str): Base placeholder text
        """
        if self.accept_files and self.accept_folders:
            hint = " (or drag & drop file/folder here)"
        elif self.accept_files:
            hint = " (or drag & drop file here)"
        elif self.accept_folders:
            hint = " (or drag & drop folder here)"
        else:
            hint = ""
        
        self.setPlaceholderText(text + hint)


class DragDropLabel(QLabel):
    """
    Label widget that can serve as a drop target.
    
    Signals:
        fileDropped (str): Emitted when a file is dropped
        folderDropped (str): Emitted when a folder is dropped
        pathDropped (str): Emitted when any path is dropped
    """
    
    fileDropped = pyqtSignal(str)
    folderDropped = pyqtSignal(str)
    pathDropped = pyqtSignal(str)
    
    def __init__(self, text="", parent=None, accept_files=True, accept_folders=True):
        """
        Initialize the drag and drop label.
        
        Args:
            text (str): Label text
            parent: Parent widget
            accept_files (bool): Whether to accept file drops
            accept_folders (bool): Whether to accept folder drops
        """
        super().__init__(text, parent)
        self.accept_files = accept_files
        self.accept_folders = accept_folders
        self.setAcceptDrops(True)
        
        # Store original stylesheet
        self.original_style = self.styleSheet()
        
        # Default styling for drop zone
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumHeight(100)
        self.setStyleSheet("""
            QLabel {
                border: 2px dashed #80deea;
                border-radius: 8px;
                background-color: #e0f7fa;
                color: #004d40;
                padding: 20px;
                font-size: 12pt;
            }
        """)
        
        # Drag hover style
        self.drag_hover_style = """
            QLabel {
                border: 2px dashed #00bcd4;
                border-radius: 8px;
                background-color: #b2ebf2;
                color: #004d40;
                padding: 20px;
                font-size: 12pt;
                font-weight: bold;
            }
        """
        
        self._update_text()
    
    def _update_text(self):
        """Update the label text based on accepted drop types."""
        if not self.text() or "Drop" in self.text():
            if self.accept_files and self.accept_folders:
                self.setText("Drop files or folders here")
            elif self.accept_files:
                self.setText("Drop files here")
            elif self.accept_folders:
                self.setText("Drop folders here")
            else:
                self.setText("Drop zone disabled")
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter events."""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                path = urls[0].toLocalFile()
                
                # Check if we accept this type of drop
                if os.path.isfile(path) and self.accept_files:
                    event.acceptProposedAction()
                    self.setStyleSheet(self.drag_hover_style)
                    return
                elif os.path.isdir(path) and self.accept_folders:
                    event.acceptProposedAction()
                    self.setStyleSheet(self.drag_hover_style)
                    return
        
        event.ignore()
    
    def dragLeaveEvent(self, event):
        """Handle drag leave events."""
        self.setStyleSheet(self.original_style or """
            QLabel {
                border: 2px dashed #80deea;
                border-radius: 8px;
                background-color: #e0f7fa;
                color: #004d40;
                padding: 20px;
                font-size: 12pt;
            }
        """)
        super().dragLeaveEvent(event)
    
    def dropEvent(self, event: QDropEvent):
        """Handle drop events."""
        self.setStyleSheet(self.original_style or """
            QLabel {
                border: 2px dashed #80deea;
                border-radius: 8px;
                background-color: #e0f7fa;
                color: #004d40;
                padding: 20px;
                font-size: 12pt;
            }
        """)
        
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                path = urls[0].toLocalFile()
                
                # Validate the dropped path
                if not os.path.exists(path):
                    logger.warning(f"Dropped path does not exist: {path}")
                    event.ignore()
                    return
                
                # Emit appropriate signals
                self.pathDropped.emit(path)
                
                if os.path.isdir(path):
                    if self.accept_folders:
                        self.folderDropped.emit(path)
                        event.acceptProposedAction()
                        self.setText(f"Folder: {os.path.basename(path)}")
                        logger.debug(f"Folder dropped: {path}")
                    else:
                        event.ignore()
                else:
                    if self.accept_files:
                        self.fileDropped.emit(path)
                        event.acceptProposedAction()
                        self.setText(f"File: {os.path.basename(path)}")
                        logger.debug(f"File dropped: {path}")
                    else:
                        event.ignore()
                return
        
        event.ignore()
    
    def set_accept_files(self, accept):
        """
        Set whether to accept file drops.
        
        Args:
            accept (bool): Whether to accept files
        """
        self.accept_files = accept
        self._update_text()
    
    def set_accept_folders(self, accept):
        """
        Set whether to accept folder drops.
        
        Args:
            accept (bool): Whether to accept folders
        """
        self.accept_folders = accept
        self._update_text()
    
    def reset(self):
        """Reset the label to its default state."""
        self._update_text()
        self.setStyleSheet("""
            QLabel {
                border: 2px dashed #80deea;
                border-radius: 8px;
                background-color: #e0f7fa;
                color: #004d40;
                padding: 20px;
                font-size: 12pt;
            }
        """)
