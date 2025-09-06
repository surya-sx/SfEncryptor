"""
Encrypt Tab Module for Sf-Encryptor

This module provides the encryption interface with features including:
- File and folder encryption support
- Multiple encryption algorithms via plugins
- Password and key file authentication
- File integrity verification options
- Secure file deletion after encryption
- Progress tracking and batch operations
"""

from PyQt6.QtWidgets import QMessageBox
from ui.tabs.crypto_tab import CryptoTab


class EncryptTab(CryptoTab):
    def __init__(self, plugin_manager, app_settings, main_window):
        super().__init__(plugin_manager, app_settings, main_window, is_encrypt_mode=True)
        self.retranslate_ui()

    def retranslate_ui(self):
        """Update UI text for encryption mode"""
        super().retranslate_ui()
        self.action_button.setText("Encrypt Files")
        
        # Update tooltips for encryption context
        self.input_path_entry.setToolTip("Select files or folders to encrypt")
        self.output_path_entry.setToolTip("Choose where to save encrypted files")
        self.algo_dropdown.setToolTip("Select encryption algorithm")
        self.password_entry.setToolTip("Enter password for encryption")
        
        if hasattr(self, 'delete_original_checkbox'):
            self.delete_original_checkbox.setToolTip("Securely delete original files after successful encryption")

    # The start_operation method is inherited from CryptoTab and provides full encryption functionality
