"""
Decrypt Tab Module for Sf-Encryptor

This module provides the decryption interface with features including:
- Encrypted file and folder decryption
- Multiple decryption algorithms via plugins
- Password and key file authentication
- Automatic algorithm detection (where possible)
- Progress tracking and batch operations
- File integrity verification
"""

from PyQt6.QtWidgets import QMessageBox
from ui.tabs.crypto_tab import CryptoTab


class DecryptTab(CryptoTab):
    def __init__(self, plugin_manager, app_settings, main_window):
        super().__init__(plugin_manager, app_settings, main_window, is_encrypt_mode=False)
        self.retranslate_ui()

    def retranslate_ui(self):
        """Update UI text for decryption mode"""
        super().retranslate_ui()
        self.action_button.setText("Decrypt Files")
        
        # Update tooltips for decryption context
        self.input_path_entry.setToolTip("Select encrypted files or folders to decrypt")
        self.output_path_entry.setToolTip("Choose where to save decrypted files")
        self.algo_dropdown.setToolTip("Select decryption algorithm (or auto-detect)")
        self.password_entry.setToolTip("Enter password used for encryption")

    # The start_operation method is inherited from CryptoTab and provides full decryption functionality
