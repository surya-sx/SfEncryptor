import sys
import os
import json
import argparse
import logging
import importlib.util
import time
from base64 import b64encode, b64decode
import hashlib
import webbrowser
from datetime import datetime
import shutil
import gzip
import bz2
import lzma
from logging.handlers import RotatingFileHandler
import secrets
import string

# --- PyQt6 Imports ---
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QCheckBox, QProgressBar,
    QTextEdit, QFileDialog, QMessageBox, QFrame, QRadioButton,
    QListWidget, QListWidgetItem, QStatusBar, QHBoxLayout,
    QHeaderView, QTableWidget, QTableWidgetItem, QMenu, QSlider, QButtonGroup,
    QToolButton, QStackedWidget, QSpinBox, QSizePolicy
)
from PyQt6.QtGui import QPixmap, QIcon, QFont, QColor, QImage, QBrush, QGuiApplication, QAction
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject, QPropertyAnimation, QSize, QEasingCurve, QCoreApplication

# --- Cryptography Imports ---
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

# --- Configuration and Global Settings ---
APP_NAME = "SF FileManager"
APP_VERSION = "1.3.0.0"
DEVELOPER_NAME = "Surya B"
DEVELOPER_EMAIL = "myselfsuryaaz@gmail.com"
GITHUB_URL = "https://github.com/Suryabx"

# --- Fix for PyInstaller plugin loading ---
# This block of code ensures that the application can find the plugins
# directory whether it's running as a script or a compiled executable.
if getattr(sys, 'frozen', False):
    # If running as a bundled executable, use the temporary directory
    # where PyInstaller extracts the files.
    BASE_DIR = sys._MEIPASS
else:
    # If running as a normal script, use the current directory.
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PLUGINS_DIR = os.path.join(BASE_DIR, "plugins")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")

ICON_FILENAME = "Sf_encryptor.png"
SF_LOGO_FILENAME = "Sf_encryptor.png"
GITHUB_LOGO_FILENAME = "github.png"

# --- OS-Specific Directory Setup ---
if sys.platform == "win32":
    APP_DATA_BASE_DIR = os.environ.get("LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local"))
elif sys.platform == "darwin":
    APP_DATA_BASE_DIR = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
else:
    APP_DATA_BASE_DIR = os.environ.get("XDG_DATA_HOME", os.path.join(os.path.expanduser("~"), ".local", "share"))

APP_SPECIFIC_DIR = os.path.join(APP_DATA_BASE_DIR, APP_NAME)
LOG_DIR = os.path.join(APP_SPECIFIC_DIR, "logs")
SETTINGS_DIR = APP_SPECIFIC_DIR
LANGUAGES_DIR = os.path.join(APP_SPECIFIC_DIR, "languages")
KEYS_DIR = os.path.join(APP_SPECIFIC_DIR, "keys")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "sf_manager_suite.log")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")
KEY_STORE_FILE = os.path.join(KEYS_DIR, "key_store.json")

# --- Logging Setup ---
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
    logger.addHandler(console_handler)

# --- Modern UI Theme ---
THEME_PRIMARY_BG = "#e0f7fa"  # Lighter, more vibrant sky blue
THEME_SECONDARY_BG = "#b2ebf2" # Brighter, slightly darker sky blue
THEME_FOREGROUND = "#004d40"    # Dark teal for high contrast text
THEME_ACCENT = "#00bcd4"        # Cyan for vibrant accents
THEME_ACCENT_DARK = "#00838f"   # Darker cyan for hover
THEME_BORDER = "#80deea"        # Light cyan border
THEME_ERROR_RED = "#e74c3c"
THEME_SUCCESS_GREEN = "#2ecc71"
THEME_WARNING_ORANGE = "#f39c12"
THEME_CARD_BG = "#ffffff"       # White card background with shadow
THEME_SHADOW_COLOR = "#00000030" # Subtle shadow for depth

BRIGHT_ARROW_COLOR = "#004d40" # Using the dark teal foreground color for contrast

MODERN_STYLESHEET = f"""
    QWidget {{
        background-color: {THEME_PRIMARY_BG};
        color: {THEME_FOREGROUND};
        font-family: "Segoe UI", "Inter", sans-serif;
        font-size: 10pt;
    }}
    QMainWindow {{
        background-color: {THEME_PRIMARY_BG};
    }}
    /* Main container and sidebar */
    #MainContainer {{
        background-color: {THEME_PRIMARY_BG};
    }}
    #Sidebar {{
        background-color: {THEME_SECONDARY_BG};
        border-right: 1px solid {THEME_BORDER};
        border-radius: 0 15px 15px 0;
        padding: 10px;
    }}
    #NavButton {{
        background-color: transparent;
        border: none;
        padding: 12px 15px;
        text-align: left;
        border-radius: 8px;
        font-weight: 500;
        color: {THEME_FOREGROUND};
    }}
    #NavButton:hover {{
        background-color: {THEME_BORDER};
    }}
    #NavButton:checked {{
        background-color: {THEME_ACCENT};
        color: white;
        font-weight: bold;
    }}
    /* Content Area */
    #MainContentArea {{
        background-color: {THEME_PRIMARY_BG};
        padding: 20px;
    }}
    #Card {{
        background-color: {THEME_CARD_BG};
        border: 1px solid {THEME_BORDER};
        border-radius: 12px;
        padding: 20px;
    }}
    QPushButton {{
        background-color: {THEME_ACCENT};
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 8px;
        font-weight: bold;
    }}
    QPushButton:hover {{
        background-color: {THEME_ACCENT_DARK};
    }}
    QPushButton:pressed {{
        background-color: #1e6091;
    }}
    QPushButton:disabled {{
        background-color: {THEME_BORDER};
        color: #6c7a89;
    }}
    QLineEdit, QTextEdit, QListWidget, QTableWidget {{
        background-color: {THEME_SECONDARY_BG};
        border: 1px solid {THEME_BORDER};
        border-radius: 8px;
        padding: 8px;
        color: {THEME_FOREGROUND};
    }}
    QLineEdit:focus, QTextEdit:focus, QListWidget:focus, QTableWidget:focus {{
        border: 1px solid {THEME_ACCENT};
    }}
    QComboBox {{
        background-color: {THEME_SECONDARY_BG};
        border: 1px solid {THEME_BORDER};
        border-radius: 8px;
        padding: 8px;
        color: {THEME_FOREGROUND};
        padding-right: 30px;
    }}
    QComboBox:focus {{
        border: 1px solid {THEME_ACCENT};
    }}
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 25px;
        border-left-width: 1px;
        border-left-color: {THEME_BORDER};
        border-left-style: solid;
        border-top-right-radius: 7px;
        border-bottom-right-radius: 7px;
        background-color: {THEME_SECONDARY_BG};
        border: none;
    }}
    QComboBox::down-arrow {{
        image: none;
        background: transparent;
        width: 0px;
        height: 0px;
    }}
    QToolButton#ComboBoxArrowButton {{
        background-color: {THEME_SECONDARY_BG};
        border: 1px solid {THEME_BORDER};
        border-left: none;
        border-top-right-radius: 7px;
        border-bottom-right-radius: 7px;
        width: 25px;
        height: 100%;
        padding: 0;
    }}
    QToolButton#ComboBoxArrowButton:hover {{
        background-color: {THEME_BORDER};
    }}
    QCheckBox::indicator {{
        border: 1px solid {THEME_ACCENT};
        border-radius: 4px;
        background-color: {THEME_CARD_BG};
        width: 16px;
        height: 16px;
    }}
    QCheckBox::indicator:checked {{
        background-color: {THEME_ACCENT};
    }}
    QRadioButton::indicator {{
        width: 14px;
        height: 14px;
        border-radius: 7px;
        border: 1px solid {THEME_ACCENT};
        background-color: {THEME_CARD_BG};
    }}
    QRadioButton::indicator:checked {{
        background-color: {THEME_ACCENT};
    }}
    QLabel#TitleLabel {{
        font-size: 16pt;
        font-weight: bold;
        color: {THEME_FOREGROUND};
        margin-bottom: 10px;
    }}
    QLabel#SectionLabel {{
        font-size: 12pt;
        font-weight: bold;
        color: {THEME_FOREGROUND};
        margin-top: 15px;
        margin-bottom: 5px;
    }}
    QProgressBar {{
        border: 1px solid {THEME_ACCENT};
        border-radius: 10px;
        text-align: center;
        background-color: {THEME_SECONDARY_BG};
        color: {THEME_FOREGROUND};
        height: 25px;
    }}
    QProgressBar::chunk {{
        background-color: {THEME_ACCENT};
        border-radius: 9px;
    }}
    QStatusBar {{
        background-color: {THEME_PRIMARY_BG};
        color: {THEME_FOREGROUND};
        border-top: 1px solid {THEME_BORDER};
    }}
    QTableWidget {{
        gridline-color: {THEME_BORDER};
        border: 1px solid {THEME_BORDER};
        border-radius: 8px;
    }}
    QTableWidget::item {{
        padding: 5px;
    }}
    QTableWidget::item:selected {{
        background-color: {THEME_ACCENT};
        color: white;
    }}
    QHeaderView::section {{
        background-color: {THEME_SECONDARY_BG};
        color: {THEME_FOREGROUND};
        padding: 8px;
        border: 1px solid {THEME_BORDER};
        border-radius: 4px;
        font-weight: bold;
    }}
    QMenu {{
        background-color: {THEME_CARD_BG};
        border: 1px solid {THEME_BORDER};
        border-radius: 6px;
    }}
    QMenu::item {{
        padding: 8px 18px;
        color: {THEME_FOREGROUND};
    }}
    QMenu::item:selected {{
        background-color: {THEME_SECONDARY_BG};
    }}
    #ChatContainer {{
        background-color: {THEME_SECONDARY_BG};
        border: 1px solid {THEME_BORDER};
        border-radius: 10px;
        padding: 10px;
    }}
    #ChatInput {{
        background-color: {THEME_CARD_BG};
        border: 1px solid {THEME_BORDER};
        border-radius: 15px;
        padding: 10px 15px;
    }}
    #ChatHistory {{
        background-color: transparent;
        border: none;
    }}
    #ChatSendButton {{
        border-radius: 15px;
        padding: 8px;
    }}
    #MessageBox {{
        background-color: {THEME_CARD_BG};
        border: 1px solid {THEME_BORDER};
        border-radius: 8px;
        padding: 15px;
    }}
"""

# --- Custom QComboBox with ToolButton for Arrow ---
class CustomComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setEditable(False)
        self.init_arrow_button()

    def init_arrow_button(self):
        self.arrow_button = QToolButton(self)
        self.arrow_button.setObjectName("ComboBoxArrowButton")
        pixmap = QPixmap(os.path.join(ASSETS_DIR, "downarrow.png"))
        self.arrow_button.setIcon(QIcon(pixmap))
        self.arrow_button.setIconSize(pixmap.size())
        self.arrow_button.setCursor(Qt.CursorShape.ArrowCursor)

        self.arrow_button.clicked.connect(self.showPopup)

        self.arrow_button.installEventFilter(self)
        self.update_arrow_button_geometry()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update_arrow_button_geometry()

    def showPopup(self):
        super().showPopup()

    def update_arrow_button_geometry(self):
        button_width = 25
        self.arrow_button.setGeometry(
            self.width() - button_width, 0,
            button_width, self.height()
        )

    def eventFilter(self, obj, event):
        if obj == self.arrow_button and event.type() == event.Type.MouseButtonPress:
            self.showPopup()
            return True
        return super().eventFilter(obj, event)

# --- DragDropLineEdit ---
class DragDropLineEdit(QLineEdit):
    fileDropped = pyqtSignal(str)
    folderDropped = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        if urls := event.mimeData().urls():
            path = urls[0].toLocalFile()
            self.setText(path)
            if os.path.isdir(path):
                self.folderDropped.emit(path)
            else:
                self.fileDropped.emit(path)

class LocalizationManager:
    def __init__(self):
        self.current_language = "en"
        self.translations = {}
        self._default_english_translations = {
            "app_name": "SF FileManager", "encrypt_tab": "Encrypt", "decrypt_tab": "Decrypt",
            "generate_keys_tab": "Generate Keys", "settings_tab": "Settings", "about_tab": "About",
            "plugins_tab": "Plugins", "input_file_folder": "Input File/Folder:",
            "select_file_folder": "Select File/Folder", "select_file": "Select File", "select_folder": "Select Folder",
            "select_file_folder_encrypt": "Select file or folder to encrypt", "output_folder": "Output Folder:",
            "select_output_folder": "Select output folder", "encryption_algorithm": "Encryption Algorithm:",
            "no_plugins_loaded": "No Plugins Loaded", "key_len": "Key Len:", "nonce_iv_len": "Nonce/IV Len:",
            "mode": "Mode:", "padding": "Padding:", "key_type": "Key Type:",
            "password_derive_key": "Password (Derive Key)", "direct_key_base64_pem": "Direct Key (Base64/PEM)",
            "enter_password_derivation": "Enter password for key derivation", "password": "Password:",
            "direct_key": "Direct Key:", "show_input": "Show Input", "password_strength": "Password Strength: ",
            "weak": "Weak", "medium": "Medium", "strong": "Strong", "kdf_iterations": "KDF Iterations:",
            "output_suffix": "Output Suffix:", "delete_original_after_encrypt": "Delete Original After Encrypt",
            "encrypt_files": "Encrypt File(s)", "decrypt_files": "Decrypt File(s)",
            "input_encrypted_file_folder": "Input Encrypted File/Folder:",
            "select_encrypted_file_folder": "Select encrypted file or folder", "decryption_algorithm": "Decryption Algorithm:",
            "input_salt": "Input Salt:", "input_nonce_iv": "Input Nonce/IV:",
            "algorithm_key_generation": "Algorithm for Key Generation:", "key_length_bits_rsa": "Key Length (bits, for RSA):",
            "output_format": "Output Format:", "base64_url_safe": "Base64 (URL-safe)", "hex": "Hex",
            "pem_rsa_only": "PEM (RSA Only)", "generate_keys": "Generate Key(s)", "generated_keys": "Generated Key(s):",
            "copy_keys_clipboard": "Copy Key(s) to Clipboard", "theme": "Theme:",
            "system": "System", "auto_clear_logs_startup": "Auto-clear logs on startup",
            "confirm_overwrite_files": "Confirm before overwriting files", "enable_expert_mode": "Enable Expert Mode (More Options)",
            "log_level": "Log Level:", "file_chunk_size_kb": "File Chunk Size (KB):", "language_wip": "Language:",
            "export_settings": "Export Settings", "import_settings": "Import Settings",
            "loaded_encryption_plugins": "Loaded Encryption Plugins", "reload_plugins": "Reload Plugins",
            "selected_plugin_details": "Selected Plugin Details:", "name": "Name:", "key_length": "Key Length:",
            "nonce_iv_length": "Nonce/IV Length:", "cipher_mode": "Cipher Mode:",
            "no_plugins_found": "No plugins found. Place .py files in the 'plugins' folder.", "view_github": "View GitHub",
            "license_proprietary": "License: Proprietary (See terms.txt)",
            "feedback_contact_github": "For feedback or contact, please visit the GitHub page.",
            "app_started": "{app_name} v{app_version} started.", "input_error": "Input Error",
            "all_fields_filled": "All fields must be filled.", "encryption_complete_title": "Encryption Complete",
            "encryption_complete": "{count} file(s) encrypted successfully!", "decryption_complete_title": "Decryption Complete",
            "decryption_complete": "{count} file(s) decrypted successfully!", "key_generation": "Key Generation",
            "key_generation_success": "{algo_name} key(s) generated successfully!", "key_generation_error_title": "Key Generation Error",
            "key_copied_clipboard": "Key(s) copied to clipboard!", "no_key_copy": "No key to copy.",
            "plugins_reloaded": "Plugins Reloaded", "plugins_reloaded_success": "Plugins reloaded successfully!",
            "app_closed": "{app_name} closed.", "browse": "Browse", "encrypting": "Encrypting...", "decrypting": "Decrypting...",
            "expert_mode_warning_title": "Expert Mode Enabled",
            "expert_mode_warning_message": "Expert Mode exposes advanced cryptographic options. Incorrect use may lead to data loss or insecure operations. Proceed with caution.",
            "version": "Version: ", "developed_by": "Developed by: ",
            "tooltip_input_file": "Select the file or folder to process. You can also drag and drop a file here.",
            "tooltip_output_folder": "Select the destination folder for the output files.",
            "tooltip_algorithm": "Choose the encryption or decryption algorithm.",
            "tooltip_key_type": "Choose between deriving a key from a password or using a direct key (Base64/PEM).",
            "tooltip_password": "Enter the password. Used to generate a secure encryption key.",
            "tooltip_direct_key": "Enter the key directly, usually in Base64 or PEM format.",
            "tooltip_iterations": "Number of rounds for password-based key derivation. Higher is more secure.",
            "tooltip_delete_original": "If checked, the original file will be deleted after a successful operation.",
            "tooltip_rsa_gen_password": "Optional. If provided, the generated RSA private key will be encrypted with this password.",
            "tooltip_save_key": "Save the generated key(s) to a file.",
            "plugins_enable_disable": "Enable or disable encryption plugins. Changes are saved automatically.",
            "save_public_key": "Save Public Key...", "save_private_key": "Save Private Key...",
            "key_saved_to": "Key saved to {path}", "file_save_error": "File Save Error",
            "no_key_to_save": "No key to save.", "copied_to_clipboard": "Copied to clipboard!",
            "status_file_selected": "File selected: {path}", "status_metadata_found": "Metadata found. Algorithm set to {algo}.",
            "status_metadata_error": "Could not read metadata: {e}",
            "metadata_not_found": "Metadata file (.meta) not found. Manual configuration required.",
            "invalid_password_or_corrupt": "Decryption failed: Invalid password or corrupted file.",
            "file_processing_status": "Processing: {filename}", "waiting_for_op": "Waiting for operation...",
            "rsa_gen_password_label": "Key Password (optional):",
            "whats_new_tab": "What's New",
            "whats_new_content": """
                <h3>Welcome to the new and improved SF FileManager Suite!</h3>
                <p>This version brings a host of new features and improvements:</p>
                <ul>
                    <li><b>Modern UI Overhaul:</b> A fresh, clean look with new colors, gradients, and styles for a better user experience.</li>
                    <li><b>Drag & Drop Support:</b> You can now drag files directly onto the input fields to select them instantly.</li>
                    <li><b>Automatic Metadata Files:</b> Encryption settings (like algorithm, salt, etc.) are now saved automatically with your files, making decryption much easier.</li>
                    <li><b>Enhanced Security:</b> Generate password-protected RSA keys to keep your private keys secure.</li>
                    <li><b>Plugin Management:</b> Easily enable or disable encryption algorithms from the new 'Plugins' tab.</li>
                    <li><b>Command-Line Interface (CLI):</b> Automate your encryption tasks by running the application from the command line.</li>
                    <li><b>Key File Support for Encryption/Decryption:</b> You can now use generated RSA public/private keys or symmetric keys directly from files for cryptographic operations.</li>
                    <li><b>Improved Key Management:</b> The Key Management tab now provides better tools to view, export, and delete your stored keys.</li>
                    <li><b>Refined UI/CSS:</b> The application's visual aesthetics have a been further polished across all themes for a more modern and consistent look.</li>
                </ul>
                <p>Thank you for using the application!</p>
            """,
            "compression_algorithm": "Compression Algorithm:",
            "compression_level": "Compression Level:",
            "no_compression": "No Compression",
            "gzip": "Gzip", "bzip2": "Bzip2", "lzma": "LZMA",
            "secure_shredding_passes": "Secure Shredding Passes (0 for none):",
            "file_integrity_check": "File Integrity Check (SHA-256)",
            "log_viewer": "Log Viewer",
            "filter_by_level": "Filter by Level:",
            "search_logs": "Search Logs...",
            "export_logs": "Export Logs",
            "all_levels": "All Levels", "info": "INFO", "warning": "WARNING", "error": "ERROR",
            "log_exported_to": "Logs exported to {path}",
            "log_export_error": "Error exporting logs: {e}",
            "key_management_tab": "Key Management",
            "managed_keys": "Managed Keys:",
            "key_name": "Key Name", "key_type": "Type", "key_path": "Path", "key_actions": "Actions",
            "export_key": "Export Key", "delete_key": "Delete Key", "view_key": "View Key",
            "key_deleted": "Key '{name}' deleted.",
            "key_exported": "Key '{name}' exported to {path}",
            "confirm_delete_key": "Are you sure you want to delete key '{name}'? This action cannot be undone.",
            "key_view_title": "View Key: {name}",
            "key_load_error": "Error loading key: {e}",
            "checksum_mismatch": "Checksum mismatch for {filename}! File may be corrupted.",
            "checksum_verified": "Checksum verified for {filename}.",
            "file_shredding": "Securely shredding original file...",
            "shredding_complete": "Original file securely shredded.",
            "batch_processing_progress": "Overall Progress: {current}/{total} files ({percentage:.1f}%)",
            "file_processing_status_batch": "Processing file {current_file_index}/{total_files}: {filename}",
            "operation_cancelled": "Operation cancelled by user.",
            "loading_app": "Loading Application...",
            "initializing_ui": "Initializing User Interface...",
            "loading_plugins": "Loading Encryption Plugins...",
            "preparing_key_manager": "Preparing Key Manager...",
            "finalizing_startup": "Finalizing Startup...",
            "font_selection": "Font Selection:",
            "animation_speed": "Animation Speed:",
            "log_file_settings": "Log File Settings",
            "max_log_size_mb": "Max Log Size (MB):",
            "enable_log_rotation": "Enable Log Rotation",
            "default_output_folder": "Default Output Folder:",
            "select_default_output_folder": "Select Default Output Folder",
            "default_encryption_algorithm": "Default Encryption Algorithm:",
            "confirm_on_exit": "Confirm on Exit",
            "contact_developer": "Contact Developer",
            "contact_email_label": "Contact Email:",
            "save_symmetric_key": "Save Symmetric Key...",
            "password_input_type": "Password Input Type:",
            "use_password": "Use Password",
            "use_key_file": "Use Key File",
            "key_file_path": "Key File Path:",
            "select_key_file": "Select Key File",
            "open_github": "Open GitHub",
            "success": "Success",
            "error": "Error",
            "no_key": "No Key",
            "confirm_exit_title": "Confirm Exit",
            "confirm_exit_message": "Are you sure you want to exit?",
            "key_error_title": "Key Error",
            "delete_failed_title": "Delete Failed",
            "no_symmetric_plugins_found": "No symmetric encryption plugins found. Please add plugins to the 'plugins' folder.",
            "select_algorithm_warning": "Please select an encryption algorithm.",
            "confirm_delete_key_title": "Confirm Key Deletion",
            "delete_failed_message": "Failed to delete key '{name}'.",
            "export_complete_title": "Export Complete",
            "export_error_title": "Export Error",
            "Time": "Time",
            "Level": "Level",
            "Message": "Message",
            "password_strength_weak": "Weak: Use a mix of characters.",
            "password_strength_medium": "Medium: Add numbers and symbols.",
            "password_strength_strong": "Strong: Longer, complex password.",
            "decrypt_failed_invalid_password": "Decryption failed: Incorrect password.",
            "decrypt_failed_corrupt": "Decryption failed: The file is corrupted or not a valid encrypted file.",
            "file_integrity_tab": "File Integrity",
            "file_integrity_title": "File Integrity & Password Generator",
            "file_to_hash": "File to Hash:",
            "calculate_hash": "Calculate Hash",
            "sha256_hash": "SHA-256 Hash:",
            "sha512_hash": "SHA-512 Hash:",
            "secure_password_generator": "Secure Password Generator",
            "password_length": "Password Length:",
            "include_uppercase": "Include Uppercase",
            "include_numbers": "Include Numbers",
            "include_symbols": "Include Symbols",
            "generate_password": "Generate Password",
            "generated_password": "Generated Password:",
            "save_settings_as": "Save Settings As...",
            "load_settings_from": "Load Settings From...",
            "settings_exported": "Settings exported to {path}",
            "settings_imported": "Settings imported from {path}"
            ,
            "import_export_error": "Error importing/exporting settings: {e}"
        }
        self.translations["en"] = self._default_english_translations

    def get_string(self, key, **kwargs):
        return self.translations.get(self.current_language, self.translations["en"]).get(key, key).format(**kwargs)

loc = LocalizationManager()

# --- Secure File Shredding Utility ---
def secure_delete_file(filepath, passes=3):
    """
    Securely deletes a file by overwriting its content multiple times
    and then unlinking it.
    """
    if not os.path.exists(filepath):
        logger.warning(f"Attempted to shred non-existent file: {filepath}")
        return
    file_size = os.path.getsize(filepath)
    try:
        with open(filepath, 'r+b') as f:
            for i in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
            f.seek(0)
            f.write(b'\0' * file_size)
            f.flush()
            os.fsync(f.fileno())
        os.remove(filepath)
        logger.info(f"Securely shredded file: {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error during secure file shredding of {filepath}: {e}")
        return False

# --- UPDATED: Plugin Management System ---
class PluginManager:
    def __init__(self, settings):
        self.encryption_plugins = {}
        self.settings = settings
        self.load_plugins()
    def load_plugins(self):
        self.encryption_plugins.clear()
        
        logger.info(f"Scanning for plugins in: {PLUGINS_DIR}")

        # Add the plugins directory to Python's import path
        if PLUGINS_DIR not in sys.path:
            sys.path.append(PLUGINS_DIR)
            logger.info(f"Added '{PLUGINS_DIR}' to sys.path.")
        
        if not os.path.exists(PLUGINS_DIR):
            logger.warning(f"Plugins directory not found at {PLUGINS_DIR}. Skipping plugin loading.")
            return

        # New logging to help with debugging the file listing
        try:
            plugin_files = [f for f in os.listdir(PLUGINS_DIR) if f.endswith(".py") and not f.startswith("__")]
            logger.info(f"Found plugin files in directory: {plugin_files}")
        except FileNotFoundError:
            logger.error(f"Plugins directory does not exist at {PLUGINS_DIR}.")
            return
        except Exception as e:
            logger.error(f"An error occurred while listing plugin files: {e}")
            return
        
        for filename in plugin_files:
            try:
                module_name = filename[:-3]
                # Use importlib.import_module for more robust import in frozen environments
                module = importlib.import_module(module_name)
                
                if hasattr(module, 'EncryptorPlugin'):
                    plugin_instance = module.EncryptorPlugin()
                    self.encryption_plugins[plugin_instance.name] = plugin_instance
                    logger.info(f"Successfully loaded plugin: {plugin_instance.name} from {filename}")
                else:
                    logger.warning(f"Plugin file {filename} does not contain an 'EncryptorPlugin' class.")
            except ImportError as e:
                logger.error(f"Failed to import plugin '{filename}': {e}", exc_info=True)
            except Exception as e:
                logger.error(f"Failed to load plugin '{filename}': {e}", exc_info=True)
    def get_available_plugins(self):
        # Correctly initialize settings if not present
        if "enabled_plugins" not in self.settings:
            self.settings["enabled_plugins"] = {name: True for name in self.encryption_plugins}
        enabled_plugins = self.settings.get("enabled_plugins", {})
        return [name for name, is_enabled in enabled_plugins.items() if is_enabled and name in self.encryption_plugins]
    
    def get_all_plugins(self):
        return self.encryption_plugins

    def get_plugin_key_length(self, name):
        plugin = self.encryption_plugins.get(name)
        return getattr(plugin, 'key_length_bits', 256) # Default to 256 for safety

    def set_plugin_status(self, name, is_enabled):
        enabled_plugins = self.settings.get("enabled_plugins", {})
        enabled_plugins[name] = is_enabled
        self.settings["enabled_plugins"] = enabled_plugins

# --- NEW: Key Management System ---
class KeyManager:
    def __init__(self):
        self.keys = self._load_keys()
    def _load_keys(self):
        if os.path.exists(KEY_STORE_FILE):
            try:
                with open(KEY_STORE_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load key store: {e}")
        return []
    def _save_keys(self):
        try:
            with open(KEY_STORE_FILE, 'w') as f:
                json.dump(self.keys, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save key store: {e}")
    def add_key(self, name, type, path):
        original_name = name
        counter = 1
        while any(key['name'] == name for key in self.keys):
            name = f"{original_name}_{counter}"
            counter += 1
        self.keys.append({"name": name, "type": type, "path": path, "added_on": datetime.now().isoformat()})
        self._save_keys()
        return name
    def get_keys(self):
        return self.keys
    def delete_key(self, name):
        original_len = len(self.keys)
        self.keys = [key for key in self.keys if key['name'] != name]
        if len(self.keys) < original_len:
            self._save_keys()
            return True
        return False
    def get_key_by_name(self, name):
        return next((key for key in self.keys if key['name'] == name), None)

# --- NEW: Crypto Engine for core logic ---
class CryptoEngine(QObject):
    # Signals for communication with the main thread
    progress = pyqtSignal(int)
    file_progress = pyqtSignal(int, int, str)
    current_file_status = pyqtSignal(str)
    operation_finished = pyqtSignal(object)
    operation_error = pyqtSignal(str)

    def __init__(self, is_encrypt_mode, kwargs):
        super().__init__()
        self.is_encrypt_mode = is_encrypt_mode
        self.kwargs = kwargs
        self.is_cancelled = False

    def run(self):
        try:
            if self.is_encrypt_mode:
                result = self._perform_batch_encryption()
            else:
                result = self._perform_batch_decryption()
            if not self.is_cancelled:
                self.operation_finished.emit(result)
        except Exception as e:
            logger.error(f"Worker thread error: {e}", exc_info=True)
            if not self.is_cancelled:
                self.operation_error.emit(str(e))
        finally:
            self.thread().quit()

    def cancel(self):
        self.is_cancelled = True
        logger.info("Worker thread cancellation requested.")

    def _derive_key(self, password, salt):
        if not salt:
            raise ValueError("Salt is required for key derivation.")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def _load_key_from_file(self, key_file_path):
        try:
            with open(key_file_path, 'rb') as f:
                key_data = f.read()
            if key_file_path.lower().endswith('.key'):
                return b64decode(key_data)
            else:
                raise ValueError("Unsupported key file extension. Use .key")
        except Exception as e:
            logger.error(f"Error loading key from file {key_file_path}: {e}")
            raise ValueError(loc.get_string("key_load_error", e=str(e)))

    def _get_files_in_path(self, path):
        if os.path.isfile(path):
            return [path]
        elif os.path.isdir(path):
            file_list = []
            for root, _, files in os.walk(path):
                for file in files:
                    file_list.append(os.path.join(root, file))
            return file_list
        return []

    def _perform_batch_encryption(self):
        input_path = self.kwargs["input_path"]
        output_base_path = self.kwargs["output_path"]
        key_source = self.kwargs["key_source"]
        password_or_key_file = self.kwargs["password_or_key_file"]
        algo_name = self.kwargs["algo_name"]
        compression_algo = self.kwargs["compression_algo"]
        compression_level = self.kwargs["compression_level"]
        perform_checksum = self.kwargs["perform_checksum"]
        delete_original = self.kwargs["delete_original"]
        secure_shredding_passes = self.kwargs["secure_shredding_passes"]
        files_to_process = self._get_files_in_path(input_path)
        total_files = len(files_to_process)
        processed_count = 0
        successful_count = 0
        if total_files == 0:
            return loc.get_string("encryption_complete", count=0)
        encryption_key_material = None
        if key_source == "file":
            try:
                encryption_key_material = self._load_key_from_file(password_or_key_file)
            except ValueError as e:
                raise Exception(loc.get_string("key_load_error", e=str(e)))
        for i, file_path in enumerate(files_to_process):
            if self.is_cancelled:
                return loc.get_string("operation_cancelled")
            self.file_progress.emit(i + 1, total_files, file_path)
            self.current_file_status.emit(loc.get_string("file_processing_status", filename=os.path.basename(file_path)))
            try:
                relative_path_part = os.path.relpath(file_path, input_path)
                relative_dir = os.path.dirname(relative_path_part)
                output_dir = os.path.join(output_base_path, relative_dir)
                os.makedirs(output_dir, exist_ok=True)
                final_output_path = os.path.join(output_dir, os.path.basename(file_path) + ".enc")

                with open(file_path, 'rb') as f:
                    plaintext = f.read()
                original_checksum = None
                if perform_checksum:
                    original_checksum = hashlib.sha256(plaintext).hexdigest()
                    logger.info(f"Generated checksum for {os.path.basename(file_path)}: {original_checksum}")
                compressed_data = plaintext
                if compression_algo != loc.get_string("no_compression"):
                    temp_compressed_path = file_path + ".comp_temp"
                    if compress_file(file_path, temp_compressed_path, compression_algo, compression_level):
                        with open(temp_compressed_path, 'rb') as f_comp:
                            compressed_data = f_comp.read()
                        os.remove(temp_compressed_path)
                    else:
                        raise Exception("Compression failed.")

                salt = secrets.token_bytes(16)
                iv = secrets.token_bytes(12)
                
                if key_source == "password":
                    key = self._derive_key(password_or_key_file, salt)
                else: # key_source == "file"
                    key = encryption_key_material

                encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
                encrypted_data = encryptor.update(compressed_data) + encryptor.finalize()
                tag = encryptor.tag

                with open(final_output_path, 'wb') as f:
                    f.write(encrypted_data)

                meta = {
                    'algorithm': algo_name,
                    'salt': b64encode(salt).decode() if key_source == 'password' else None,
                    'iv': b64encode(iv).decode(),
                    'tag': b64encode(tag).decode(),
                    'compression': compression_algo if compression_algo != loc.get_string("no_compression") else None,
                    'original_checksum': original_checksum,
                    'key_source': key_source,
                    'key_path': password_or_key_file if key_source == 'file' else None
                }
                with open(final_output_path + '.meta', 'w') as f:
                    json.dump(meta, f, indent=4)

                if delete_original:
                    self.current_file_status.emit(loc.get_string("file_shredding"))
                    if secure_shredding_passes > 0:
                        secure_delete_file(file_path, secure_shredding_passes)
                    else:
                        os.remove(file_path)
                    self.current_file_status.emit(loc.get_string("shredding_complete"))
                successful_count += 1
                logger.info(f"Successfully encrypted: {os.path.basename(file_path)}")
            except Exception as e:
                logger.error(f"Failed to encrypt {os.path.basename(file_path)}: {e}")
                self.operation_error.emit(f"Failed to encrypt {os.path.basename(file_path)}: {e}")
            processed_count += 1
            self.progress.emit(int((processed_count / total_files) * 100))
        return loc.get_string("encryption_complete", count=successful_count)

    def _perform_batch_decryption(self):
        input_path = self.kwargs["input_path"]
        output_base_path = self.kwargs["output_path"]
        key_source = self.kwargs["key_source"]
        password_or_key_file = self.kwargs["password_or_key_file"]
        files_to_process = [f for f in self._get_files_in_path(input_path) if f.endswith('.enc')]
        total_files = len(files_to_process)
        processed_count = 0
        successful_count = 0
        if total_files == 0:
            return loc.get_string("decryption_complete", count=0)
        decryption_key_material = None
        if key_source == "file":
            try:
                decryption_key_material = self._load_key_from_file(password_or_key_file)
            except ValueError as e:
                raise Exception(loc.get_string("key_load_error", e=str(e)))
        for i, file_path in enumerate(files_to_process):
            if self.is_cancelled:
                return loc.get_string("operation_cancelled")
            self.file_progress.emit(i + 1, total_files, file_path)
            self.current_file_status.emit(loc.get_string("file_processing_status", filename=os.path.basename(file_path)))
            meta_path = file_path + '.meta'
            if not os.path.exists(meta_path):
                logger.warning(f"Metadata file not found for {os.path.basename(file_path)}. Skipping.")
                self.operation_error.emit(loc.get_string("metadata_not_found"))
                processed_count += 1
                continue
            try:
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                salt_b64 = meta.get('salt')
                iv_b64 = meta['iv']
                tag_b64 = meta['tag']
                compression_algo_meta = meta.get('compression')
                original_checksum_meta = meta.get('original_checksum')
                key_source_meta = meta.get('key_source', 'password')
                decryption_key = None
                if key_source_meta == "password":
                    if not password_or_key_file:
                        raise ValueError("Password not provided for decryption.")
                    if not salt_b64:
                        raise ValueError("Salt not found in metadata. Cannot derive key.")
                    salt = b64decode(salt_b64)
                    decryption_key = self._derive_key(password_or_key_file, salt)
                elif key_source_meta == "file":
                    if not decryption_key_material:
                        raise ValueError("Key file not provided or invalid for decryption.")
                    if isinstance(decryption_key_material, bytes):
                        decryption_key = decryption_key_material
                    else:
                        raise ValueError("Invalid key material type for decryption.")
                if decryption_key is None:
                    raise ValueError("Could not determine decryption key.")
                with open(file_path, 'rb') as f:
                    ciphertext = f.read()
                try:
                    iv = b64decode(iv_b64)
                    tag = b64decode(tag_b64)
                    decryptor = Cipher(algorithms.AES(decryption_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
                    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                except InvalidTag:
                    raise ValueError(loc.get_string("decrypt_failed_invalid_password"))
                decompressed_data = decrypted_data
                if compression_algo_meta:
                    temp_decompressed_path = file_path.replace(".enc", "") + ".decomp_temp"
                    with open(temp_decompressed_path, 'wb') as f_temp:
                        f_temp.write(decrypted_data)
                    if decompress_file(temp_decompressed_path, temp_decompressed_path + ".final", compression_algo_meta):
                        with open(temp_decompressed_path + ".final", 'rb') as f_decomp:
                            decompressed_data = f_decomp.read()
                        os.remove(temp_decompressed_path)
                        os.remove(temp_decompressed_path + ".final")
                    else:
                        os.remove(temp_decompressed_path)
                        raise Exception("Decompression failed.")
                relative_path_part = os.path.relpath(file_path, input_path)
                relative_dir = os.path.dirname(relative_path_part)
                output_dir = os.path.join(output_base_path, relative_dir)
                os.makedirs(output_dir, exist_ok=True)
                final_output_path = os.path.join(output_dir, os.path.basename(file_path).replace(".enc", ""))
                with open(final_output_path, 'wb') as f:
                    f.write(decompressed_data)
                if original_checksum_meta:
                    current_checksum = hashlib.sha256(decompressed_data).hexdigest()
                    if current_checksum == original_checksum_meta:
                        logger.info(loc.get_string("checksum_verified", filename=os.path.basename(file_path)))
                    else:
                        logger.warning(loc.get_string("checksum_mismatch", filename=os.path.basename(file_path)))
                        self.current_file_status.emit(loc.get_string("checksum_mismatch", filename=os.path.basename(file_path)))
                successful_count += 1
                logger.info(f"Successfully decrypted: {os.path.basename(file_path)}")
            except Exception as e:
                logger.error(f"Failed to decrypt {os.path.basename(file_path)}: {e}")
                self.operation_error.emit(f"Failed to decrypt {os.path.basename(file_path)}: {e}")
            processed_count += 1
            self.progress.emit(int((processed_count / total_files) * 100))
        return loc.get_string("decryption_complete", count=successful_count)


# --- Compression Utilities ---
def compress_file(input_filepath, output_filepath, algorithm="Gzip", level=-1):
    """Compresses a file using the specified algorithm."""
    try:
        if algorithm == "Gzip":
            with open(input_filepath, 'rb') as f_in:
                with gzip.open(output_filepath, 'wb', compresslevel=level if level != -1 else 9) as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif algorithm == "Bzip2":
            with open(input_filepath, 'rb') as f_in:
                with bz2.open(output_filepath, 'wb', compresslevel=level if level != -1 else 9) as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif algorithm == "LZMA":
            with open(input_filepath, 'rb') as f_in:
                with lzma.open(output_filepath, 'wb', preset=level if level != -1 else 6) as f_out:
                    shutil.copyfileobj(f_in, f_out)
        else:
            raise ValueError(f"Unsupported compression algorithm: {algorithm}")
        logger.info(f"Compressed {input_filepath} to {output_filepath} using {algorithm}")
        return True
    except Exception as e:
        logger.error(f"Error compressing file {input_filepath}: {e}")
        return False
def decompress_file(input_filepath, output_filepath, algorithm="Gzip"):
    """Decompresses a file using the specified algorithm."""
    try:
        if algorithm == "Gzip":
            with gzip.open(input_filepath, 'rb') as f_in:
                with open(output_filepath, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif algorithm == "Bzip2":
            with bz2.open(input_filepath, 'rb') as f_in:
                with open(output_filepath, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif algorithm == "LZMA":
            with lzma.open(input_filepath, 'rb') as f_in:
                with open(output_filepath, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        else:
            raise ValueError(f"Unsupported decompression algorithm: {algorithm}")
        logger.info(f"Decompressed {input_filepath} to {output_filepath} using {algorithm}")
        return True
    except Exception as e:
        logger.error(f"Error decompressing file {input_filepath}: {e}")
        return False

# --- Encrypt/Decrypt Tabs ---
class CryptoTab(QWidget):
    def __init__(self, plugin_manager, app_settings, main_window, is_encrypt_mode):
        super().__init__()
        self.plugin_manager, self.app_settings, self.main_window = plugin_manager, app_settings, main_window
        self.is_encrypt_mode = is_encrypt_mode
        self.worker = None
        self.thread = None
        self.layout = QGridLayout(self)
        # Add optimal content margins for perfect view
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(15)
        self.setLayout(self.layout)
        self.setup_ui()
        self.connect_signals()
        self.update_plugin_options()
        self.update_expert_mode_ui()

    def log(self, message, level="info"):
        self.main_window.log_signal.emit(message, level)
    def retranslate_ui(self):
        self.browse_input_file_button.setText(loc.get_string("select_file"))
        self.browse_input_folder_button.setText(loc.get_string("select_folder"))
        self.browse_output_button.setText(loc.get_string("browse"))
        self.key_input_type_label.setText(loc.get_string("password_input_type"))
        self.password_radio_button.setText(loc.get_string("use_password"))
        self.key_file_radio_button.setText(loc.get_string("use_key_file"))
        self.password_label.setText(loc.get_string("password"))
        self.key_file_label.setText(loc.get_string("key_file_path"))
        self.browse_key_file_button.setText(loc.get_string("browse"))
        self.file_status_label.setText(loc.get_string("waiting_for_op"))
        self.input_path_entry.setToolTip(loc.get_string("tooltip_input_file"))
        self.output_path_entry.setToolTip(loc.get_string("tooltip_output_folder"))
        self.algo_dropdown.setToolTip(loc.get_string("tooltip_algorithm"))
        self.password_entry.setToolTip(loc.get_string("tooltip_password"))
        
        if self.is_encrypt_mode:
            self.action_button.setText(loc.get_string("encrypt_files"))
            self.compression_algo_label.setText(loc.get_string("compression_algorithm"))
            self.compression_level_label.setText(loc.get_string("compression_level"))
            self.checksum_checkbox.setText(loc.get_string("file_integrity_check"))
            self.delete_original_checkbox.setText(loc.get_string("delete_original_after_encrypt"))
            self.secure_shredding_passes_label.setText(loc.get_string("secure_shredding_passes"))
            self.delete_original_checkbox.setToolTip(loc.get_string("tooltip_delete_original"))
            self.compression_level_spinbox.setToolTip("Compression level from 0-9. -1 for default.")
            self.secure_shredding_passes_spinbox.setToolTip("Number of passes to securely overwrite the file.")
        else:
            self.action_button.setText(loc.get_string("decrypt_files"))
            
    def update_expert_mode_ui(self):
        pass
    def update_plugin_options(self):
        pass

    def setup_ui(self):
        self.input_path_entry = DragDropLineEdit()
        self.output_path_entry = DragDropLineEdit()

        self.browse_input_file_button = QPushButton(loc.get_string("select_file"))
        self.browse_input_file_button.setIcon(QIcon(os.path.join(ASSETS_DIR, "file.png")))
        self.browse_input_folder_button = QPushButton(loc.get_string("select_folder"))
        self.browse_input_folder_button.setIcon(QIcon(os.path.join(ASSETS_DIR, "folder.png")))

        self.browse_output_button = QPushButton(loc.get_string("browse"))
        self.algo_dropdown = CustomComboBox()
        self.key_input_type_label = QLabel(loc.get_string("password_input_type"))
        self.password_radio_button = QRadioButton(loc.get_string("use_password"))
        self.key_file_radio_button = QRadioButton(loc.get_string("use_key_file"))
        self.password_radio_button.setChecked(True)
        self.key_input_group = QButtonGroup(self)
        self.key_input_group.addButton(self.password_radio_button)
        self.key_input_group.addButton(self.key_file_radio_button)
        self.key_input_group.buttonToggled.connect(
            lambda button: self.toggle_key_input_method(button == self.password_radio_button)
        )
        self.password_label = QLabel(loc.get_string("password"))
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_strength_label = QLabel()
        self.password_strength_label.setStyleSheet("color: grey;")

        self.key_file_label = QLabel(loc.get_string("key_file_path"))
        self.key_file_path_entry = DragDropLineEdit()
        self.key_file_path_entry.setReadOnly(True)
        self.browse_key_file_button = QPushButton(loc.get_string("browse"))
        self.browse_key_file_button.clicked.connect(self.browse_key_file)
        self.key_file_path_entry.fileDropped.connect(self.on_key_file_dropped)
        self.action_button = QPushButton()
        self.progress_bar = QProgressBar()
        self.batch_progress_label = QLabel("")
        self.file_status_label = QLabel(loc.get_string("waiting_for_op"))
        self.file_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.compression_algo_label = QLabel(loc.get_string("compression_algorithm"))
        self.compression_algo_dropdown = CustomComboBox()
        self.compression_algo_dropdown.addItems([loc.get_string("no_compression"), loc.get_string("gzip"), loc.get_string("bzip2"), loc.get_string("lzma")])
        self.compression_level_label = QLabel(loc.get_string("compression_level"))
        self.compression_level_spinbox = QSpinBox()
        self.compression_level_spinbox.setRange(-1, 9)
        self.compression_level_spinbox.setValue(-1)
        self.checksum_checkbox = QCheckBox(loc.get_string("file_integrity_check"))
        self.delete_original_checkbox = QCheckBox(loc.get_string("delete_original_after_encrypt"))
        self.secure_shredding_passes_label = QLabel(loc.get_string("secure_shredding_passes"))
        self.secure_shredding_passes_spinbox = QSpinBox()
        self.secure_shredding_passes_spinbox.setRange(0, 100)
        self.secure_shredding_passes_spinbox.setValue(0)

        self.layout.addWidget(QLabel(loc.get_string("input_file_folder")), 0, 0)
        self.layout.addWidget(self.input_path_entry, 0, 1, 1, 2)

        input_browse_layout = QHBoxLayout()
        input_browse_layout.addWidget(self.browse_input_file_button)
        input_browse_layout.addWidget(self.browse_input_folder_button)
        self.layout.addLayout(input_browse_layout, 0, 3)

        self.layout.addWidget(QLabel(loc.get_string("output_folder")), 1, 0)
        self.layout.addWidget(self.output_path_entry, 1, 1, 1, 2)
        self.layout.addWidget(self.browse_output_button, 1, 3)
        self.layout.addWidget(QLabel(loc.get_string("encryption_algorithm") if self.is_encrypt_mode else loc.get_string("decryption_algorithm")), 2, 0)
        self.layout.addWidget(self.algo_dropdown, 2, 1, 1, 3)
        key_input_method_layout = QHBoxLayout()
        key_input_method_layout.addWidget(self.key_input_type_label)
        key_input_method_layout.addWidget(self.password_radio_button)
        key_input_method_layout.addWidget(self.key_file_radio_button)
        key_input_method_layout.addStretch(1)
        self.layout.addLayout(key_input_method_layout, 3, 0, 1, 4)

        self.layout.addWidget(self.password_label, 4, 0)
        self.layout.addWidget(self.password_entry, 4, 1, 1, 3)
        self.layout.addWidget(self.password_strength_label, 5, 1, 1, 3)

        self.layout.addWidget(self.key_file_label, 6, 0)
        self.layout.addWidget(self.key_file_path_entry, 6, 1, 1, 2)
        self.layout.addWidget(self.browse_key_file_button, 6, 3)

        row_offset = 7
        if self.is_encrypt_mode:
            self.layout.addWidget(self.compression_algo_label, row_offset, 0)
            self.layout.addWidget(self.compression_algo_dropdown, row_offset, 1)
            self.layout.addWidget(self.compression_level_label, row_offset, 2)
            self.layout.addWidget(self.compression_level_spinbox, row_offset, 3)
            row_offset += 1
            self.layout.addWidget(self.checksum_checkbox, row_offset, 0, 1, 2)
            self.layout.addWidget(self.delete_original_checkbox, row_offset, 2, 1, 2)
            row_offset += 1
            self.layout.addWidget(self.secure_shredding_passes_label, row_offset, 0)
            self.layout.addWidget(self.secure_shredding_passes_spinbox, row_offset, 1)
            row_offset += 1

        self.layout.addWidget(self.action_button, row_offset, 0, 1, 4)
        row_offset += 1

        # --- NEW: Added batch progress label ---
        self.layout.addWidget(self.batch_progress_label, row_offset, 0, 1, 4)
        row_offset += 1
        self.layout.addWidget(self.progress_bar, row_offset, 0, 1, 4)
        row_offset += 1
        self.layout.addWidget(self.file_status_label, row_offset, 0, 1, 4)
        self.layout.setRowStretch(row_offset + 1, 1)
        self.toggle_key_input_method(self.password_radio_button.isChecked())
    def connect_signals(self):
        self.input_path_entry.fileDropped.connect(self.on_file_dropped)
        self.input_path_entry.folderDropped.connect(self.on_folder_dropped)
        self.browse_input_file_button.clicked.connect(self.browse_input_file)
        self.browse_input_folder_button.clicked.connect(self.browse_input_folder)
        self.browse_output_button.clicked.connect(self.browse_output)
        self.action_button.clicked.connect(self.start_operation)
        self.delete_original_checkbox.stateChanged.connect(self.toggle_shredding_options)
        self.toggle_shredding_options(self.delete_original_checkbox.checkState())
        if self.is_encrypt_mode:
            self.password_entry.textChanged.connect(self.update_password_strength_label)
    def update_password_strength_label(self, text):
        strength = self.get_password_strength(text)
        if strength == "weak":
            self.password_strength_label.setText(f"{loc.get_string('password_strength')}{loc.get_string('password_strength_weak')}")
            self.password_strength_label.setStyleSheet("color: red;")
        elif strength == "medium":
            self.password_strength_label.setText(f"{loc.get_string('password_strength')}{loc.get_string('password_strength_medium')}")
            self.password_strength_label.setStyleSheet("color: orange;")
        elif strength == "strong":
            self.password_strength_label.setText(f"{loc.get_string('password_strength')}{loc.get_string('password_strength_strong')}")
            self.password_strength_label.setStyleSheet("color: green;")
        else:
            self.password_strength_label.setText("")
    def get_password_strength(self, password):
        if not password:
            return "none"
        length_score = 0
        if len(password) >= 8:
            length_score = 1
        if len(password) >= 12:
            length_score = 2

        char_score = 0
        if any(c.islower() for c in password) and any(c.isupper() for c in password):
            char_score += 1
        if any(c.isdigit() for c in password):
            char_score += 1
        if any(not c.isalnum() for c in password):
            char_score += 1
        total_score = length_score + char_score
        if total_score >= 4:
            return "strong"
        if total_score >= 2:
            return "medium"
        return "weak"
    def toggle_key_input_method(self, use_password_checked):
        self.password_label.setVisible(use_password_checked)
        self.password_entry.setVisible(use_password_checked)
        self.password_strength_label.setVisible(use_password_checked and self.is_encrypt_mode)
        self.key_file_label.setVisible(not use_password_checked)
        self.key_file_path_entry.setVisible(not use_password_checked)
        self.browse_key_file_button.setVisible(not use_password_checked)
        self.key_file_path_entry.setEnabled(not use_password_checked)
        self.browse_key_file_button.setEnabled(not use_password_checked)
    def on_key_file_dropped(self, file_path):
        self.key_file_path_entry.setText(file_path)
    def browse_key_file(self):
        file_filter = "Symmetric Key Files (*.key);;All Files (*.*)"
        if path := QFileDialog.getOpenFileName(self, loc.get_string("select_key_file"), "", file_filter)[0]:
            self.key_file_path_entry.setText(path)
    def toggle_shredding_options(self, state):
        is_checked = (state == Qt.CheckState.Checked)
        self.secure_shredding_passes_label.setEnabled(is_checked)
        self.secure_shredding_passes_spinbox.setEnabled(is_checked)
    def on_file_dropped(self, file_path):
        self.input_path_entry.setText(file_path)
        self.main_window.show_status_message(loc.get_string("status_file_selected", path=os.path.basename(file_path)), 3000)
        self.try_load_metadata(file_path)
    def on_folder_dropped(self, folder_path):
        self.input_path_entry.setText(folder_path)
        self.main_window.show_status_message(loc.get_string("status_file_selected", path=os.path.basename(folder_path)), 3000)
    def try_load_metadata(self, file_path):
        if not self.is_encrypt_mode and file_path.endswith('.enc'):
            try:
                with open(file_path + '.meta', 'r') as f:
                    metadata = json.load(f)
                if (algo := metadata.get('algorithm')) in self.plugin_manager.get_available_plugins():
                    self.algo_dropdown.setCurrentText(algo)
                    self.main_window.show_status_message(loc.get_string("status_metadata_found", algo=algo), 5000)
                if metadata.get('key_source') == 'file' and metadata.get('key_path'):
                    self.key_file_radio_button.setChecked(True)
                    self.key_file_path_entry.setText(metadata['key_path'])
                else:
                    self.password_radio_button.setChecked(True)
            except FileNotFoundError:
                self.main_window.show_status_message(loc.get_string("metadata_not_found"), 5000)
            except Exception as e:
                self.main_window.show_status_message(loc.get_string("status_metadata_error", e=str(e)), 5000)
    def browse_input_file(self):
        last_dir = self.app_settings.get("last_input_dir", "")
        file_dialog = QFileDialog(self)
        file_dialog.setWindowTitle(loc.get_string("select_file"))
        file_dialog.setDirectory(last_dir)
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        if file_dialog.exec():
            selected_path = file_dialog.selectedFiles()[0]
            self.on_file_dropped(selected_path)
            self.app_settings["last_input_dir"] = os.path.dirname(selected_path)
            self.main_window.save_settings()
    def browse_input_folder(self):
        last_dir = self.app_settings.get("last_input_dir", "")
        folder_dialog = QFileDialog(self)
        folder_dialog.setWindowTitle(loc.get_string("select_folder"))
        folder_dialog.setDirectory(last_dir)
        folder_dialog.setFileMode(QFileDialog.FileMode.Directory)
        folder_dialog.setOption(QFileDialog.Option.ShowDirsOnly, True)
        folder_dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        if folder_dialog.exec():
            selected_path = folder_dialog.selectedFiles()[0]
            self.on_folder_dropped(selected_path)
            self.app_settings["last_input_dir"] = selected_path
            self.main_window.save_settings()
    def browse_output(self):
        if path := QFileDialog.getExistingDirectory(self, loc.get_string("select_output_folder")):
            self.output_path_entry.setText(path)
    def update_plugin_options(self):
        current_algo = self.algo_dropdown.currentText()
        self.algo_dropdown.clear()
        if available := self.plugin_manager.get_available_plugins():
            self.algo_dropdown.addItems(available)
            if current_algo in available:
                self.algo_dropdown.setCurrentText(current_algo)
            elif self.app_settings.get("default_encryption_algorithm") in available:
                self.algo_dropdown.setCurrentText(self.app_settings.get("default_encryption_algorithm"))
            else:
                self.algo_dropdown.setCurrentIndex(0)
    def start_operation(self):
        input_path = self.input_path_entry.text()
        output_path = self.output_path_entry.text()
        algo_name = self.algo_dropdown.currentText()
        compression_algo = self.compression_algo_dropdown.currentText() if self.is_encrypt_mode else loc.get_string("no_compression")
        compression_level = self.compression_level_spinbox.value() if self.is_encrypt_mode else -1
        perform_checksum = self.checksum_checkbox.isChecked() if self.is_encrypt_mode else False
        delete_original = self.delete_original_checkbox.isChecked() if self.is_encrypt_mode else False
        secure_shredding_passes = self.secure_shredding_passes_spinbox.value() if delete_original else 0
        key_source = "password" if self.password_radio_button.isChecked() else "file"
        password_or_key_file = self.password_entry.text() if key_source == "password" else self.key_file_path_entry.text()
        params = {
            "input_path": input_path,
            "output_path": output_path,
            "key_source": key_source,
            "password_or_key_file": password_or_key_file,
            "algo_name": algo_name,
            "compression_algo": compression_algo,
            "compression_level": compression_level,
            "perform_checksum": perform_checksum,
            "delete_original": delete_original,
            "secure_shredding_passes": secure_shredding_passes
        }
        if not all([input_path, output_path, algo_name]):
            QMessageBox.warning(self, loc.get_string("input_error"), loc.get_string("all_fields_filled"))
            return
        if key_source == "password" and not password_or_key_file:
            QMessageBox.warning(self, loc.get_string("input_error"), loc.get_string("password") + " " + loc.get_string("all_fields_filled").lower())
            return
        if key_source == "file" and not password_or_key_file:
            QMessageBox.warning(self, loc.get_string("input_error"), loc.get_string("key_file_path") + " " + loc.get_string("all_fields_filled").lower())
            return
        if key_source == "file" and not os.path.exists(password_or_key_file):
            QMessageBox.warning(self, loc.get_string("input_error"), loc.get_string("key_file_path") + ": " + password_or_key_file + " " + loc.get_string("metadata_not_found").lower())
            return
        self.action_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.file_status_label.setText(loc.get_string("waiting_for_op"))
        self.thread = QThread()
        self.worker = CryptoEngine(self.is_encrypt_mode, params)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.operation_finished.connect(self.on_operation_complete)
        self.worker.operation_error.connect(self.on_operation_error)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.file_progress.connect(self.update_file_progress_label)
        self.worker.current_file_status.connect(self.file_status_label.setText)
        self.thread.start()
    def update_file_progress_label(self, current_file_index, total_files, filename):
        self.batch_progress_label.setText(loc.get_string("batch_processing_progress",
                                                        current=current_file_index,
                                                        total=total_files,
                                                        percentage=(current_file_index / total_files) * 100))
        self.file_status_label.setText(loc.get_string("file_processing_status_batch",
                                                      current_file_index=current_file_index,
                                                      total_files=total_files,
                                                      filename=os.path.basename(filename)))
        overall_progress = int((current_file_index / total_files) * 100)
        self.progress_bar.setValue(overall_progress)
    def on_operation_complete(self, result_message):
        self.action_button.setEnabled(True)
        self.progress_bar.setValue(100)
        self.file_status_label.setText(loc.get_string("waiting_for_op"))
        self.main_window.show_status_message(str(result_message), 5000)
        QMessageBox.information(self, loc.get_string("success"), str(result_message))
        self.thread.wait()
    def on_operation_error(self, error_message):
        self.action_button.setEnabled(True)
        self.file_status_label.setText(loc.get_string("waiting_for_op"))
        self.main_window.show_status_message(f"Error: {error_message}", 8000)
        QMessageBox.critical(self, loc.get_string("error"), error_message)
        self.thread.wait()

class EncryptTab(CryptoTab):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, is_encrypt_mode=True)
        self.retranslate_ui()
    def retranslate_ui(self):
        super().retranslate_ui()
        self.action_button.setText(loc.get_string("encrypt_files"))
        self.input_path_entry.setToolTip(loc.get_string("tooltip_input_file"))
        self.output_path_entry.setToolTip(loc.get_string("tooltip_output_folder"))
        self.algo_dropdown.setToolTip(loc.get_string("tooltip_algorithm"))
        self.password_entry.setToolTip(loc.get_string("tooltip_password"))
        self.delete_original_checkbox.setToolTip(loc.get_string("tooltip_delete_original"))

class DecryptTab(CryptoTab):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, is_encrypt_mode=False)
        self.retranslate_ui()
    def retranslate_ui(self):
        super().retranslate_ui()
        self.action_button.setText(loc.get_string("decrypt_files"))
        self.input_path_entry.setToolTip(loc.get_string("tooltip_input_file"))
        self.output_path_entry.setToolTip(loc.get_string("tooltip_output_folder"))
        self.algo_dropdown.setToolTip(loc.get_string("tooltip_algorithm"))
        self.password_entry.setToolTip(loc.get_string("tooltip_password"))

class GenerateKeysTab(QWidget):
    def __init__(self, key_manager, plugin_manager, app_settings, main_window):
        super().__init__()
        self.key_manager = key_manager
        self.plugin_manager = plugin_manager
        self.app_settings = app_settings
        self.main_window = main_window
        self.symmetric_key_b64 = None
        self.layout = QGridLayout(self)
        # Add optimal content margins for perfect view
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(15)
        self.setLayout(self.layout)
        self.setup_ui()
        self.retranslate_ui()
        self.update_plugin_options()

    def setup_ui(self):
        self.algo_label = QLabel(loc.get_string("algorithm_key_generation"))
        self.algo_dropdown = CustomComboBox()
        self.layout.addWidget(self.algo_label, 0, 0)
        self.layout.addWidget(self.algo_dropdown, 0, 1, 1, 2)
        self.generate_button = QPushButton(loc.get_string("generate_keys"))
        self.layout.addWidget(self.generate_button, 1, 0, 1, 3)
        self.key_output_textbox = QTextEdit()
        self.key_output_textbox.setReadOnly(True)
        self.layout.addWidget(self.key_output_textbox, 2, 0, 1, 3)
        btn_layout = QHBoxLayout()
        self.copy_key_button = QPushButton(loc.get_string("copy_keys_clipboard"))
        self.save_symmetric_key_button = QPushButton(loc.get_string("save_symmetric_key"))
        btn_layout.addWidget(self.copy_key_button)
        btn_layout.addWidget(self.save_symmetric_key_button)
        self.layout.addLayout(btn_layout, 3, 0, 1, 3)
        self.layout.setRowStretch(4, 1)
        self.generate_button.clicked.connect(self.generate_keys)
        self.copy_key_button.clicked.connect(lambda: self.main_window.copy_to_clipboard(self.key_output_textbox.toPlainText()))
        self.save_symmetric_key_button.clicked.connect(lambda: self.save_key_to_file('symmetric'))

    def retranslate_ui(self):
        self.generate_button.setText(loc.get_string("generate_keys"))
        self.save_symmetric_key_button.setToolTip(loc.get_string("tooltip_save_key"))
        self.copy_key_button.setText(loc.get_string("copy_keys_clipboard"))
        self.algo_label.setText(loc.get_string("algorithm_key_generation"))

    def update_plugin_options(self):
        current_algo = self.algo_dropdown.currentText()
        self.algo_dropdown.clear()
        available_plugins = self.plugin_manager.get_available_plugins()
        if available_plugins:
            self.algo_dropdown.addItems(available_plugins)
            if current_algo in available_plugins:
                self.algo_dropdown.setCurrentText(current_algo)
            else:
                self.algo_dropdown.setCurrentIndex(0)
            self.generate_button.setEnabled(True)
            self.copy_key_button.setEnabled(True)
            self.save_symmetric_key_button.setEnabled(True)
        else:
            self.algo_dropdown.addItem(loc.get_string("no_symmetric_plugins_found"))
            self.generate_button.setEnabled(False)
            self.copy_key_button.setEnabled(False)
            self.save_symmetric_key_button.setEnabled(False)
    def generate_keys(self):
        algo_name = self.algo_dropdown.currentText()
        if not algo_name or algo_name == loc.get_string("no_symmetric_plugins_found"):
            QMessageBox.warning(self, loc.get_string("input_error"), loc.get_string("select_algorithm_warning"))
            return
        self.symmetric_key_b64 = None
        self.key_output_textbox.clear()
        try:
            key_length_bits = self.plugin_manager.get_plugin_key_length(algo_name)
            key_length_bytes = key_length_bits // 8
            key = secrets.token_bytes(key_length_bytes)
            self.symmetric_key_b64 = b64encode(key).decode()
            self.key_output_textbox.setText(f"--- {algo_name} KEY (Base64) ---\n{self.symmetric_key_b64}")
            QMessageBox.information(self, loc.get_string("key_generation"), loc.get_string("key_generation_success", algo_name=algo_name))
        except Exception as e:
            QMessageBox.critical(self, loc.get_string("key_generation_error_title"), str(e))
            logger.error(f"Key generation error: {e}")
    def save_key_to_file(self, key_type):
        if key_type == 'symmetric':
            content = self.symmetric_key_b64
            if not content:
                QMessageBox.warning(self, loc.get_string("no_key"), loc.get_string("no_key_to_save"))
                return
            path, _ = QFileDialog.getSaveFileName(self, loc.get_string("save_symmetric_key"), "symmetric_key.key", "Key Files (*.key);;Text Files (*.txt);;All Files (*.*)")
            if path:
                try:
                    with open(path, 'w') as f:
                        f.write(content)
                    self.key_manager.add_key(os.path.basename(path), "Symmetric", path)
                    self.main_window.key_management_tab.load_keys()
                    self.main_window.show_status_message(loc.get_string("key_saved_to", path=path), 5000)
                except Exception as e:
                    QMessageBox.critical(self, loc.get_string("file_save_error"), str(e))
                    logger.error(f"Error saving symmetric key to file: {e}")

class PluginsTab(QWidget):
    def __init__(self, plugin_manager, app_settings, main_window):
        super().__init__()
        self.plugin_manager, self.app_settings, self.main_window = plugin_manager, app_settings, main_window
        self.layout = QVBoxLayout(self)
        # Add optimal content margins for perfect view
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(15)
        self.setLayout(self.layout)
        self.setup_ui()
        self.retranslate_ui()
        self.load_plugin_list()
    def setup_ui(self):
        self.plugin_list_widget = QListWidget()
        self.reload_button = QPushButton()
        self.layout.addWidget(QLabel(loc.get_string("loaded_encryption_plugins")))
        self.layout.addWidget(self.plugin_list_widget)
        self.layout.addWidget(self.reload_button)
        self.plugin_list_widget.itemChanged.connect(self.on_plugin_status_changed)
        self.reload_button.clicked.connect(self.reload_plugins)
    def retranslate_ui(self):
        self.reload_button.setText(loc.get_string("reload_plugins"))
        self.plugin_list_widget.setToolTip(loc.get_string("plugins_enable_disable"))
    def load_plugin_list(self):
        self.plugin_list_widget.blockSignals(True)
        self.plugin_list_widget.clear()
        all_plugins = self.plugin_manager.get_all_plugins()
        enabled_plugins = self.app_settings.get("enabled_plugins", {})
        for name in all_plugins.keys():
            item = QListWidgetItem(name)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            if name not in enabled_plugins:
                enabled_plugins[name] = True
            item.setCheckState(Qt.CheckState.Checked if enabled_plugins.get(name, True) else Qt.CheckState.Unchecked)
            self.plugin_list_widget.addItem(item)
        self.plugin_manager.settings["enabled_plugins"] = enabled_plugins
        self.plugin_list_widget.blockSignals(False)
    def on_plugin_status_changed(self, item):
        self.plugin_manager.set_plugin_status(item.text(), item.checkState() == Qt.CheckState.Checked)
        self.main_window.update_all_tabs_plugin_options()
        self.main_window.save_settings()
    def reload_plugins(self):
        self.plugin_manager.load_plugins()
        self.load_plugin_list()
        self.main_window.update_all_tabs_plugin_options()
        self.main_window.show_status_message(loc.get_string("plugins_reloaded_success"), 3000)

class SettingsTab(QWidget):
    def __init__(self, plugin_manager, app_settings, main_window):
        super().__init__()
        self.plugin_manager, self.app_settings, self.main_window = plugin_manager, app_settings, main_window
        self.layout = QGridLayout(self)
        # Add optimal content margins for perfect view
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(15)
        self.setLayout(self.layout)
        self.setup_ui()
        self.load_settings_to_ui()
    def retranslate_ui(self):
        self.language_label.setText(loc.get_string("language_wip"))
        self.animation_speed_label.setText(loc.get_string("animation_speed"))
        self.default_output_folder_label.setText(loc.get_string("default_output_folder"))
        self.browse_default_output_button.setText(loc.get_string("browse"))
        self.default_encryption_algo_label.setText(loc.get_string("default_encryption_algorithm"))
        self.default_shred_passes_label.setText(loc.get_string("secure_shredding_passes"))
        self.confirm_on_exit_checkbox.setText(loc.get_string("confirm_on_exit"))
        self.log_settings_group_label.setText(loc.get_string("log_file_settings"))
        self.max_log_size_label.setText(loc.get_string("max_log_size_mb"))
        self.enable_log_rotation_checkbox.setText(loc.get_string("enable_log_rotation"))
        self.export_settings_button.setText(loc.get_string("export_settings"))
        self.import_settings_button.setText(loc.get_string("import_settings"))
    def setup_ui(self):
        self.language_label = QLabel(loc.get_string("language_wip"))
        self.language_dropdown = CustomComboBox()
        self.language_dropdown.addItem("English")
        self.language_dropdown.setEnabled(False)
        self.layout.addWidget(self.language_label, 0, 0)
        self.layout.addWidget(self.language_dropdown, 0, 1)
        self.animation_speed_label = QLabel(loc.get_string("animation_speed"))
        self.animation_speed_slider = QSlider(Qt.Orientation.Horizontal)

        self.animation_speed_slider.setRange(1, 10)
        self.animation_speed_slider.setValue(5)
        self.animation_speed_slider.setTickInterval(1)
        self.animation_speed_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.animation_speed_slider.valueChanged.connect(self.change_animation_speed)
        self.layout.addWidget(self.animation_speed_label, 1, 0)
        self.layout.addWidget(self.animation_speed_slider, 1, 1)
        self.default_output_folder_label = QLabel(loc.get_string("default_output_folder"))
        self.default_output_folder_entry = DragDropLineEdit()
        self.browse_default_output_button = QPushButton(loc.get_string("browse"))
        self.browse_default_output_button.clicked.connect(self.browse_default_output_folder)
        self.layout.addWidget(self.default_output_folder_label, 2, 0)
        self.layout.addWidget(self.default_output_folder_entry, 2, 1)
        self.layout.addWidget(self.browse_default_output_button, 2, 2)
        self.default_encryption_algo_label = QLabel(loc.get_string("default_encryption_algorithm"))
        self.default_encryption_algo_dropdown = CustomComboBox()
        self.default_encryption_algo_dropdown.currentTextChanged.connect(self.save_default_encryption_algo)
        self.layout.addWidget(self.default_encryption_algo_label, 3, 0)
        self.layout.addWidget(self.default_encryption_algo_dropdown, 3, 1, 1, 2)
        self.update_default_encryption_algo_options()
        self.default_shred_passes_label = QLabel(loc.get_string("secure_shredding_passes"))
        self.default_shred_passes_entry = QLineEdit("0")
        self.default_shred_passes_entry.textChanged.connect(self.save_shredding_setting)
        self.layout.addWidget(self.default_shred_passes_label, 4, 0)
        self.layout.addWidget(self.default_shred_passes_entry, 4, 1)
        self.confirm_on_exit_checkbox = QCheckBox(loc.get_string("confirm_on_exit"))
        self.confirm_on_exit_checkbox.stateChanged.connect(self.save_confirm_on_exit_setting)
        self.layout.addWidget(self.confirm_on_exit_checkbox, 5, 0, 1, 2)
        self.log_settings_group_label = QLabel(loc.get_string("log_file_settings"))
        self.log_settings_group_label.setObjectName("SectionLabel")
        self.layout.addWidget(self.log_settings_group_label, 6, 0, 1, 3)
        self.max_log_size_label = QLabel(loc.get_string("max_log_size_mb"))
        self.max_log_size_entry = QLineEdit("5")
        self.max_log_size_entry.textChanged.connect(self.save_log_settings)
        self.layout.addWidget(self.max_log_size_label, 7, 0)
        self.layout.addWidget(self.max_log_size_entry, 7, 1)
        self.enable_log_rotation_checkbox = QCheckBox(loc.get_string("enable_log_rotation"))
        self.enable_log_rotation_checkbox.stateChanged.connect(self.save_log_settings)
        self.layout.addWidget(self.enable_log_rotation_checkbox, 8, 0, 1, 2)

        # --- NEW: Export/Import Buttons ---
        export_import_layout = QHBoxLayout()
        self.export_settings_button = QPushButton(loc.get_string("export_settings"))
        self.import_settings_button = QPushButton(loc.get_string("import_settings"))
        self.export_settings_button.clicked.connect(self.export_settings)
        self.import_settings_button.clicked.connect(self.import_settings)
        export_import_layout.addWidget(self.export_settings_button)
        export_import_layout.addWidget(self.import_settings_button)
        self.layout.addLayout(export_import_layout, 9, 0, 1, 3)

        self.layout.setRowStretch(10, 1)

    def export_settings(self):
        file_path, _ = QFileDialog.getSaveFileName(self, loc.get_string("save_settings_as"), "sf_settings.json", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.app_settings, f, indent=4)
                QMessageBox.information(self, loc.get_string("success"), loc.get_string("settings_exported", path=file_path))
            except Exception as e:
                QMessageBox.critical(self, loc.get_string("error"), loc.get_string("import_export_error", e=str(e)))

    def import_settings(self):
        file_path, _ = QFileDialog.getOpenFileName(self, loc.get_string("load_settings_from"), "", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    new_settings = json.load(f)
                self.main_window.app_settings.update(new_settings)
                self.main_window.save_settings()
                self.load_settings_to_ui()
                self.main_window.update_all_tabs_plugin_options()
                QMessageBox.information(self, loc.get_string("success"), loc.get_string("settings_imported", path=file_path))
            except Exception as e:
                QMessageBox.critical(self, loc.get_string("error"), loc.get_string("import_export_error", e=str(e)))

    def change_font(self, font_name):
        self.app_settings["font"] = font_name
        self.main_window.apply_font(font_name)
        self.main_window.save_settings()
    def change_animation_speed(self, value):
        self.app_settings["animation_speed"] = value
        self.main_window.save_settings()
    def browse_default_output_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, loc.get_string("select_default_output_folder"))
        if folder_path:
            self.default_output_folder_entry.setText(folder_path)
            self.app_settings["default_output_folder"] = folder_path
            self.main_window.save_settings()
    def update_default_encryption_algo_options(self):
        current_algo = self.default_encryption_algo_dropdown.currentText()
        self.default_encryption_algo_dropdown.clear()
        available_plugins = self.plugin_manager.get_available_plugins()
        self.default_encryption_algo_dropdown.addItems([""] + available_plugins)
        if current_algo in available_plugins:
            self.default_encryption_algo_dropdown.setCurrentText(current_algo)
        elif self.app_settings.get("default_encryption_algorithm") in available_plugins:
            self.default_encryption_algo_dropdown.setCurrentText(self.app_settings.get("default_encryption_algorithm"))
        else:
            self.default_encryption_algo_dropdown.setCurrentIndex(0)
    def save_default_encryption_algo(self, algo_name):
        self.app_settings["default_encryption_algorithm"] = algo_name if algo_name else None
        self.main_window.save_settings()
    def save_shredding_setting(self):
        try:
            passes = int(self.default_shred_passes_entry.text())
            self.app_settings["default_shredding_passes"] = max(0, passes)
            self.main_window.save_settings()
        except ValueError:
            pass
    def save_confirm_on_exit_setting(self, state):
        self.app_settings["confirm_on_exit"] = (state == Qt.CheckState.Checked)
        self.main_window.save_settings()
    def save_log_settings(self):
        try:
            max_size_mb = int(self.max_log_size_entry.text())
            self.app_settings["max_log_size_mb"] = max(1, max_size_mb)
            self.app_settings["enable_log_rotation"] = self.enable_log_rotation_checkbox.isChecked()
            self.main_window.configure_logging()
            self.main_window.save_settings()
        except ValueError:
            pass
    def load_settings_to_ui(self):
        self.default_shred_passes_entry.setText(str(self.app_settings.get("default_shredding_passes", 0)))
        self.animation_speed_slider.setValue(self.app_settings.get("animation_speed", 5))
        self.max_log_size_entry.setText(str(self.app_settings.get("max_log_size_mb", 5)))
        self.enable_log_rotation_checkbox.setChecked(self.app_settings.get("enable_log_rotation", True))
        self.default_output_folder_entry.setText(self.app_settings.get("default_output_folder", ""))
        self.confirm_on_exit_checkbox.setChecked(self.app_settings.get("confirm_on_exit", False))
        self.update_default_encryption_algo_options()

# --- NEW: File Integrity and Password Generator Tab ---
class HashAndGenTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = QGridLayout(self)
        # Add optimal content margins for perfect view
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(15)
        self.setLayout(self.layout)
        self.setup_ui()
        self.retranslate_ui()

    def setup_ui(self):
        # --- File Integrity Section ---
        self.hash_title_label = QLabel(loc.get_string("file_integrity_title"))
        self.hash_title_label.setObjectName("TitleLabel")
        self.file_to_hash_label = QLabel(loc.get_string("file_to_hash"))
        self.file_to_hash_entry = DragDropLineEdit()
        self.browse_hash_file_button = QPushButton(loc.get_string("browse"))
        self.browse_hash_file_button.clicked.connect(self.browse_hash_file)
        self.calculate_hash_button = QPushButton(loc.get_string("calculate_hash"))
        self.calculate_hash_button.clicked.connect(self.calculate_hash)
        self.sha256_label = QLabel(loc.get_string("sha256_hash"))
        self.sha256_output = QLineEdit()
        self.sha256_output.setReadOnly(True)
        self.sha512_label = QLabel(loc.get_string("sha512_hash"))
        self.sha512_output = QLineEdit()
        self.sha512_output.setReadOnly(True)

        self.layout.addWidget(self.hash_title_label, 0, 0, 1, 3)
        self.layout.addWidget(self.file_to_hash_label, 1, 0)
        self.layout.addWidget(self.file_to_hash_entry, 1, 1)
        self.layout.addWidget(self.browse_hash_file_button, 1, 2)
        self.layout.addWidget(self.calculate_hash_button, 2, 0, 1, 3)
        self.layout.addWidget(self.sha256_label, 3, 0)
        self.layout.addWidget(self.sha256_output, 3, 1, 1, 2)
        self.layout.addWidget(self.sha512_label, 4, 0)
        self.layout.addWidget(self.sha512_output, 4, 1, 1, 2)

        # --- Secure Password Generator Section ---
        self.password_gen_title_label = QLabel(loc.get_string("secure_password_generator"))
        self.password_gen_title_label.setObjectName("SectionLabel")
        self.password_length_label = QLabel(loc.get_string("password_length"))
        self.password_length_spinbox = QSpinBox()
        self.password_length_spinbox.setRange(8, 64)
        self.password_length_spinbox.setValue(16)
        self.include_uppercase_checkbox = QCheckBox(loc.get_string("include_uppercase"))
        self.include_numbers_checkbox = QCheckBox(loc.get_string("include_numbers"))
        self.include_symbols_checkbox = QCheckBox(loc.get_string("include_symbols"))
        self.generate_password_button = QPushButton(loc.get_string("generate_password"))
        self.generate_password_button.clicked.connect(self.generate_password)
        self.generated_password_label = QLabel(loc.get_string("generated_password"))
        self.generated_password_output = QLineEdit()
        self.generated_password_output.setReadOnly(True)

        self.layout.addWidget(self.password_gen_title_label, 5, 0, 1, 3)
        self.layout.addWidget(self.password_length_label, 6, 0)
        self.layout.addWidget(self.password_length_spinbox, 6, 1, 1, 2)
        self.layout.addWidget(self.include_uppercase_checkbox, 7, 0, 1, 3)
        self.layout.addWidget(self.include_numbers_checkbox, 8, 0, 1, 3)
        self.layout.addWidget(self.include_symbols_checkbox, 9, 0, 1, 3)
        self.layout.addWidget(self.generate_password_button, 10, 0, 1, 3)
        self.layout.addWidget(self.generated_password_label, 11, 0)
        self.layout.addWidget(self.generated_password_output, 11, 1, 1, 2)

        self.layout.setRowStretch(12, 1)

    def retranslate_ui(self):
        self.hash_title_label.setText(loc.get_string("file_integrity_title"))
        self.file_to_hash_label.setText(loc.get_string("file_to_hash"))
        self.browse_hash_file_button.setText(loc.get_string("browse"))
        self.calculate_hash_button.setText(loc.get_string("calculate_hash"))
        self.sha256_label.setText(loc.get_string("sha256_hash"))
        self.sha512_label.setText(loc.get_string("sha512_hash"))
        self.password_gen_title_label.setText(loc.get_string("secure_password_generator"))
        self.password_length_label.setText(loc.get_string("password_length"))
        self.include_uppercase_checkbox.setText(loc.get_string("include_uppercase"))
        self.include_numbers_checkbox.setText(loc.get_string("include_numbers"))
        self.include_symbols_checkbox.setText(loc.get_string("include_symbols"))
        self.generate_password_button.setText(loc.get_string("generate_password"))
        self.generated_password_label.setText(loc.get_string("generated_password"))

    def browse_hash_file(self):
        if path := QFileDialog.getOpenFileName(self, loc.get_string("select_file"))[0]:
            self.file_to_hash_entry.setText(path)

    def calculate_hash(self):
        file_path = self.file_to_hash_entry.text()
        if not os.path.exists(file_path):
            QMessageBox.warning(self, loc.get_string("error"), "File not found.")
            return

        hasher_256 = hashlib.sha256()
        hasher_512 = hashlib.sha512()

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    hasher_256.update(chunk)
                    hasher_512.update(chunk)
            self.sha256_output.setText(hasher_256.hexdigest())
            self.sha512_output.setText(hasher_512.hexdigest())
            self.main_window.show_status_message(loc.get_string("success"), 3000)
        except Exception as e:
            self.main_window.show_status_message(f"Hashing failed: {e}", 5000)
            self.sha256_output.setText("Error")
            self.sha512_output.setText("Error")
            QMessageBox.critical(self, loc.get_string("error"), f"An error occurred during hashing: {e}")

    def generate_password(self):
        length = self.password_length_spinbox.value()
        chars = string.ascii_lowercase
        if self.include_uppercase_checkbox.isChecked():
            chars += string.ascii_uppercase
        if self.include_numbers_checkbox.isChecked():
            chars += string.digits
        if self.include_symbols_checkbox.isChecked():
            chars += string.punctuation

        if not chars:
            QMessageBox.warning(self, loc.get_string("warning"), "Please select at least one character type.")
            return

        password = ''.join(secrets.choice(chars) for _ in range(length))
        self.generated_password_output.setText(password)
        self.main_window.show_status_message(loc.get_string("success"), 3000)


class AboutTab(QWidget):
    def __init__(self, plugin_manager, app_settings, main_window):
        super().__init__()
        self.plugin_manager, self.app_settings, self.main_window = plugin_manager, app_settings, main_window
        self.github_button = None
        self.mail_button = None
        self.layout = QGridLayout(self)  # <-- Add this line
        # Add optimal content margins for perfect view
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(15)
        self.setLayout(self.layout)      # <-- Add this line
        self.setup_ui()
        self.retranslate_ui()
    def setup_ui(self):
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label = QLabel()
        logo_path = os.path.join(ASSETS_DIR, SF_LOGO_FILENAME)
        if os.path.exists(logo_path):
            pixmap = QPixmap(logo_path).scaledToHeight(128, Qt.TransformationMode.SmoothTransformation)
            self.logo_label.setPixmap(pixmap)
            self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label.setObjectName("AboutTabLogo")
        content_layout.addWidget(self.logo_label)
        self.app_name_label = QLabel(loc.get_string("app_name"))
        font = self.app_name_label.font()
        font.setPointSize(24)
        font.setBold(True)
        self.app_name_label.setFont(font)
        self.app_name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.app_name_label.setObjectName("AboutTabInfo")
        content_layout.addWidget(self.app_name_label)
        self.version_label = QLabel(f'{loc.get_string("version")}{APP_VERSION}')
        self.version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.version_label.setObjectName("AboutTabInfo")
        content_layout.addWidget(self.version_label)
        self.developer_label = QLabel(f'{loc.get_string("developed_by")}{DEVELOPER_NAME}')
        self.developer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.developer_label.setObjectName("AboutTabInfo")
        content_layout.addWidget(self.developer_label)
        content_layout.addSpacing(20)
        contact_layout = QHBoxLayout()
        contact_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        contact_layout.setSpacing(20)
        self.github_button = QPushButton()
        github_logo_path = os.path.join(ASSETS_DIR, GITHUB_LOGO_FILENAME)
        if os.path.exists(github_logo_path):
            github_pixmap = QPixmap(github_logo_path).scaledToHeight(32, Qt.TransformationMode.SmoothTransformation)
            self.github_button.setIcon(QIcon(github_pixmap))
        else:
            logger.warning(f"Github logo not found at {github_logo_path}. Using placeholder.")
        self.github_button.setObjectName("open_github_button")
        self.github_button.clicked.connect(lambda: webbrowser.open(GITHUB_URL))
        contact_layout.addWidget(self.github_button)
        self.mail_button = QPushButton()
        mail_path = os.path.join(ASSETS_DIR, "mail.png")
        if os.path.exists(mail_path):
            mail_pixmap = QPixmap(mail_path)
            self.mail_button.setIcon(QIcon(mail_pixmap))
        self.mail_button.setObjectName("contact_developer_button")
        self.mail_button.clicked.connect(lambda: webbrowser.open(f"mailto:{DEVELOPER_EMAIL}"))
        contact_layout.addWidget(self.mail_button)
        self.layout.setRowStretch(0, 1)
        self.layout.setColumnStretch(0, 1)
        self.layout.addWidget(content_widget, 1, 1)
        self.layout.setRowStretch(2, 1)
        self.layout.setColumnStretch(2, 1)
    def retranslate_ui(self):
        self.app_name_label.setText(loc.get_string("app_name"))
        self.version_label.setText(f'{loc.get_string("version")}{APP_VERSION}')
        self.developer_label.setText(f'{loc.get_string("developed_by")}{DEVELOPER_NAME}')
        if self.github_button:
            self.github_button.setText(loc.get_string("open_github"))
        if self.mail_button:
            self.mail_button.setText(loc.get_string("contact_developer"))


class LogViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.log_entries = []
        self.layout = QVBoxLayout(self)
        self.setLayout(self.layout)
        self.setup_ui()
    def setup_ui(self):
        control_layout = QHBoxLayout()
        self.filter_label = QLabel(loc.get_string("filter_by_level"))
        self.filter_dropdown = CustomComboBox()
        self.filter_dropdown.addItems([loc.get_string("all_levels"), loc.get_string("info"), loc.get_string("warning"), loc.get_string("error")])
        self.filter_dropdown.currentTextChanged.connect(self.apply_filter)
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText(loc.get_string("search_logs"))
        self.search_entry.textChanged.connect(self.apply_filter)
        self.export_button = QPushButton(loc.get_string("export_logs"))
        self.export_button.clicked.connect(self.export_logs)
        control_layout.addWidget(self.filter_label)
        control_layout.addWidget(self.filter_dropdown)
        control_layout.addWidget(self.search_entry)
        control_layout.addWidget(self.export_button)
        self.layout.addLayout(control_layout)
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(3)
        self.log_table.setHorizontalHeaderLabels([loc.get_string("Time"), loc.get_string("Level"), loc.get_string("Message")])
        self.log_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.log_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.log_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.log_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.log_table.customContextMenuRequested.connect(self.show_context_menu)
        self.layout.addWidget(self.log_table)
    def append_log(self, message, level):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_entries.append({"timestamp": timestamp, "level": level.upper(), "message": message})
        self.apply_filter()
    def apply_filter(self):
        self.log_table.setRowCount(0)
        filter_level = self.filter_dropdown.currentText().upper()
        search_text = self.search_entry.text().lower()
        for entry in self.log_entries:
            if (filter_level == loc.get_string("all_levels").upper() or entry["level"] == filter_level) and \
               (not search_text or search_text in entry["message"].lower() or search_text in entry["level"].lower()):
                row_position = self.log_table.rowCount()
                self.log_table.insertRow(row_position)
                self.log_table.setItem(row_position, 0, QTableWidgetItem(entry["timestamp"]))
                level_item = QTableWidgetItem(entry["level"])
                if entry["level"] == "ERROR":
                    level_item.setForeground(QBrush(QColor(THEME_ERROR_RED)))
                elif entry["level"] == "WARNING":
                    level_item.setForeground(QBrush(QColor(THEME_WARNING_ORANGE)))
                elif entry["level"] == "INFO":
                    level_item.setForeground(QBrush(QColor(THEME_SUCCESS_GREEN)))
                self.log_table.setItem(row_position, 1, level_item)
                self.log_table.setItem(row_position, 2, QTableWidgetItem(entry["message"]))
        self.log_table.scrollToBottom()
    def export_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, loc.get_string("export_logs"), "application_logs.txt", "Text Files (*.txt);;All Files (*.*)")
        if path:
            try:
                with open(path, 'w') as f:
                    for entry in self.log_entries:
                        f.write(f"[{entry['timestamp']}] [{entry['level']}] {entry['message']}\n")
                QMessageBox.information(self, loc.get_string("export_complete_title"), loc.get_string("log_exported_to", path=path))
            except Exception as e:
                QMessageBox.critical(self, loc.get_string("export_error_title"), loc.get_string("log_export_error", e=str(e)))
                logger.error(f"Error exporting logs: {e}")
    def show_context_menu(self, pos):
        pass

class KeyManagementTab(QWidget):
    def __init__(self, key_manager, plugin_manager, app_settings, main_window):
        super().__init__()
        self.key_manager, self.plugin_manager, self.app_settings, self.main_window = key_manager, plugin_manager, app_settings, main_window
        self.layout = QGridLayout(self)
        # Add optimal content margins for perfect view
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(15)
        self.setLayout(self.layout)
        self.setup_ui()
        self.retranslate_ui()
        self.load_keys()
    def setup_ui(self):
        self.key_table = QTableWidget()
        self.key_table.setColumnCount(4)
        self.key_table.setHorizontalHeaderLabels([loc.get_string("key_name"), loc.get_string("key_type"), loc.get_string("key_path"), loc.get_string("key_actions")])
        self.key_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.key_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.key_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.key_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.key_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.key_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.key_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.key_table.customContextMenuRequested.connect(self.show_context_menu)
        self.layout.addWidget(QLabel(loc.get_string("managed_keys")), 0, 0)
        self.layout.addWidget(self.key_table, 1, 0, 1, 1)
        self.layout.setRowStretch(2, 1)
    def retranslate_ui(self):
        self.key_table.setHorizontalHeaderLabels([loc.get_string("key_name"), loc.get_string("key_type"), loc.get_string("key_path"), loc.get_string("key_actions")])

    def load_keys(self):
        self.key_table.setRowCount(0)
        for row, key_data in enumerate(self.key_manager.get_keys()):
            self.key_table.insertRow(row)
            self.key_table.setItem(row, 0, QTableWidgetItem(key_data.get("name", "N/A")))
            self.key_table.setItem(row, 1, QTableWidgetItem(key_data.get("type", "N/A")))
            self.key_table.setItem(row, 2, QTableWidgetItem(key_data.get("path", "N/A")))
    def show_context_menu(self, pos):
        item = self.key_table.itemAt(pos)
        if item:
            row = item.row()
            key_name = self.key_table.item(row, 0).text()
            key_data = self.key_manager.get_key_by_name(key_name)
            if key_data:
                menu = QMenu(self)
                view_action = QAction(loc.get_string("view_key"), self)
                export_action = QAction(loc.get_string("export_key"), self)
                delete_action = QAction(loc.get_string("delete_key"), self)
                view_action.triggered.connect(lambda: self.view_key(key_data))
                export_action.triggered.connect(lambda: self.export_key(key_data))
                delete_action.triggered.connect(lambda: self.delete_key(key_data))
                menu.addAction(view_action)
                menu.addAction(export_action)
                menu.addAction(delete_action)
                menu.exec(self.key_table.viewport().mapToGlobal(pos))
    def view_key(self, key_data):
        key_path = key_data.get("path")
        if not key_path or not os.path.exists(key_path):
            QMessageBox.warning(self, loc.get_string("key_error_title"), loc.get_string("key_load_error", e="File not found."))
            return
        try:
            with open(key_path, 'r') as f:
                content = f.read()
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(loc.get_string("key_view_title", name=key_data.get("name", "N/A")))
            msg_box.setText(content)
            msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg_box.exec()
        except Exception as e:
            QMessageBox.critical(self, loc.get_string("key_error_title"), loc.get_string("key_load_error", e=str(e)))
            logger.error(f"Error viewing key {key_data.get('name')}: {e}")
    def export_key(self, key_data):
        key_path = key_data.get("path")
        if not key_path or not os.path.exists(key_path):
            QMessageBox.warning(self, loc.get_string("key_error_title"), loc.get_string("key_load_error", e="File not found."))
            return
        if key_data.get("type") == "Symmetric":
            file_filter = "Key Files (*.key);;Text Files (*.txt);;All Files (*.*)"
            default_extension = ".key"
        else:
            file_filter = "All Files (*.*)"
            default_extension = ""
        path, _ = QFileDialog.getSaveFileName(self, loc.get_string("export_key"), os.path.basename(key_path).replace(".pem", "").replace(".key", "") + default_extension, file_filter)
        if path:
            try:
                shutil.copy(key_path, path)
                self.main_window.show_status_message(loc.get_string("key_exported", name=key_data.get("name"), path=path), 5000)
            except Exception as e:
                QMessageBox.critical(self, loc.get_string("file_save_error"), str(e))
                logger.error(f"Error exporting key {key_data.get('name')}: {e}")
    def delete_key(self, key_data):
        reply = QMessageBox.question(self, loc.get_string("confirm_delete_key_title"),
                                     loc.get_string("confirm_delete_key", name=key_data.get("name")),
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            if self.key_manager.delete_key(key_data.get("name")):
                key_file_path = key_data.get("path")
                if key_file_path and os.path.exists(key_file_path):
                    try:
                        os.remove(key_file_path)
                    except Exception as e:
                        logger.error(f"Error deleting key file {key_file_path}: {e}")
                self.load_keys()
                self.main_window.show_status_message(loc.get_string("key_deleted", name=key_data.get("name")), 3000)
            else:
                QMessageBox.warning(self, loc.get_string("delete_failed_title"), loc.get_string("delete_failed_message", name=key_data.get("name")))

class SFManagerModernUI(QMainWindow):
    log_signal = pyqtSignal(str, str)
    def __init__(self):
        super().__init__()
        self.app_settings = self.load_settings()
        self.plugin_manager = PluginManager(self.app_settings)
        self.key_manager = KeyManager()
        self.setup_ui()
        self.retranslate_ui()
        self.apply_font(self.app_settings.get("font", "Segoe UI"))
        self.statusBar().showMessage(loc.get_string("loading_app"))
        self.show_status_message(loc.get_string("app_started", app_name=APP_NAME, app_version=APP_VERSION))
        self.configure_logging()

    def setup_ui(self):
        self.setWindowTitle(APP_NAME)
        
        # Simple window sizing for testing
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        
        self.setStyleSheet(MODERN_STYLESHEET)
        main_container = QWidget()
        main_container.setObjectName("MainContainer")
        main_layout = QHBoxLayout(main_container)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setCentralWidget(main_container)
        icon_path = os.path.join(ASSETS_DIR, ICON_FILENAME)
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            logger.warning(f"Application icon not found at {icon_path}.")

        self.sidebar_widget = QWidget()
        self.sidebar_widget.setObjectName("Sidebar")
        self.sidebar_widget.setFixedWidth(250)  # Increased from 200 for better proportions

        self.sidebar_layout = QVBoxLayout(self.sidebar_widget)
        self.sidebar_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.sidebar_layout.setContentsMargins(0, 20, 0, 0)

        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setObjectName("MainContentArea")

        self.encrypt_tab = EncryptTab(self.plugin_manager, self.app_settings, self)
        self.decrypt_tab = DecryptTab(self.plugin_manager, self.app_settings, self)
        self.gen_keys_tab = GenerateKeysTab(self.key_manager, self.plugin_manager, self.app_settings, self)
        self.key_management_tab = KeyManagementTab(self.key_manager, self.plugin_manager, self.app_settings, self)
        self.plugins_tab = PluginsTab(self.plugin_manager, self.app_settings, self)
        self.settings_tab = SettingsTab(self.plugin_manager, self.app_settings, self)
        
        # --- NEW: File Integrity & Password Generator Tab ---
        self.hash_and_gen_tab = HashAndGenTab(self)
        
        self.about_tab = AboutTab(self.plugin_manager, self.app_settings, self)
        self.log_viewer = LogViewer()

        self.stacked_widget.addWidget(self.encrypt_tab)
        self.stacked_widget.addWidget(self.decrypt_tab)
        self.stacked_widget.addWidget(self.gen_keys_tab)
        self.stacked_widget.addWidget(self.key_management_tab)
        self.stacked_widget.addWidget(self.hash_and_gen_tab)  # New tab added here
        self.stacked_widget.addWidget(self.plugins_tab)
        self.stacked_widget.addWidget(self.settings_tab)
        self.stacked_widget.addWidget(self.log_viewer)
        self.stacked_widget.addWidget(self.about_tab)

        self.nav_buttons = [
            self.create_nav_button(loc.get_string("encrypt_tab"), 0, "encrypt.png"),
            self.create_nav_button(loc.get_string("decrypt_tab"), 1, "decrypt.png"),
            self.create_nav_button(loc.get_string("generate_keys_tab"), 2, "fingerprint.png"),
            self.create_nav_button(loc.get_string("key_management_tab"), 3, "encrypt.png"),
            self.create_nav_button(loc.get_string("file_integrity_tab"), 4, "fingerprint.png"), # New nav button
            self.create_nav_button(loc.get_string("plugins_tab"), 5, "plugins.png"),
            self.create_nav_button(loc.get_string("settings_tab"), 6, "settings.png"),
            self.create_nav_button(loc.get_string("log_viewer"), 7, "log.png"),
            self.create_nav_button(loc.get_string("about_tab"), 8, "about.png"),
        ]

        # Removed the toggle button from the layout
        # self.sidebar_layout.addWidget(self.toggle_button, 0, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        for btn in self.nav_buttons:
            self.sidebar_layout.addWidget(btn)
        self.sidebar_layout.addStretch(1)

        main_layout.addWidget(self.sidebar_widget)
        main_layout.addWidget(self.stacked_widget, 1)

        self.nav_buttons[0].setChecked(True)
        self.stacked_widget.setCurrentIndex(0)  # Ensure first tab is displayed
        self.log_signal.connect(self.log_viewer.append_log)

    def optimize_window_size(self):
        """Optimize window size and position for perfect view across different screen resolutions"""
        screen = QGuiApplication.primaryScreen()
        if screen:
            screen_geometry = screen.availableGeometry()
            screen_width = screen_geometry.width()
            screen_height = screen_geometry.height()
            
            # Calculate optimal window size based on screen resolution
            if screen_width >= 1920 and screen_height >= 1080:  # 1080p or higher
                window_width = 1400
                window_height = 900
                min_width = 1200
                min_height = 800
            elif screen_width >= 1366 and screen_height >= 768:  # 720p-1080p range
                window_width = min(1200, int(screen_width * 0.8))
                window_height = min(800, int(screen_height * 0.8))
                min_width = 1000
                min_height = 700
            else:  # Smaller screens
                window_width = min(1000, int(screen_width * 0.9))
                window_height = min(700, int(screen_height * 0.9))
                min_width = 800
                min_height = 600
            
            # Set window size
            self.setMinimumSize(min_width, min_height)
            self.resize(window_width, window_height)
            
            # Center the window on screen
            window_geometry = self.frameGeometry()
            center_point = screen_geometry.center()
            window_geometry.moveCenter(center_point)
            self.move(window_geometry.topLeft())
        else:
            # Fallback if screen detection fails
            self.setMinimumSize(1200, 800)
            self.resize(1400, 900)

        # Create main layout after window optimization  
        main_container = QWidget()
        main_container.setObjectName("MainContainer")
        main_layout = QHBoxLayout(main_container)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setCentralWidget(main_container)

        self.sidebar_widget = QWidget()
        self.sidebar_widget.setObjectName("Sidebar")
        self.sidebar_widget.setFixedWidth(250)  # Increased from 200 for better proportions

        self.sidebar_layout = QVBoxLayout(self.sidebar_widget)
        self.sidebar_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.sidebar_layout.setContentsMargins(0, 20, 0, 0)

        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setObjectName("MainContentArea")

        self.encrypt_tab = EncryptTab(self.plugin_manager, self.app_settings, self)
        self.decrypt_tab = DecryptTab(self.plugin_manager, self.app_settings, self)
        self.gen_keys_tab = GenerateKeysTab(self.key_manager, self.plugin_manager, self.app_settings, self)
        self.key_management_tab = KeyManagementTab(self.key_manager, self.plugin_manager, self.app_settings, self)
        self.plugins_tab = PluginsTab(self.plugin_manager, self.app_settings, self)
        self.settings_tab = SettingsTab(self.plugin_manager, self.app_settings, self)
        
        # --- NEW: File Integrity & Password Generator Tab ---
        self.hash_and_gen_tab = HashAndGenTab(self)
        
        self.about_tab = AboutTab(self.plugin_manager, self.app_settings, self)
        self.log_viewer = LogViewer()

        self.stacked_widget.addWidget(self.encrypt_tab)
        self.stacked_widget.addWidget(self.decrypt_tab)
        self.stacked_widget.addWidget(self.gen_keys_tab)
        self.stacked_widget.addWidget(self.key_management_tab)
        self.stacked_widget.addWidget(self.hash_and_gen_tab) # New tab
        self.stacked_widget.addWidget(self.plugins_tab)
        self.stacked_widget.addWidget(self.settings_tab)
        self.stacked_widget.addWidget(self.log_viewer)
        self.stacked_widget.addWidget(self.about_tab)

        self.nav_buttons = [
            self.create_nav_button(loc.get_string("encrypt_tab"), 0, "upload.png"),
            self.create_nav_button(loc.get_string("decrypt_tab"), 1, "decrypt.png"),
            self.create_nav_button(loc.get_string("generate_keys_tab"), 2, "encrypt.png"),
            self.create_nav_button(loc.get_string("key_management_tab"), 3, "encrypt.png"),
            self.create_nav_button(loc.get_string("file_integrity_tab"), 4, "fingerprint.png"), # New nav button
            self.create_nav_button(loc.get_string("plugins_tab"), 5, "plugins.png"),
            self.create_nav_button(loc.get_string("settings_tab"), 6, "settings.png"),
            self.create_nav_button(loc.get_string("log_viewer"), 7, "log.png"),
            self.create_nav_button(loc.get_string("about_tab"), 8, "about.png"),
        ]

        # Removed the toggle button from the layout
        # self.sidebar_layout.addWidget(self.toggle_button, 0, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        for btn in self.nav_buttons:
            self.sidebar_layout.addWidget(btn)
        self.sidebar_layout.addStretch(1)

        main_layout.addWidget(self.sidebar_widget)
        main_layout.addWidget(self.stacked_widget, 1)

        self.nav_buttons[0].setChecked(True)
        self.stacked_widget.setCurrentIndex(0)  # Ensure first tab is displayed
        self.log_signal.connect(self.log_viewer.append_log)

    # The toggle_sidebar method and related properties were removed in a previous step,
    # as per the user's request to fix UI issues related to the expandable menu.

    def create_nav_button(self, text, index, icon_filename=""):
        btn = QPushButton(text)
        btn.setObjectName(f"NavButton")
        btn.setCheckable(True)
        btn.setAutoExclusive(True)
        btn.setProperty("fullText", text)
        btn.setFixedWidth(180) # Set a fixed width for the expanded state
        btn.setToolTip(text)
        btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(index))

        if icon_filename:
            icon_path = os.path.join(ASSETS_DIR, icon_filename)
            if os.path.exists(icon_path):
                pixmap = QPixmap(icon_path)
                btn.setIcon(QIcon(pixmap))
                btn.setIconSize(QSize(24, 24))

        return btn

    def retranslate_ui(self):
        self.setWindowTitle(loc.get_string("app_name"))

        self.encrypt_tab.retranslate_ui()
        self.decrypt_tab.retranslate_ui()
        self.gen_keys_tab.retranslate_ui()
        self.key_management_tab.retranslate_ui()
        self.plugins_tab.retranslate_ui()
        self.settings_tab.retranslate_ui()
        self.hash_and_gen_tab.retranslate_ui()
        self.about_tab.retranslate_ui()
        self.log_viewer.log_table.setHorizontalHeaderLabels([loc.get_string("Time"), loc.get_string("Level"), loc.get_string("Message")])
        for btn in self.nav_buttons:
            btn.setText(loc.get_string(f"{btn.property('fullText').replace(' ', '_').lower()}_tab"))

    def load_settings(self):
        settings = {
            "font": "Segoe UI",
            "animation_speed": 5,
            "default_output_folder": "",
            "default_encryption_algorithm": None,
            "default_shredding_passes": 0,
            "confirm_on_exit": False,
            "max_log_size_mb": 5,
            "enable_log_rotation": True,
            "enabled_plugins": {},
            "last_input_dir": ""
        }
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r') as f:
                    user_settings = json.load(f)
                    settings.update(user_settings)
            except Exception as e:
                logger.error(f"Failed to load settings file: {e}")
        return settings

    def save_settings(self):
        try:
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(self.app_settings, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")

    def apply_font(self, font_name):
        font = QFont(font_name)
        QApplication.setFont(font)
        self.setStyleSheet(MODERN_STYLESHEET)

    def copy_to_clipboard(self, text):
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(text)
        self.show_status_message(loc.get_string("copied_to_clipboard"), 3000)

    def show_status_message(self, message, timeout=0):
        self.statusBar().showMessage(message, timeout)

    def update_all_tabs_plugin_options(self):
        self.encrypt_tab.update_plugin_options()
        self.decrypt_tab.update_plugin_options()
        self.gen_keys_tab.update_plugin_options()
        self.settings_tab.update_default_encryption_algo_options()

    def configure_logging(self):
        for h in logger.handlers:
            if isinstance(h, RotatingFileHandler):
                logger.removeHandler(h)
        if self.app_settings.get("enable_log_rotation", True):
            max_bytes = self.app_settings.get("max_log_size_mb", 5) * 1024 * 1024
            file_handler = RotatingFileHandler(LOG_FILE, maxBytes=max_bytes, backupCount=5)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            logger.addHandler(file_handler)

    def closeEvent(self, event):
        if self.app_settings.get("confirm_on_exit", False):
            reply = QMessageBox.question(self, loc.get_string("confirm_exit_title"),
                                         loc.get_string("confirm_exit_message"),
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                         QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.show_status_message(loc.get_string("app_closed", app_name=APP_NAME))
                event.accept()
            else:
                event.ignore()
        else:
            self.show_status_message(loc.get_string("app_closed", app_name=APP_NAME))
            event.accept()


def main():
    app = QApplication(sys.argv)
    
    # --- Fix for PyInstaller folder creation ---
    # The application can only create directories when run as a script.
    # The PyInstaller command's --add-data flag handles this for the compiled executable.
    if not getattr(sys, 'frozen', False):
        os.makedirs(PLUGINS_DIR, exist_ok=True)
        os.makedirs(ASSETS_DIR, exist_ok=True)

    if not os.path.exists(os.path.join(ASSETS_DIR, SF_LOGO_FILENAME)):
        logger.warning(f"SF Manager logo not found at {os.path.join(ASSETS_DIR, SF_LOGO_FILENAME)}. Please add it to the assets folder.")
    if not os.path.exists(os.path.join(ASSETS_DIR, GITHUB_LOGO_FILENAME)):
        logger.warning(f"Github logo not found at {os.path.join(ASSETS_DIR, GITHUB_LOGO_FILENAME)}. Please add it to the assets folder.")
    
    try:
        main_win = SFManagerModernUI()
        print("Main window created successfully")  # Debug print
        main_win.show()  # Changed from showMaximized() to show() to use our optimized window sizing
        print("Window shown successfully")  # Debug print
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error during application startup: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
