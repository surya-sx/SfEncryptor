"""
Crypto Engine - Core cryptographic operations and batch processing.

This module provides the CryptoEngine class which handles:
- Batch encryption and decryption operations
- Key derivation and validation
- File processing with progress reporting
- Compression and integrity checking
"""

import os
import json
import hashlib
import logging
from base64 import b64encode, b64decode
from datetime import datetime

from PyQt6.QtCore import QObject, pyqtSignal, QThread

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

# Import compression manager if available
try:
    from compression_manager import compression_manager, compress_file, decompress_file
    COMPRESSION_AVAILABLE = True
except ImportError:
    COMPRESSION_AVAILABLE = False
    logging.warning("Compression system not available")

logger = logging.getLogger(__name__)

class CryptoEngine(QObject):
    """Core cryptographic engine with batch processing capabilities."""
    
    # Signals for communication with the main thread
    progress = pyqtSignal(int)  # Overall progress (0-100)
    file_progress = pyqtSignal(int, int, str)  # current_file, total_files, filename
    current_file_status = pyqtSignal(str)  # Status message
    operation_finished = pyqtSignal(object)  # Result object
    operation_error = pyqtSignal(str)  # Error message
    
    def __init__(self, is_encrypt_mode, **kwargs):
        """
        Initialize the crypto engine.
        
        Args:
            is_encrypt_mode (bool): True for encryption, False for decryption
            **kwargs: Operation parameters
        """
        super().__init__()
        self.is_encrypt_mode = is_encrypt_mode
        self.kwargs = kwargs
        self.is_cancelled = False
        
    def run(self):
        """Main execution method (called by QThread)."""
        try:
            if self.is_encrypt_mode:
                result = self._perform_batch_encryption()
            else:
                result = self._perform_batch_decryption()
            
            if not self.is_cancelled:
                self.operation_finished.emit(result)
                
        except Exception as e:
            logger.error(f"Crypto engine error: {e}", exc_info=True)
            if not self.is_cancelled:
                self.operation_error.emit(str(e))
    
    def cancel(self):
        """Cancel the current operation."""
        self.is_cancelled = True
        logger.info("Crypto operation cancellation requested")
    
    def _derive_key(self, password, salt):
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password (str): Password string
            salt (bytes): Salt bytes
            
        Returns:
            bytes: Derived key
        """
        if not salt:
            raise ValueError("Salt is required for key derivation")
        
        iterations = self.kwargs.get('kdf_iterations', 480000)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        
        return kdf.derive(password.encode('utf-8'))
    
    def _load_key_from_file(self, key_file_path):
        """
        Load encryption key from file.
        
        Args:
            key_file_path (str): Path to key file
            
        Returns:
            bytes: Key bytes
        """
        try:
            with open(key_file_path, 'rb') as f:
                key_data = f.read()
            
            # Handle different key file formats
            if key_file_path.lower().endswith('.key'):
                # Assume Base64 encoded key
                return b64decode(key_data)
            elif key_file_path.lower().endswith('.pem'):
                # Handle PEM format (would need more specific parsing)
                return key_data
            else:
                # Try to decode as Base64, fallback to raw bytes
                try:
                    return b64decode(key_data)
                except:
                    return key_data
                    
        except Exception as e:
            logger.error(f"Error loading key from file {key_file_path}: {e}")
            raise ValueError(f"Failed to load key: {str(e)}")
    
    def _get_files_in_path(self, path):
        """
        Get list of files from path (file or directory).
        
        Args:
            path (str): File or directory path
            
        Returns:
            list: List of file paths
        """
        if os.path.isfile(path):
            return [path]
        elif os.path.isdir(path):
            file_list = []
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_list.append(file_path)
            return file_list
        return []
    
    def _calculate_file_hash(self, file_path, algorithm='sha256'):
        """
        Calculate hash of a file.
        
        Args:
            file_path (str): Path to file
            algorithm (str): Hash algorithm ('sha256' or 'sha512')
            
        Returns:
            str: Hex digest of file hash
        """
        if algorithm == 'sha256':
            hash_obj = hashlib.sha256()
        elif algorithm == 'sha512':
            hash_obj = hashlib.sha512()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def _secure_delete_file(self, filepath, passes=3):
        """
        Securely delete a file by overwriting its content.
        
        Args:
            filepath (str): Path to file to delete
            passes (int): Number of overwrite passes
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not os.path.exists(filepath):
            return False
        
        try:
            file_size = os.path.getsize(filepath)
            
            with open(filepath, 'r+b') as f:
                for i in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                
                # Final pass with zeros
                f.seek(0)
                f.write(b'\0' * file_size)
                f.flush()
                os.fsync(f.fileno())
            
            os.remove(filepath)
            logger.info(f"Securely deleted file: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error during secure file deletion of {filepath}: {e}")
            return False
    
    def _perform_batch_encryption(self):
        """
        Perform batch encryption operation.
        
        Returns:
            str: Result message
        """
        input_path = self.kwargs["input_path"]
        output_base_path = self.kwargs["output_path"]
        key_source = self.kwargs["key_source"]
        password_or_key_file = self.kwargs["password_or_key_file"]
        algo_name = self.kwargs["algo_name"]
        plugin_manager = self.kwargs["plugin_manager"]
        
        # Optional parameters
        compression_algo = self.kwargs.get("compression_algo", "none")
        compression_level = self.kwargs.get("compression_level", 6)
        perform_checksum = self.kwargs.get("perform_checksum", False)
        delete_original = self.kwargs.get("delete_original", False)
        secure_shredding_passes = self.kwargs.get("secure_shredding_passes", 0)
        
        files_to_process = self._get_files_in_path(input_path)
        total_files = len(files_to_process)
        processed_count = 0
        successful_count = 0
        
        if total_files == 0:
            return "No files found to encrypt"
        
        # Get plugin
        plugin = plugin_manager.get_plugin(algo_name)
        if not plugin:
            raise ValueError(f"Plugin '{algo_name}' not found")
        
        # Prepare encryption key
        encryption_key = None
        if key_source == "password":
            # Key will be derived per file with unique salt
            pass
        elif key_source == "file":
            encryption_key = self._load_key_from_file(password_or_key_file)
        else:
            raise ValueError(f"Unsupported key source: {key_source}")
        
        # Process each file
        for i, file_path in enumerate(files_to_process):
            if self.is_cancelled:
                return "Operation cancelled by user"
            
            self.file_progress.emit(i + 1, total_files, file_path)
            self.current_file_status.emit(f"Processing: {os.path.basename(file_path)}")
            
            try:
                # Calculate output path preserving directory structure
                relative_path = os.path.relpath(file_path, input_path)
                if os.path.isdir(input_path):
                    relative_dir = os.path.dirname(relative_path)
                    output_dir = os.path.join(output_base_path, relative_dir)
                else:
                    output_dir = output_base_path
                
                os.makedirs(output_dir, exist_ok=True)
                output_file_path = os.path.join(output_dir, os.path.basename(file_path) + ".enc")
                
                # Read file content
                with open(file_path, 'rb') as f:
                    plaintext = f.read()
                
                # Calculate original checksum if requested
                original_checksum = None
                if perform_checksum:
                    original_checksum = self._calculate_file_hash(file_path, 'sha256')
                
                # Apply compression if specified
                if COMPRESSION_AVAILABLE and compression_algo != "none":
                    try:
                        compressed_data = compress_file(
                            plaintext, 
                            algorithm=compression_algo,
                            level=compression_level
                        )
                        if len(compressed_data) < len(plaintext):
                            plaintext = compressed_data
                            compression_used = compression_algo
                        else:
                            compression_used = "none"  # Compression not beneficial
                    except Exception as e:
                        logger.warning(f"Compression failed, using uncompressed data: {e}")
                        compression_used = "none"
                else:
                    compression_used = "none"
                
                # Generate salt if using password-based encryption
                if key_source == "password":
                    salt = os.urandom(32)  # 256-bit salt
                    actual_key = self._derive_key(password_or_key_file, salt)
                else:
                    salt = None
                    actual_key = encryption_key
                
                # Encrypt the data
                encrypted_data, nonce_iv = plugin.encrypt(plaintext, actual_key)
                
                # Create metadata
                metadata = {
                    "algorithm": algo_name,
                    "version": "1.3.0.0",
                    "timestamp": datetime.now().isoformat(),
                    "original_filename": os.path.basename(file_path),
                    "compression": compression_used
                }
                
                if salt is not None:
                    metadata["salt"] = b64encode(salt).decode('utf-8')
                if nonce_iv is not None:
                    metadata["nonce_iv"] = b64encode(nonce_iv).decode('utf-8')
                if original_checksum:
                    metadata["original_checksum"] = original_checksum
                
                # Save encrypted file
                with open(output_file_path, 'wb') as f:
                    f.write(encrypted_data)
                
                # Save metadata file
                metadata_file_path = output_file_path + ".meta"
                with open(metadata_file_path, 'w', encoding='utf-8') as f:
                    json.dump(metadata, f, indent=2)
                
                # Delete original file if requested
                if delete_original:
                    if secure_shredding_passes > 0:
                        self._secure_delete_file(file_path, secure_shredding_passes)
                    else:
                        os.remove(file_path)
                
                successful_count += 1
                
            except Exception as e:
                logger.error(f"Failed to encrypt {file_path}: {e}")
            
            processed_count += 1
            self.progress.emit(int((processed_count / total_files) * 100))
        
        return f"Encryption complete: {successful_count}/{total_files} files encrypted successfully"
    
    def _perform_batch_decryption(self):
        """
        Perform batch decryption operation.
        
        Returns:
            str: Result message
        """
        input_path = self.kwargs["input_path"]
        output_base_path = self.kwargs["output_path"]
        key_source = self.kwargs["key_source"]
        password_or_key_file = self.kwargs["password_or_key_file"]
        plugin_manager = self.kwargs["plugin_manager"]
        
        # Find encrypted files
        all_files = self._get_files_in_path(input_path)
        files_to_process = [f for f in all_files if f.endswith('.enc')]
        total_files = len(files_to_process)
        processed_count = 0
        successful_count = 0
        
        if total_files == 0:
            return "No encrypted files found"
        
        # Process each encrypted file
        for i, file_path in enumerate(files_to_process):
            if self.is_cancelled:
                return "Operation cancelled by user"
            
            self.file_progress.emit(i + 1, total_files, file_path)
            self.current_file_status.emit(f"Processing: {os.path.basename(file_path)}")
            
            try:
                # Load metadata
                metadata_file_path = file_path + ".meta"
                if os.path.exists(metadata_file_path):
                    with open(metadata_file_path, 'r', encoding='utf-8') as f:
                        metadata = json.load(f)
                else:
                    raise ValueError("Metadata file not found - manual configuration required")
                
                # Get plugin
                algo_name = metadata.get("algorithm")
                plugin = plugin_manager.get_plugin(algo_name)
                if not plugin:
                    raise ValueError(f"Plugin '{algo_name}' not found")
                
                # Prepare decryption key
                salt = None
                if "salt" in metadata:
                    salt = b64decode(metadata["salt"])
                
                if key_source == "password":
                    if not salt:
                        raise ValueError("Salt required for password-based decryption")
                    decryption_key = self._derive_key(password_or_key_file, salt)
                elif key_source == "file":
                    decryption_key = self._load_key_from_file(password_or_key_file)
                else:
                    raise ValueError(f"Unsupported key source: {key_source}")
                
                # Read encrypted data
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # Get nonce/IV if present
                nonce_iv = None
                if "nonce_iv" in metadata:
                    nonce_iv = b64decode(metadata["nonce_iv"])
                
                # Decrypt the data
                decrypted_data = plugin.decrypt(encrypted_data, decryption_key, nonce_iv)
                
                # Decompress if needed
                compression_used = metadata.get("compression", "none")
                if COMPRESSION_AVAILABLE and compression_used != "none":
                    try:
                        decrypted_data = decompress_file(decrypted_data, compression_used)
                    except Exception as e:
                        logger.error(f"Decompression failed: {e}")
                        # Continue with compressed data
                
                # Determine output path
                original_filename = metadata.get("original_filename", 
                                                os.path.basename(file_path)[:-4])  # Remove .enc
                
                relative_path = os.path.relpath(file_path, input_path)
                if os.path.isdir(input_path):
                    relative_dir = os.path.dirname(relative_path)
                    output_dir = os.path.join(output_base_path, relative_dir)
                else:
                    output_dir = output_base_path
                
                os.makedirs(output_dir, exist_ok=True)
                output_file_path = os.path.join(output_dir, original_filename)
                
                # Write decrypted file
                with open(output_file_path, 'wb') as f:
                    f.write(decrypted_data)
                
                # Verify checksum if available
                if "original_checksum" in metadata:
                    calculated_checksum = self._calculate_file_hash(output_file_path, 'sha256')
                    if calculated_checksum != metadata["original_checksum"]:
                        logger.warning(f"Checksum mismatch for {original_filename}")
                    else:
                        logger.info(f"Checksum verified for {original_filename}")
                
                successful_count += 1
                
            except Exception as e:
                logger.error(f"Failed to decrypt {file_path}: {e}")
            
            processed_count += 1
            self.progress.emit(int((processed_count / total_files) * 100))
        
        return f"Decryption complete: {successful_count}/{total_files} files decrypted successfully"


class CryptoWorker(QThread):
    """Worker thread for crypto operations."""
    
    def __init__(self, crypto_engine):
        """
        Initialize the crypto worker.
        
        Args:
            crypto_engine (CryptoEngine): Crypto engine instance
        """
        super().__init__()
        self.crypto_engine = crypto_engine
        
        # Connect signals
        self.crypto_engine.moveToThread(self)
    
    def run(self):
        """Run the crypto operation."""
        self.crypto_engine.run()
    
    def cancel(self):
        """Cancel the crypto operation."""
        self.crypto_engine.cancel()
