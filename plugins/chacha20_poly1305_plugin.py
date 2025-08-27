import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import zlib # For zlib compression
import gzip # For gzip compression
import hashlib # For integrity checks

class EncryptorPlugin:
    """
    ChaCha20-Poly1305 Encryption Plugin for Satan Encryptor Suite.
    This is an authenticated stream cipher.
    """
    def __init__(self):
        self.name = "ChaCha20-Poly1305"
        self.key_length = 256 # 256 bits for ChaCha20Poly1305
        self.nonce_length = 96 # 96 bits for ChaCha20Poly1305
        self.cipher_mode = "ChaCha20-Poly1305" # Authenticated Encryption with Associated Data
        self.padding_scheme = "AEAD" # No explicit padding needed for stream cipher with AEAD
        self.compression_supported = True
        self.integrity_supported = True # Built-in authentication tag, plus optional external hash
        self.kdf_supported = True
        self.key_derivation_functions = ["PBKDF2HMAC"] # Only PBKDF2HMAC for now
        self.salt_length_bytes = 16 # Standard salt length for PBKDF2
        self.key_usage_options = ["Encryption", "Decryption"]

    def _derive_key(self, password, salt, iterations):
        """Derives a 256-bit key from a password using PBKDF2HMAC."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length // 8, # Convert bits to bytes
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def _compress_data(self, data, compression_algo):
        if compression_algo == "gzip":
            return gzip.compress(data)
        elif compression_algo == "zlib":
            return zlib.compress(data)
        return data

    def _decompress_data(self, data, decompression_algo):
        if decompression_algo == "gzip":
            return gzip.decompress(data)
        elif decompression_algo == "zlib":
            return zlib.decompress(data)
        return data
    
    def _calculate_integrity(self, data, algo):
        if algo == "sha256":
            return hashlib.sha256(data).digest()
        elif algo == "sha512":
            return hashlib.sha512(data).digest()
        return b'' # No integrity hash

    def encrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None, iterations=100000, compression="None", integrity_check="None"):
        """
        Encrypts a file using ChaCha20-Poly1305.
        The output file will contain: salt (if password used) + nonce + compression_flag + integrity_hash_len + integrity_hash + ciphertext + tag.
        """
        salt = b''
        derived_key = key

        if password:
            salt = os.urandom(16) # Generate a unique salt for key derivation
            derived_key = self._derive_key(password, salt, iterations)
            if len(derived_key) != self.key_length // 8:
                raise ValueError(f"Derived key length mismatch: expected {self.key_length // 8} bytes, got {len(derived_key)}")
        elif key is None or len(key) != self.key_length // 8:
            raise ValueError(f"Direct key must be {self.key_length // 8} bytes for {self.name}.")

        nonce = os.urandom(self.nonce_length // 8) # Generate a unique nonce for each encryption
        chacha = ChaCha20Poly1305(derived_key)

        try:
            with open(input_filepath, 'rb') as infile, open(output_filepath, 'wb') as outfile:
                plaintext = infile.read()
                original_plaintext_size = len(plaintext)

                # Apply compression if enabled
                compression_flag = b'\x00' # None
                if compression == "gzip":
                    plaintext = self._compress_data(plaintext, "gzip")
                    compression_flag = b'\x01'
                elif compression == "zlib":
                    plaintext = self._compress_data(plaintext, "zlib")
                    compression_flag = b'\x02'
                
                # Calculate and store integrity hash of the (possibly compressed) plaintext
                integrity_hash = b''
                integrity_hash_len = b'\x00'
                if integrity_check != "None":
                    integrity_hash = self._calculate_integrity(plaintext, integrity_check)
                    integrity_hash_len = len(integrity_hash).to_bytes(1, 'big')

                # Write header: salt (if present), nonce, compression flag, integrity hash length, integrity hash
                outfile.write(salt)
                outfile.write(nonce)
                outfile.write(compression_flag)
                outfile.write(integrity_hash_len)
                outfile.write(integrity_hash)

                # Associated data (optional, authenticated but not encrypted)
                associated_data = b'' # For file encryption, this could be metadata, but we'll use b''

                # Encrypt and authenticate
                ciphertext_with_tag = chacha.encrypt(nonce, plaintext, associated_data)
                outfile.write(ciphertext_with_tag)

                if progress_callback:
                    progress_callback(original_plaintext_size, original_plaintext_size) # Indicate 100% completion

            logging.info(f"{self.name}: Encrypted '{input_filepath}' to '{output_filepath}' with compression '{compression}' and integrity '{integrity_check}'")
        except Exception as e:
            logging.error(f"{self.name} encryption failed for '{input_filepath}': {e}")
            raise

    def decrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None, iterations=100000, decompression="None", integrity_check="None"):
        """
        Decrypts a file using ChaCha20-Poly1305.
        Reads salt (if present), nonce, compression_flag, integrity_hash_len, integrity_hash, ciphertext, and tag from the input file.
        """
        try:
            with open(input_filepath, 'rb') as infile, open(output_filepath, 'wb') as outfile:
                file_size = os.path.getsize(input_filepath)
                
                # Read salt (if password used)
                salt = b''
                if password: # Assume salt is always 16 bytes if password is used
                    salt = infile.read(16)
                    if len(salt) != 16:
                        raise ValueError("Expected 16-byte salt but could not read enough bytes.")

                nonce = infile.read(self.nonce_length // 8)
                if len(nonce) != self.nonce_length // 8:
                    raise ValueError(f"Invalid nonce length read from file. Expected {self.nonce_length // 8} bytes.")

                # Initialize decompression_algo_read before reading compression_flag
                decompression_algo_read = "None" 
                
                compression_flag = infile.read(1)
                if len(compression_flag) != 1:
                    raise ValueError("Could not read compression flag from file.")
                
                if compression_flag == b'\x01':
                    decompression_algo_read = "gzip"
                elif compression_flag == b'\x02':
                    decompression_algo_read = "zlib"
                
                integrity_hash_len_byte = infile.read(1)
                if len(integrity_hash_len_byte) != 1:
                    raise ValueError("Could not read integrity hash length from file.")
                integrity_hash_len = int.from_bytes(integrity_hash_len_byte, 'big')

                integrity_hash = b''
                if integrity_hash_len > 0:
                    integrity_hash = infile.read(integrity_hash_len)
                    if len(integrity_hash) != integrity_hash_len:
                        raise ValueError("Could not read full integrity hash from file.")

                derived_key = key
                if password:
                    if not salt:
                        raise ValueError("Password provided but no salt found in file for key derivation.")
                    derived_key = self._derive_key(password, salt, iterations)
                elif key is None or len(key) != self.key_length // 8:
                    raise ValueError(f"Direct key must be {self.key_length // 8} bytes for {self.name}.")

                chacha = ChaCha20Poly1305(derived_key)

                # Read the remaining content (ciphertext + tag)
                ciphertext_with_tag = infile.read()

                # Associated data (must be the same as during encryption)
                associated_data = b''

                # Decrypt and authenticate
                plaintext_or_compressed = chacha.decrypt(nonce, ciphertext_with_tag, associated_data)

                # Verify integrity hash if it was present
                if integrity_hash_len > 0:
                    calculated_integrity_hash = self._calculate_integrity(plaintext_or_compressed, integrity_check)
                    if calculated_integrity_hash != integrity_hash:
                        raise ValueError("Integrity check failed: Data may have been tampered with or key is incorrect.")
                    logging.info(f"Integrity check passed for '{input_filepath}'.")

                # Apply decompression if enabled
                final_plaintext = plaintext_or_compressed
                if decompression != "None" and decompression_algo_read != "None":
                    if decompression != decompression_algo_read:
                        logging.warning(f"Requested decompression '{decompression}' but file was compressed with '{decompression_algo_read}'. Attempting with requested.")
                    final_plaintext = self._decompress_data(plaintext_or_compressed, decompression)
                elif decompression == "None" and decompression_algo_read != "None":
                     raise ValueError(f"File was compressed with '{decompression_algo_read}' but no decompression was selected. Please select '{decompression_algo_read}'.")
                elif decompression != "None" and decompression_algo_read == "None":
                     raise ValueError(f"Decompression '{decompression}' was selected but file was not compressed.")


                outfile.write(final_plaintext)

                if progress_callback:
                    progress_callback(file_size, file_size) # Indicate 100% completion

            logging.info(f"{self.name}: Decrypted '{input_filepath}' to '{output_filepath}' with decompression '{decompression}' and integrity '{integrity_check}'")
        except Exception as e:
            logging.error(f"{self.name} decryption failed for '{input_filepath}': {e}")
            raise # Re-raise the exception

    def generate_key(self, length=None, kdf=None, salt_len=None, key_usage=None):
        """Generates a 256-bit (32-byte) key for ChaCha20-Poly1305."""
        if kdf and kdf != "None":
            # For password-based keys, we return a descriptive string, as the actual key
            # is derived during encryption/decryption using the password, salt, and iterations.
            return f"Password-based key (KDF: {kdf}, Salt Length: {salt_len} bytes)"
        
        # For direct key generation, always generate a 256-bit key
        if length is not None and (length // 8) != self.key_length // 8:
            logging.warning(f"{self.name} key generation ignores length parameter {length}; always generates {self.key_length}-bit key.")
        return os.urandom(self.key_length // 8) # 32 bytes = 256 bits
