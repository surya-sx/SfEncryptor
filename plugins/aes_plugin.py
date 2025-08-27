import os
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import zlib # For zlib compression
import gzip # For gzip compression
import hashlib # For integrity checks

class EncryptorPlugin:
    def __init__(self):
        self.name = "AES-256-CBC"
        self.key_length = 256 # 256 bits
        self.nonce_length = 128 # 128 bits (IV)
        self.cipher_mode = "CBC"
        self.padding_scheme = "PKCS7"
        self.compression_supported = True
        self.integrity_supported = True # Can be added externally (e.g., HMAC, but not built-in to AES-CBC itself)
        self.kdf_supported = True
        self.key_derivation_functions = ["PBKDF2HMAC"] # Only PBKDF2HMAC for now
        self.salt_length_bytes = 16 # Standard salt length for PBKDF2
        self.key_usage_options = ["Encryption", "Decryption"]

    def _derive_key(self, password, salt, iterations):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, # 256 bits
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
        salt = os.urandom(16) if password else b''
        derived_key = self._derive_key(password, salt, iterations) if password else key

        iv = os.urandom(16) # 128-bit IV for AES
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        try:
            with open(input_filepath, 'rb') as infile, open(output_filepath, 'wb') as outfile:
                # Write header: salt (16 bytes), IV (16 bytes), integrity hash length (1 byte), integrity hash (variable)
                # Compression and integrity info could also be in header for more robust design
                outfile.write(salt)
                outfile.write(iv)

                total_size = os.path.getsize(input_filepath)
                processed_bytes = 0
                chunk_size = 65536 # 64 KB

                buffer = b''
                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Apply compression if enabled
                    if compression != "None":
                        chunk = self._compress_data(chunk, compression)

                    padded_chunk = padder.update(chunk)
                    encrypted_chunk = encryptor.update(padded_chunk)
                    outfile.write(encrypted_chunk)
                    processed_bytes += len(chunk) # Track original chunk size for progress
                    if progress_callback:
                        progress_callback(processed_bytes, total_size)

                final_padded_chunk = padder.finalize()
                final_encrypted_chunk = encryptor.update(final_padded_chunk) + encryptor.finalize()
                outfile.write(final_encrypted_chunk)
                
                # Calculate and write integrity hash after encryption
                if integrity_check != "None":
                    # Re-read the encrypted file content (excluding salt/IV) to calculate hash
                    # This is simplified; in a real app, you'd calculate hash on the fly or on original data
                    outfile.flush() # Ensure all data is written to disk
                    with open(output_filepath, 'rb') as f_read:
                        f_read.seek(32) # Skip salt and IV
                        encrypted_content_for_hash = f_read.read()
                    
                    integrity_hash = self._calculate_integrity(encrypted_content_for_hash, integrity_check)
                    outfile.write(len(integrity_hash).to_bytes(1, 'big')) # Write hash length
                    outfile.write(integrity_hash) # Write hash

            logging.info(f"AES-256-CBC: Encrypted '{input_filepath}' to '{output_filepath}' with compression '{compression}' and integrity '{integrity_check}'")
        except Exception as e:
            logging.error(f"AES-256-CBC encryption failed for '{input_filepath}': {e}")
            raise

    def decrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None, iterations=100000, decompression="None", integrity_check="None"):
        try:
            with open(input_filepath, 'rb') as infile, open(output_filepath, 'wb') as outfile:
                salt = infile.read(16)
                iv = infile.read(16)

                derived_key = self._derive_key(password, salt, iterations) if password else key

                cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

                # Read integrity hash if present
                file_size = os.path.getsize(input_filepath)
                integrity_hash_len = 0
                stored_integrity_hash = b''

                if integrity_check != "None":
                    infile.seek(file_size - 1) # Go to last byte for hash length
                    integrity_hash_len = int.from_bytes(infile.read(1), 'big')
                    infile.seek(file_size - 1 - integrity_hash_len) # Go back to read hash
                    stored_integrity_hash = infile.read(integrity_hash_len)
                    
                    # Reset infile position to start of encrypted data
                    infile.seek(32) 
                    encrypted_content_for_hash = infile.read(file_size - 32 - integrity_hash_len - 1) # Exclude salt, IV, hash len, hash
                    infile.seek(32) # Reset for decryption read

                    calculated_integrity_hash = self._calculate_integrity(encrypted_content_for_hash, integrity_check)
                    if calculated_integrity_hash != stored_integrity_hash:
                        raise ValueError("Integrity check failed: Data may have been tampered with or key is incorrect.")
                    logging.info(f"Integrity check passed for '{input_filepath}'.")

                total_encrypted_data_size = file_size - 32 - (integrity_hash_len + 1 if integrity_check != "None" else 0)
                processed_bytes = 0
                chunk_size = 65536

                buffer = b''
                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    
                    decrypted_chunk = decryptor.update(chunk)
                    buffer += decrypted_chunk

                    while len(buffer) >= algorithms.AES.block_size:
                        block = buffer[:algorithms.AES.block_size]
                        try:
                            unpadded_block = unpadder.update(block)
                            
                            # Apply decompression if enabled
                            if decompression != "None":
                                unpadded_block = self._decompress_data(unpadded_block, decompression)

                            outfile.write(unpadded_block)
                            processed_bytes += len(unpadded_block)
                            buffer = buffer[algorithms.AES.block_size:]
                        except ValueError: # Not a full block yet or padding error
                            break
                    if progress_callback:
                        progress_callback(infile.tell() - 32, total_encrypted_data_size) # Approximate progress

                final_decrypted_chunk = decryptor.finalize()
                buffer += final_decrypted_chunk
                final_unpadded_chunk = unpadder.update(buffer) + unpadder.finalize()
                
                # Apply decompression if enabled
                if decompression != "None":
                    final_unpadded_chunk = self._decompress_data(final_unpadded_chunk, decompression)

                outfile.write(final_unpadded_chunk)
                processed_bytes += len(final_unpadded_chunk)
                if progress_callback:
                    progress_callback(total_encrypted_data_size, total_encrypted_data_size) # Ensure 100%

            logging.info(f"AES-256-CBC: Decrypted '{input_filepath}' to '{output_filepath}' with decompression '{decompression}' and integrity '{integrity_check}'")
        except Exception as e:
            logging.error(f"AES-256-CBC decryption failed for '{input_filepath}': {e}")
            raise

    def generate_key(self, length=256, kdf=None, salt_len=None, key_usage=None): # Accept new args
        if length != 256:
            logging.warning("AES-256-CBC plugin only supports 256-bit keys for direct use.")
        # If KDF is specified, this method would ideally return components needed for KDF, not a direct key
        # For simplicity, if a KDF is chosen, we'll indicate a password-based key.
        if kdf and kdf != "None":
            return f"Password-based key (KDF: {kdf}, Salt Length: {salt_len} bytes)"
        return os.urandom(32) # 32 bytes = 256 bits
