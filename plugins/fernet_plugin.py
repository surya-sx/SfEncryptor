from cryptography.fernet import Fernet
import os
import logging
from base64 import urlsafe_b64encode

class EncryptorPlugin:
    def __init__(self):
        self.name = "Fernet"
        self.key_length = 256 # Fernet uses 256-bit keys
        self.nonce_length = 128 # Implicitly part of Fernet token, IV size
        self.cipher_mode = "GCM" # Internally uses AES in GCM mode
        self.padding_scheme = "N/A" # GCM is authenticated encryption, no explicit padding needed
        self.compression_supported = False
        self.integrity_supported = True # Built-in authentication tag
        self.kdf_supported = False
        self.key_derivation_functions = []
        self.salt_length_bytes = "N/A"
        self.key_usage_options = ["Encryption", "Decryption"]


    def encrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None, iterations=None, compression=None, integrity_check=None):
        f = Fernet(key)
        try:
            with open(input_filepath, 'rb') as infile:
                original_data = infile.read()
            encrypted_data = f.encrypt(original_data)
            with open(output_filepath, 'wb') as outfile:
                outfile.write(encrypted_data)
            logging.info(f"Fernet: Encrypted '{input_filepath}' to '{output_filepath}'")
            if progress_callback:
                progress_callback(len(original_data), len(original_data))
        except Exception as e:
            logging.error(f"Fernet encryption failed for '{input_filepath}': {e}")
            raise

    def decrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None, iterations=None, decompression=None, integrity_check=None):
        f = Fernet(key)
        try:
            with open(input_filepath, 'rb') as infile:
                encrypted_data = infile.read()
            decrypted_data = f.decrypt(encrypted_data)
            with open(output_filepath, 'wb') as outfile:
                outfile.write(decrypted_data)
            logging.info(f"Fernet: Decrypted '{input_filepath}' to '{output_filepath}'")
            if progress_callback:
                progress_callback(len(encrypted_data), len(encrypted_data))
        except Exception as e:
            logging.error(f"Fernet decryption failed for '{input_filepath}': {e}")
            raise

    def generate_key(self, length=None, kdf=None, salt_len=None, key_usage=None): # Accept new args
        return Fernet.generate_key()
