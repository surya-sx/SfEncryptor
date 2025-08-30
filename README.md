# SF Encryptor

_A modern, cross-platform file management and encryption suite built with PyQt6 and Cryptography._

---

## About

SF Encryptor is a powerful desktop application designed to provide robust file encryption and decryption in a user-friendly interface. Built with Python and leveraging the PyQt6 and Cryptography libraries, this suite offers strong security features for managing your sensitive data.

---

## Key Features

- **Modern UI:** A clean and intuitive graphical interface for an enhanced user experience.
- **Cross-Platform Support:** Works seamlessly on Windows, macOS, and Linux.
- **Robust Encryption:** Utilizes the industry-standard AES-256-GCM algorithm for secure file protection.
- **Drag & Drop Functionality:** Easily add files and folders for processing with simple drag-and-drop actions.
- **Secure Deletion:** Overwrites original files multiple times to prevent data recovery after encryption.
- **Metadata Integration:** Automatically saves encryption settings with your encrypted files for hassle-free decryption.
- **Key Management:** A dedicated tab for managing and generating cryptographic keys.
- **Extensible Plugin System:** The architecture allows for easy addition of new encryption algorithms via plugins.

---

## Installation

**Prerequisites**
- Python 3.7 or newer

_Additional installation instructions can be provided based on your platform and Python environment._

---

## Usage

1. **Launch the Application:** Run the main `SfEncryptor.py` script.
2. **Encrypt/Decrypt Files:** Use the intuitive UI to select files or folders, choose your encryption algorithm, and process them securely.
3. **Key Management:** Generate, import, export, and delete cryptographic keys via the Key Management tab.
4. **Plugin System:** Add new encryption algorithms as plugins in the `plugins/` directory.

---

## Security

- **Encryption Algorithm:** AES-256-GCM and support for other algorithms via plugins.
- **Secure Shredding:** Optionally overwrite files multiple times to prevent recovery.
- **Metadata & Key Files:** Encryption settings are saved for easier decryption; keys can be managed securely within the app.

_For security policy and reporting vulnerabilities, see [SECURITY.md](SECURITY.md)._

---

## Supported Platforms

- Windows
- macOS
- Linux

---

## Contributing

Contributions, feature requests, and bug reports are welcome! Please open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Contact

Developed by Surya B  
Email: myselsuryaaz@gmail.com  
GitHub: [https://github.com/Suryabx](https://github.com/Suryabx)

---

## What's New

- Modern UI overhaul with new themes and styles
- Drag & drop file support
- Automatic metadata file creation for encrypted files
- Enhanced key management with password protection
- Plugin management for encryption algorithms
- Command-line interface (CLI) support

---

## Acknowledgements

- [PyQt6](https://riverbankcomputing.com/software/pyqt/intro)
- [Cryptography](https://cryptography.io/en/latest/)
