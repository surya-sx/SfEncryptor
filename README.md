# SF-Encryptor 🔐

## Secure File Encryption & Management Tool

SF-Encryptor is a powerful, user-friendly file encryption application built with Python and PyQt6. It provides military-grade encryption for your sensitive files and folders with a modern, intuitive interface and comprehensive feature set.

![SF-Encryptor](assets/Sf_encryptor.png)

---

## 🌟 Key Features

### 🔒 **Advanced Encryption Support**
- **Multiple Algorithms**: AES-256-CBC, ChaCha20-Poly1305, and Fernet encryption
- **Plugin-Based Architecture**: Extensible system for adding new encryption methods  
- **Secure Key Generation**: Cryptographically secure key generation with multiple formats
- **Password-Based Encryption**: Strong password-based encryption with custom key derivation

### � **Modern User Interface**
- **Tabbed Interface**: Organized tabs for different functionalities
- **Responsive Design**: Adaptive layout with scroll support for better usability
- **Drag & Drop Support**: Easy file and folder selection
- **Real-Time Progress Tracking**: Visual progress bars for all operations
- **Status Messages**: Comprehensive feedback and status updates

### 🛠️ **Comprehensive Functionality**

#### **Encryption & Decryption**
- Encrypt/decrypt individual files or entire folders
- Batch processing with progress tracking
- Algorithm selection per operation
- Secure file deletion options
- Output path customization

#### **Key Management**
- Secure key generation (128, 256, 512 bits)
- Key import/export functionality
- Base64 encoded key output
- Key information display (algorithm, length, creation date)
- Clipboard integration for easy key sharing

#### **File Integrity**
- File hash verification (MD5, SHA-1, SHA-256, SHA-512)
- Batch hash calculation
- Hash comparison and verification
- Export hash reports

#### **Plugin System**
- Dynamic plugin loading and management
- Plugin information display
- Hot-reload functionality
- Plugin folder access

#### **Application Management**
- Comprehensive settings with scroll interface
- Real-time log viewing with filtering
- Log export functionality
- System information display
- Application statistics and monitoring

---

## 📸 Screenshots

### Main Interface
![Main Interface](docs/screenshots/main-interface.png)

### Encryption Tab
![Encryption Tab](docs/screenshots/encrypt-tab.png)

### Settings Panel
![Settings Panel](docs/screenshots/settings-tab.png)

---

## 🚀 Getting Started

### Prerequisites
```bash
Python 3.8 or higher
PyQt6
cryptography library
```

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/sf-development/sf-encryptor.git
   cd sf-encryptor
   ```

2. **Install Dependencies**
   ```bash
   pip install PyQt6 cryptography secrets hashlib
   ```

3. **Run the Application**
   ```bash
   python Sf-Encryptor.py
   ```

### Alternative: Use Pre-built Executable
Download the latest release from [Releases](https://github.com/sf-development/sf-encryptor/releases) page.

---

## 📋 Application Tabs

### 🔐 **Encrypt**
- Select files or folders for encryption
- Choose encryption algorithm (AES, ChaCha20-Poly1305, Fernet)
- Set password or import key file
- Configure output settings
- Monitor encryption progress

### 🔓 **Decrypt**
- Select encrypted files for decryption
- Auto-detect encryption algorithm
- Enter password or select key file
- Choose output location
- Track decryption progress with integrity verification

### 🔑 **Generate Keys**
- Generate cryptographically secure keys
- Multiple key lengths (128, 256, 512 bits)
- Algorithm-specific key generation
- Base64 encoded output
- Save to file or copy to clipboard

### 🗂️ **Key Management**
- Import keys from files
- View detailed key information
- Export keys securely
- Delete unused keys
- Key validation and verification

### ✅ **File Integrity**
- Calculate file hashes (MD5, SHA-1, SHA-256, SHA-512)
- Verify file integrity
- Batch hash calculation
- Compare hash values
- Export hash reports

### 🧩 **Plugins**
- View loaded encryption plugins
- Plugin information display
- Reload plugins without restart
- Access plugin folder
- Plugin status monitoring

### ⚙️ **Settings**
- Application preferences
- Theme and appearance settings
- Security configurations
- Language selection (framework ready)
- Import/export settings
- Auto-save options

### 📝 **Logs**
- Real-time application logs
- Log level filtering (DEBUG, INFO, WARNING, ERROR)
- Auto-refresh functionality
- Export logs to file
- Clear log display
- Open log folder

### ℹ️ **About**
- Application information and version
- Developer contact information
- System information display
- License information
- Credits and acknowledgments
- Links to GitHub and support

---

## 🔧 Technical Architecture

### **Modular Design**
```
sf-encryptor/
├── core/                 # Core application logic
├── ui/                   # User interface modules
│   ├── tabs/            # Individual tab implementations
│   └── main_window.py   # Main application window
├── utils/               # Utility functions and helpers
├── plugins/             # Encryption algorithm plugins
├── assets/              # Images, icons, and resources
└── Sf-Encryptor.py     # Main application entry point
```

### **Plugin System**
- **Standardized Interface**: All encryption plugins follow a common interface
- **Hot-Swappable**: Plugins can be loaded/reloaded without restarting
- **Extensible**: Easy to add new encryption algorithms
- **Isolated**: Each plugin operates independently

### **Security Features**
- **Secure Memory Handling**: Sensitive data cleared from memory after use
- **Key Derivation**: PBKDF2 with salt for password-based encryption
- **Secure Random Generation**: Cryptographically secure random number generation
- **Input Validation**: Comprehensive input validation and sanitization

---

## 🔌 Plugin Development

### Creating a New Encryption Plugin

1. **Create Plugin File**: `plugins/your_algorithm_plugin.py`

2. **Implement Required Interface**:
   ```python
   class YourAlgorithmPlugin:
       def get_name(self):
           return "Your Algorithm Name"
       
       def get_description(self):
           return "Description of your algorithm"
       
       def encrypt(self, data, key):
           # Your encryption implementation
           pass
       
       def decrypt(self, encrypted_data, key):
           # Your decryption implementation
           pass
       
       def generate_key(self, key_length=256):
           # Key generation implementation
           pass
   ```

3. **Test Your Plugin**: Use the plugin reload functionality to test

---

## 🛡️ Security Considerations

### **Encryption Standards**
- **AES-256**: Industry-standard symmetric encryption
- **ChaCha20-Poly1305**: Modern authenticated encryption
- **Fernet**: High-level cryptographic recipe for symmetric encryption

### **Best Practices**
- Use strong, unique passwords for each encryption operation
- Store keys securely and separately from encrypted data
- Regularly update the application for security patches
- Verify file integrity after encryption/decryption operations

### **Security Recommendations**
- Enable secure deletion of original files after encryption
- Use key files instead of passwords for maximum security
- Regular backups of encrypted data with tested restore procedures
- Monitor logs for any suspicious activity

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on:
- Code style guidelines
- Pull request process
- Issue reporting
- Feature requests

### **Development Setup**
```bash
git clone https://github.com/sf-development/sf-encryptor.git
cd sf-encryptor
pip install -r requirements.txt
python -m pytest tests/  # Run tests
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

- **Documentation**: [Wiki](https://github.com/sf-development/sf-encryptor/wiki)
- **Issues**: [GitHub Issues](https://github.com/sf-development/sf-encryptor/issues)
- **Email**: support@sf-encryptor.com
- **Discord**: [SF Development Community](https://discord.gg/sf-dev)

---

## 🙏 Acknowledgments

- **PyQt6**: Cross-platform GUI toolkit
- **Cryptography Library**: Comprehensive cryptographic library
- **Python Community**: For excellent libraries and documentation
- **Contributors**: All developers who have contributed to this project
- **Beta Testers**: Community members who helped test and improve the application

---

## 📈 Version History

### v1.3.0.0 (Latest)
- ✅ Complete modular architecture implementation
- ✅ All 9 main tabs fully functional
- ✅ Comprehensive settings with scroll interface
- ✅ Real-time logging and monitoring
- ✅ Plugin system with hot-reload
- ✅ Enhanced UI/UX with modern design

### v1.2.1.0
- ✅ Basic encryption/decryption functionality
- ✅ Initial plugin system
- ✅ Core settings implementation

### v1.0.0
- ✅ Initial release with basic features

---

**Made with ❤️ by the SF Development Team**

*Secure your files with confidence using SF-Encryptor!*

Developer Info: Features developer Surya B with a direct link to their GitHub profile.

Feedback/Contact: Guidance on how to provide feedback.

📜 Logging
Comprehensive Activity Log: Full logging of all significant application actions, including file operations, encryption/decryption events, errors, and warnings.

In-App Display: Logs are displayed directly within each tab's interface for real-time monitoring.

Optional Auto-Clear: Configure logs to be cleared automatically on application startup.

🚀 Installation
To get the Satan Encryptor Suite up and running, follow these steps:

Clone the Repository (or download the files):

git clone https://github.com/Suryabx/SatanEncryptorSuite.git
cd SatanEncryptorSuite

(Note: Replace SatanEncryptorSuite with your actual repository name if different, or just navigate to your project folder if you downloaded it.)

Create and Activate a Virtual Environment (Recommended):

# For Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```bash
# For macOS/Linux Bash
python3 -m venv .venv
source .venv/bin/activate

Install Dependencies:
With your virtual environment activated, install the required libraries:

pip install customtkinter cryptography Pillow

Ensure Plugin and Assets Structure:
Make sure you have the plugins and assets folders in the same directory as satan_encryptor_suite.py. The initial run of the app will create dummy plugins and the assets folder if they don't exist.

Place your icon.png inside the assets folder.

The example plugin files (fernet_plugin.py, aes_plugin.py, rsa_plugin.py) should be inside the plugins folder.

Run the Application:

python satan_encryptor_suite.py

💡 Usage
Encrypting Files/Folders
Navigate to the Encrypt tab.

Click "Browse" next to "Input File/Folder" to select the item(s) you wish to encrypt.

Click "Browse" next to "Output Folder" to choose where the encrypted files will be saved.

Select your desired "Encryption Algorithm" from the dropdown (e.g., Fernet, AES-256-CBC, RSA).

Enter the Key / Password for encryption. Observe the password strength meter.

Click the Encrypt File(s) button.

Decrypting Files/Folders
Go to the Decrypt tab.

Click "Browse" next to "Input Encrypted File/Folder" to select the .enc file(s) or folder containing them.

Click "Browse" next to "Output Folder" to choose where the decrypted files will be saved.

Select the "Decryption Algorithm" that was used for encryption.

Enter the correct Key / Password used during encryption.

Click the Decrypt File(s) button.

Generating Secure Keys/Passwords
Switch to the Generate Keys tab.

Select the "Algorithm for Key Generation" (e.g., Fernet for symmetric keys, RSA for asymmetric key pairs).

If generating an RSA key, specify the "Key Length (bits)".

Click Generate Key(s). The generated key(s) will appear in the textbox below.

Use the Copy Key(s) to Clipboard button to easily copy them.

🔌 Plugin System
The application is designed with a plugin-based architecture for its encryption algorithms. This allows for easy integration of new encryption methods.

How it Works:
The plugins directory is scanned on startup for Python files ending with _plugin.py.

Each such file is expected to define a class named EncryptorPlugin that adheres to a specific interface (methods like encrypt_file, decrypt_file, generate_key).

These plugins are then made available in the "Encryption Algorithm" dropdowns.

Example Plugins Included:
fernet_plugin.py

aes_plugin.py

rsa_plugin.py

📂 File Structure
SatanEncryptorSuite/
├── satan_encryptor_suite.py  # Main application entry point
├── settings.json             # Application settings (created on first run)
├── satan_encryptor_suite.log # Activity logs (created on first run)
├── terms.txt                 # Proprietary Terms and Conditions
├── plugins/                  # Directory for encryption algorithm plugins
│   ├── fernet_plugin.py
│   ├── aes_plugin.py
│   └── rsa_plugin.py
└── assets/                   # Directory for application assets like icons
    └── icon.png

⚠️ Security Notes
Important Security Information:

AES-256 & Fernet Plugins: These utilize the cryptography library, which implements industry-standard encryption algorithms. When used correctly with strong, unique keys/passwords, they provide robust security.

Password Security: Always use strong, unique passwords for each encryption operation. Avoid reusing passwords.

Key Storage: Generated keys (especially RSA private keys) should be stored securely and not shared. Losing a key means losing access to your encrypted data.

Backup: Always backup important data before encryption. While the application aims to be reliable, no software is infallible, and data loss can occur.

Demonstration vs. Production: While designed with security in mind, this application is for educational and personal use. For highly sensitive, production-level data, consult professional-grade, audited security solutions.

⚙️ Configuration
Application settings are automatically saved and loaded from settings.json. This file stores:

Theme preferences

Auto-clear log settings

File overwrite confirmation preference

You can export and import this configuration via the Settings tab.

📜 Logging
All significant activities within the application are logged with timestamps to satan_encryptor_suite.log. This includes:

File selection and operation events

Encryption and decryption attempts (success/failure)

Key generation events

Errors and warnings

Settings changes

Logs can be reviewed directly in the application's log textboxes.

💻 Development
Developer Information
Created by: Surya B

GitHub: https://github.com/Suryabx

Version: 1.0.0

Building Executable (Optional)
To create a standalone executable for Windows using PyInstaller:

Activate your virtual environment (as described in Installation Step 2).

Install PyInstaller:

pip install pyinstaller

Compile the application:

pyinstaller --noconfirm --onefile --windowed --icon=assets\icon.png --add-data "plugins;plugins" --add-data "assets;assets" "satan_encryptor_suite.py"

The executable will be found in the dist folder.

🚫 Limitations
While the Satan Encryptor Suite offers a modern UI with customtkinter, it still has some inherent limitations:

True Glassmorphism: customtkinter provides excellent theming, but full OS-level acrylic/blur effects (like Windows Acrylic) are not natively supported and would require platform-specific APIs.

Drag & Drop: Direct drag-and-drop file/folder support into the application window is not natively implemented in customtkinter and would require additional, more complex integrations. File browsing buttons are provided as an alternative.

Advanced Animations: While hover effects are present, complex UI animations are limited by the framework.

## ❓ Troubleshooting

### Common Issues & Solutions

#### 1. `ModuleNotFoundError: No module named 'customtkinter'` (or `cryptography`, `Pillow`)
**Cause:** Required Python packages are not installed in your current environment.

**Solution:**
1. **Activate your virtual environment:**
   - **Windows PowerShell:**
     ```powershell
     cd "C:\Users\Admin\Documents\satan 1v1"  # Adjust path as needed
     .\.venv\Scripts\Activate.ps1
     ```
   - **macOS/Linux Bash:**
     ```bash
     cd /path/to/SatanEncryptorSuite  # Adjust path as needed
     source .venv/bin/activate
     ```
2. **Install dependencies:**
   ```bash
   pip install customtkinter cryptography Pillow
   ```
3. **Still not working?**
   - Double-check your Python interpreter (should be from `.venv`).
   - Try `pip install --upgrade pip` before installing packages.
   - If using an IDE, ensure it uses the correct Python environment.

---

#### 2. `File: "dist\satan_encryptor_suite.exe" -> no files found.` (during NSIS compilation)
**Cause:** PyInstaller did not create the expected executable, or the filename/path is incorrect in your NSIS script.

**Solution:**
- Run PyInstaller first:
  ```powershell
  pyinstaller --noconfirm --onefile --windowed --icon=assets\icon.png --add-data "plugins;plugins" --add-data "assets;assets" "satan_encryptor_suite.py"
  ```
- Check the `dist` folder for the actual executable name.
- Update your `satan_installer.nsi` script to match the correct filename.

---

#### 3. `Error while loading icon from "icon.ico": invalid icon file` (NSIS)
**Cause:** The icon file is missing, corrupted, or not a valid `.ico` format.

**Solution:**
- Ensure `icon.ico` is in the same directory as `satan_installer.nsi`.
- Convert your icon to `.ico` using an [online converter](https://icoconvert.com/) or a trusted image editor.
- Test the icon by opening it in Windows Explorer to confirm it's valid.

---

#### 4. File Permission Errors
**Symptoms:** Access denied, cannot read/write files, or permission denied errors.

**Solution:**
- **Windows:** Right-click your terminal or IDE and select **Run as administrator**.
- **macOS/Linux:** Use `sudo` if working in protected directories.
- Check file/folder permissions and ensure you have read/write access.
- Avoid encrypting/decrypting files in system or program folders (e.g., `C:\Windows`, `/usr/bin`).
- If using network drives or cloud folders, ensure they are mounted and accessible.

---

#### 5. Decryption Fails
**Symptoms:** Decryption produces errors, corrupted files, or fails silently.

**Solution:**
- Double-check you are using the **exact same key or password** as used for encryption.
- Select the correct **encryption algorithm** (Fernet, AES-256-CBC, RSA, etc.).
- Verify the encrypted file is not corrupted, incomplete, or truncated.
- Check the application log for detailed error messages (see the **Logging** section above).
- Try decrypting a test file to isolate if the issue is with a specific file or all files.

---

#### 6. GUI Not Launching / Crashes on Startup
**Possible Causes:**
- Missing dependencies (e.g., `customtkinter`, `cryptography`, `Pillow`)
- Running with the wrong Python version (requires **Python 3.8+**)
- Corrupted or missing assets/plugins
- Incompatible OS or missing system libraries

**Solution:**
- Reinstall dependencies:
  ```bash
  pip install -r requirements.txt  # if available
  pip install customtkinter cryptography Pillow
  ```
- Ensure all required folders (`plugins`, `assets`) exist and contain necessary files.
- Check for error messages in the terminal or log file (`satan_encryptor_suite.log`).
- Try running the app from the terminal to see real-time errors.
- If using a packaged `.exe`, ensure all runtime files are present in the same directory.

---

#### 7. PyInstaller Executable Not Working
**Symptoms:** Double-clicking the `.exe` does nothing, or crashes immediately.

**Solution:**
- Run the `.exe` from a terminal (Command Prompt or PowerShell) to view error output.
- Ensure all runtime dependencies are included (see PyInstaller docs for `--add-data`).
- Try building without `--windowed` to see console errors:
  ```powershell
  pyinstaller --noconfirm --onefile --icon=assets\icon.png --add-data "plugins;plugins" --add-data "assets;assets" satan_encryptor_suite.py
  ```
- Check for missing DLLs or antivirus interference (some AVs may block new executables).
- If you see a `MSVCP140.dll` or similar error, install the [Microsoft Visual C++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170).

---

#### 8. General Debugging Tips
- Always activate your virtual environment before running or building the app.
- Use the application's built-in log viewer for error details.
- Update all packages regularly:
  ```bash
  pip install --upgrade customtkinter cryptography Pillow
  ```
- If you encounter a new error, search the error message online or check the [GitHub Issues](https://github.com/Suryabx/SatanEncryptorSuite/issues) page.
- For plugin issues, ensure each plugin file ends with `_plugin.py` and implements the required interface.
- For UI glitches, try switching between Dark/Light/System themes in the Settings tab.

---

> **Still need help?**
>
> - Review the application's log file: `satan_encryptor_suite.log` (in the app directory).
> - Double-check all file paths and permissions.
> - Open an issue or reach out to the developer via [GitHub](https://github.com/Suryabx) with detailed error messages and steps to reproduce the problem.

---