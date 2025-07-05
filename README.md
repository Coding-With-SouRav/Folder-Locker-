### SecureLock Pro - Folder Locking Application

This Python application provides a secure way to hide and unhide folders using a master password. Here's a detailed breakdown of its features:

#### Core Features:
1. **Folder Protection**:
   - Hide folders from normal view
   - Password-protect access to hidden folders
   - Unhide folders with correct authentication

2. **Security Implementation**:
   - BCrypt password hashing for secure credential storage
   - Master password requirement for all operations
   - Minimum 4-character password enforcement
   - Password visibility toggle

3. **Cross-Platform Support**:
   - Windows: Uses file attributes (hidden + system)
   - Linux/macOS: Renames folders with leading dot (e.g., `.hidden_folder`)

4. **User Interface**:
   - Tabbed interface (Hide, Unhide, Settings)
   - Custom placeholder entry fields
   - Password visibility toggle buttons
   - Responsive treeview for history display
   - Custom dialog boxes for password entry

#### Key Components:

1. **File Management**:
   - Creates hidden data directory (`~/.FolderLock&Hide`)
   - Stores password hash in `password.txt`
   - Maintains operation history in `history.json`
   - Saves window geometry in `config.ini`

2. **Custom Widgets**:
   - `PlaceholderEntry`: Entry field with hint text
   - `PlaceholderEntryForMasterPasswordChange`: Enhanced version with style changes

3. **Main Functionality**:
   - **Hide Tab**:
     - Folder browser
     - Password entry with strength tips
     - Hiding operation
   
   - **Unhide Tab**:
     - History display with timestamps
     - Folder selection from history
     - Password-protected unhiding
   
   - **Settings Tab**:
     - Master password change
     - Application information
     - Developer contact details

4. **Security Features**:
   - Encrypted password storage
   - Session-based password verification
   - Secure password dialogs
   - History tracking with timestamps

#### Technical Highlights:
- Uses `ctypes` for Windows file attributes
- Implements BCrypt for password hashing
- JSON for history storage
- Tkinter for GUI with custom styling
- PIL for image handling
- ConfigParser for settings management

#### Usage Flow:
1. **First Run**: Sets up master password
2. **Hide Folder**:
   - Select folder
   - Enter master password
   - Folder becomes hidden
3. **Unhide Folder**:
   - Select from history
   - Enter password
   - Folder restored
4. **Password Change**:
   - Verify current password
   - Set new password

balance between user-friendly interface and robust security measures for protecting sensitive folders.

# Demo Images

![Screenshot 2025-07-05 094328](https://github.com/user-attachments/assets/13ac18d2-e819-46ec-8b7b-1a2713b984e5)
![Screenshot 2025-07-05 094405](https://github.com/user-attachments/assets/342c2fce-844b-488b-ba99-8b8e58ec2d8d)
![Screenshot 2025-07-05 094428](https://github.com/user-attachments/assets/243296fd-1b10-4252-a6b2-e3e50abebca4)
![Screenshot 2025-07-05 094508](https://github.com/user-attachments/assets/3f54c505-9956-485b-8548-e3e82a16fbf7)
![Screenshot 2025-07-05 094550](https://github.com/user-attachments/assets/aadf8f8b-b34c-498b-a83d-ebe4a44fbf2a)
![Screenshot 2025-07-05 094605](https://github.com/user-attachments/assets/4d53144f-9d6b-4939-b3e9-c306d7d52725)
![Screenshot 2025-07-05 094621](https://github.com/user-attachments/assets/04563cc9-bbf7-4cd2-8fc3-09988d99abd3)
![Screenshot 2025-07-05 094642](https://github.com/user-attachments/assets/9db430ff-5640-4887-a02d-5261e23fadb0)
![Screenshot 2025-07-05 094702](https://github.com/user-attachments/assets/4075748f-34fa-4e27-82df-297c0f75eccf)
![Screenshot 2025-07-05 094713](https://github.com/user-attachments/assets/4c432638-f41d-4d9b-9187-20f595300d80)
