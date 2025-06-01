import json
from cryptography.fernet import Fernet
import os
import hashlib
import zipfile
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
from tkinter import filedialog
import shutil

# إعداد السجل لتتبع الأحداث
logging.basicConfig(filename='file_encryptor.log', level=logging.INFO)

class Encryptor:
    def key_create(self):
        """Generate a new encryption key."""
        return Fernet.generate_key()

    def key_write(self, key, key_name):
        """Save the encryption key to a file."""
        with open(key_name, 'wb') as mykey:
            mykey.write(key)
        log_event(f"Key '{key_name}' saved successfully.")

    def key_load(self, key_name):
        """Load an encryption key from a file."""
        with open(key_name, 'rb') as mykey:
            return mykey.read()

    def file_encrypt(self, key, original_file, encrypted_file):
        """Encrypt a file using the provided key."""
        f = Fernet(key)
        with open(original_file, 'rb') as file:
            original = file.read()

        encrypted = f.encrypt(original)

        with open(encrypted_file, 'wb') as file:
            file.write(encrypted)
        log_event(f"File '{original_file}' encrypted and saved as '{encrypted_file}'.")

    def file_decrypt(self, key, encrypted_file, decrypted_file):
        """Decrypt a file using the provided key."""
        f = Fernet(key)
        with open(encrypted_file, 'rb') as file:
            encrypted = file.read()

        decrypted = f.decrypt(encrypted)

        with open(decrypted_file, 'wb') as file:
            file.write(decrypted)
        log_event(f"File '{encrypted_file}' decrypted and saved as '{decrypted_file}'.")

    def create_backup(self, key_file, backup_code):
        """Create a backup containing the key and settings.json, secured by a backup code."""
        # Hash the backup code
        hashed_code = hashlib.sha256(backup_code.encode()).hexdigest()

        # Save the hashed code to a temporary file
        with open("backup_code.hash", "w") as f:
            f.write(hashed_code)

        # Create a ZIP archive with the key and settings file
        with zipfile.ZipFile("Encryption-Code-Backup.zip", "w") as backup_zip:
            backup_zip.write(key_file)
            if os.path.exists("settings.json"):
                backup_zip.write("settings.json")
            backup_zip.write("backup_code.hash")

        os.remove("backup_code.hash")  # Clean up the temporary hash file
        log_event("Backup created successfully as 'Encryption-Code-Backup.zip'.")

    def verify_backup_code(self, backup_code, backup_file="Encryption-Code-Backup.zip"):
        """Verify the provided backup code with the hashed code in the backup file."""
        with zipfile.ZipFile(backup_file, "r") as backup_zip:
            with backup_zip.open("backup_code.hash") as f:
                stored_hashed_code = f.read().decode()

        hashed_code = hashlib.sha256(backup_code.encode()).hexdigest()
        return hashed_code == stored_hashed_code

    def restore_backup(self, backup_file="Encryption-Code-Backup.zip"):
        """Restore the key and settings from the backup file."""
        with zipfile.ZipFile(backup_file, "r") as backup_zip:
            backup_zip.extractall()  # Extract all contents

        log_event("Backup files extracted successfully.")

        # Load the key from the backup
        key_file = [name for name in backup_zip.namelist() if name.endswith('.key')][0]  # Assumes the key file is a .key file
        settings_file = [name for name in backup_zip.namelist() if name == 'settings.json'][0]  # settings.json if it exists

        try:
            # Load the key
            key = self.key_load(key_file)
            log_event(f"Key restored successfully from '{key_file}'.")
            
            # Optionally, load settings
            if os.path.exists(settings_file):
                settings = load_settings(settings_file)
                log_event(f"Settings restored from '{settings_file}'.")
            return key, settings
        except Exception as e:
            log_event(f"Error restoring backup: {e}")
            return None, None

    def encrypt_folder(self, key, folder_path, encrypted_folder_path):
        """Encrypt all files in a folder."""
        if not os.path.exists(encrypted_folder_path):
            os.makedirs(encrypted_folder_path)

        report = []
        for root, _, files in os.walk(folder_path):
            for file in files:
                original_file = os.path.join(root, file)
                encrypted_file = os.path.join(encrypted_folder_path, f"{file}.enc")
                try:
                    self.file_encrypt(key, original_file, encrypted_file)
                    report.append(f"File '{original_file}' encrypted successfully.")
                except Exception as e:
                    report.append(f"Error encrypting '{original_file}': {e}")
        return report

    def decrypt_folder(self, key, folder_path, decrypted_folder_path):
        """Decrypt all files in a folder."""
        if not os.path.exists(decrypted_folder_path):
            os.makedirs(decrypted_folder_path)

        report = []
        for root, _, files in os.walk(folder_path):
            for file in files:
                encrypted_file = os.path.join(root, file)
                decrypted_file = os.path.join(decrypted_folder_path, file.replace('.enc', ''))
                try:
                    self.file_decrypt(key, encrypted_file, decrypted_file)
                    report.append(f"File '{encrypted_file}' decrypted successfully.")
                except Exception as e:
                    report.append(f"Error decrypting '{encrypted_file}': {e}")
        return report


# Helper functions for settings management
def load_settings(file_name="settings.json"):
    """Load application settings from a JSON file."""
    if os.path.exists(file_name):
        with open(file_name, 'r') as f:
            return json.load(f)
    return {}

def save_settings(settings, file_name="settings.json"):
    """Save application settings to a JSON file."""
    with open(file_name, 'w') as f:
        json.dump(settings, f, indent=4)
    log_event(f"Settings saved to '{file_name}'.") 


# Helper functions for security
def generate_file_hash(file_path):
    """Generate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def verify_file_integrity(original_file, encrypted_file):
    """Verify if the integrity of a file is intact after encryption."""
    original_hash = generate_file_hash(original_file)
    encrypted_hash = generate_file_hash(encrypted_file)
    return original_hash == encrypted_hash

def derive_key_from_password(password: str):
    """Derive a key from a password using PBKDF2."""
    salt = os.urandom(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key


# Log events
def log_event(message):
    """Log events to the log file."""
    logging.info(message)


# Main Program
def select_file():
    """Prompt the user to select a file through a graphical interface."""
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    filename = filedialog.askopenfilename()
    return filename

def select_folder():
    """Prompt the user to select a folder through a graphical interface."""
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    folder_name = filedialog.askdirectory()
    return folder_name


def generate_report(report):
    """Generate a report file from the given list of events."""
    report_file = "operation_report.txt"
    with open(report_file, "w") as file:
        for line in report:
            file.write(line + "\n")
    print(f"Report generated: {report_file}")
    log_event(f"Report generated: {report_file}")


# اللغة
language = "en"  # اللغة الافتراضية هي الإنجليزية

def switch_language():
    global language
    if language == "en":
        language = "ar"
    else:
        language = "en"


def print_menu():
    if language == "en":
        print("\nMenu:")
        print("1. Generate a new key")
        print("2. Select an existing key")
        print("3. Encrypt Files")
        print("4. Decrypt Files")
        print("5. Encrypt a Folder")
        print("6. Decrypt a Folder")
        print("7. Create a Backup")
        print("8. Verify Backup")
        print("9. Restore Backup")
        print("10. Exit")
        print("11. Switch Language (English/Arabic)")
        print("Created by mot204t")
    else:
        print("\nالقائمة:")
        print("1. إنشاء مفتاح جديد")
        print("2. اختيار مفتاح موجود")
        print("3. تشفير الملفات")
        print("4. فك تشفير الملفات")
        print("5. تشفير مجلد")
        print("6. فك تشفير مجلد")
        print("7. إنشاء نسخة احتياطية")
        print("8. التحقق من النسخة الاحتياطية")
        print("9. استعادة النسخة الاحتياطية")
        print("10. خروج")
        print("11. تغيير اللغة (إنجليزي/عربي)")

# Main loop
if __name__ == "__main__":
    encryptor = Encryptor()
    settings = load_settings()
    key = None

    # Automatically load the default key if it exists in settings.json
    if 'default_key' in settings and os.path.exists(settings['default_key']):
        try:
            key = encryptor.key_load(settings['default_key'])
            log_event(f"Default key '{settings['default_key']}' loaded successfully.")
        except Exception as e:
            log_event(f"Failed to load default key: {e}")

    print("File Encryptor & Decryptor")
    while True:
        print_menu()
        choice = input(f"Select an Option (1/2/3/4/5/6/7/8/9/10/11): ").strip()

        if choice == '1':
            # Generate a new key
            key = encryptor.key_create()
            key_name = input("Enter the filename to save the key (e.g., 'encryption-key.key'): ")
            encryptor.key_write(key, key_name)
            print(f"Key saved successfully as '{key_name}'.")
            save_default = input("Do you want to save this key as the default key? (y/n): ").strip().lower()
            if save_default == 'y':
                settings['default_key'] = key_name
                save_settings(settings)
                print(f"Default key updated to '{key_name}'.")

        elif choice == '2':
            # Select an existing key
            key_file = input("Enter the filename of the existing key: ")
            try:
                key = encryptor.key_load(key_file)
                print(f"Key '{key_file}' loaded successfully.")
                save_default = input("Do you want to save this key as the default key? (y/n): ").strip().lower()
                if save_default == 'y':
                    settings['default_key'] = key_file
                    save_settings(settings)
                    print(f"Default key updated to '{key_file}'.")
            except Exception as e:
                print(f"Error loading key: {e}")

        elif choice == '3':
            # Encrypt a file
            if key is None:
                print("No key selected. Please generate or load a key first.")
                continue
            original_file = select_file()
            encrypted_file = original_file + ".enc"
            encryptor.file_encrypt(key, original_file, encrypted_file)

        elif choice == '4':
            # Decrypt a file
            if key is None:
                print("No key selected. Please generate or load a key first.")
                continue
            encrypted_file = select_file()
            decrypted_file = encrypted_file.replace(".enc", "")
            encryptor.file_decrypt(key, encrypted_file, decrypted_file)

        elif choice == '5':
            # Encrypt a folder
            if key is None:
                print("No key selected. Please generate or load a key first.")
                continue
            folder_path = select_folder()
            encrypted_folder_path = folder_path + "_encrypted"
            report = encryptor.encrypt_folder(key, folder_path, encrypted_folder_path)
            generate_report(report)

        elif choice == '6':
            # Decrypt a folder
            if key is None:
                print("No key selected. Please generate or load a key first.")
                continue
            folder_path = select_folder()
            decrypted_folder_path = folder_path + "_decrypted"
            report = encryptor.decrypt_folder(key, folder_path, decrypted_folder_path)
            generate_report(report)

        elif choice == '7':
            # Create a backup
            if key is None:
                print("No key selected. Please generate or load a key first.")
                continue
            backup_code = input("Enter a backup code: ")
            encryptor.create_backup(settings['default_key'], backup_code)

        elif choice == '8':
            # Verify backup code
            backup_code = input("Enter backup code to verify: ")
            if encryptor.verify_backup_code(backup_code):
                print("Backup verified successfully.")
            else:
                print("Invalid backup code.")

        elif choice == '9':
            # Restore backup
            backup_file = filedialog.askopenfilename(filetypes=[("Zip Files", "*.zip")])
            if backup_file:
                key, settings = encryptor.restore_backup(backup_file)

        elif choice == '10':
            # Exit the program
            print("Exiting program.")
            break

        elif choice == '11':
            # Switch language
            switch_language()
