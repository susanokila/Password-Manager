import os
import json
import getpass
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import keyring
import secrets
from typing import Dict, Optional

class PasswordManager:
    def __init__(self, service_name: str = "PythonPasswordManager"):
        self.service_name = service_name
        self.data_file = "passwords.enc"
        self.salt_file = "salt.bin"
        self.keyring_key = f"{service_name}_master_key"
        
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create new one"""
        if os.path.exists(self.salt_file):
            with open(self.salt_file, "rb") as f:
                return f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_file, "wb") as f:
                f.write(salt)
            return salt
    
    def _get_master_password(self) -> str:
        """Get master password from keyring or prompt user"""
        stored_hash = keyring.get_password(self.service_name, "master_hash")
        
        while True:
            password = getpass.getpass("Enter master password: ").strip()
            if not password:
                print("Password cannot be empty!")
                continue
                
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            if stored_hash is None:
                # First time setup
                confirm = getpass.getpass("Confirm master password: ").strip()
                if password == confirm:
                    keyring.set_password(self.service_name, "master_hash", password_hash)
                    print(" Master password set!")
                    return password
                else:
                    print(" Passwords don't match!")
                    continue
            elif stored_hash == password_hash:
                return password
            else:
                print(" Incorrect master password!")
    
    def _get_fernet_key(self) -> bytes:
        """Get Fernet key derived from master password"""
        master_password = self._get_master_password()
        salt = self._get_or_create_salt()
        return self._derive_key(master_password, salt)
    
    def _load_encrypted_data(self) -> Dict:
        """Load and decrypt password database"""
        if not os.path.exists(self.data_file):
            return {}
        
        try:
            fernet = Fernet(self._get_fernet_key())
            with open(self.data_file, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except (InvalidToken, ValueError):
            print(" Error decrypting data. Wrong master password?")
            return {}
    
    def _save_encrypted_data(self, data: Dict):
        """Encrypt and save password database"""
        fernet = Fernet(self._get_fernet_key())
        encrypted_data = fernet.encrypt(json.dumps(data, indent=2).encode())
        with open(self.data_file, "wb") as f:
            f.write(encrypted_data)
    
    def add_password(self, service: str, username: str, password: Optional[str] = None):
        """Add a new password entry"""
        data = self._load_encrypted_data()
        
        if password is None:
            password = getpass.getpass(f"Enter password for {service}: ")
        
        # Generate secure password if empty
        if not password.strip():
            password = self._generate_secure_password()
            print(f"Generated password: {password}")
        
        data[service] = {
            "username": username,
            "password": password
        }
        
        self._save_encrypted_data(data)
        print(f" Password for {service} saved!")
    
    def get_password(self, service: str) -> Optional[Dict]:
        """Retrieve a password"""
        data = self._load_encrypted_data()
        return data.get(service)
    
    def list_services(self):
        """List all stored services"""
        data = self._load_encrypted_data()
        if not data:
            print("No passwords stored.")
            return
        
        print("\nStored services:")
        for service in sorted(data.keys()):
            print(f"  • {service}")
    
    def delete_password(self, service: str):
        """Delete a password entry"""
        data = self._load_encrypted_data()
        if service in data:
            del data[service]
            self._save_encrypted_data(data)
            print(f"✓ Deleted password for {service}")
        else:
            print(f" No password found for {service}")
    
    def change_master_password(self):
        """Change the master password"""
        old_password = getpass.getpass("Enter current master password: ")
        old_hash = hashlib.sha256(old_password.encode()).hexdigest()
        
        if keyring.get_password(self.service_name, "master_hash") != old_hash:
            print(" Incorrect current password!")
            return
        
        new_password = getpass.getpass("Enter new master password: ")
        confirm = getpass.getpass("Confirm new master password: ")
        
        if new_password == confirm:
            new_hash = hashlib.sha256(new_password.encode()).hexdigest()
            keyring.set_password(self.service_name, "master_hash", new_hash)
            
            # Re-encrypt with new key
            data = self._load_encrypted_data()
            if data:
                self._save_encrypted_data(data)
            print(" Master password changed!")
        else:
            print(" Passwords don't match!")
    
    @staticmethod
    def _generate_secure_password(length: int = 20) -> str:
        """Generate a secure random password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def export_data(self, output_file: str):
        """Export decrypted data (use with caution!)"""
        data = self._load_encrypted_data()
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ Data exported to {output_file}")

def main():
    pm = PasswordManager()
    
    while True:
        print("\n" + "="*50)
        print(" PYTHON PASSWORD MANAGER")
        print("="*50)
        print("1. Add password")
        print("2. Get password")
        print("3. List services")
        print("4. Delete password")
        print("5. Change master password")
        print("6. Generate secure password")
        print("7. Export data")
        print("0. Quit")
        
        choice = input("\nChoose option: ").strip()
        
        if choice == "1":
            service = input("Service name: ").strip()
            username = input("Username: ").strip()
            pm.add_password(service, username)
            
        elif choice == "2":
            service = input("Service name: ").strip()
            entry = pm.get_password(service)
            if entry:
                print(f"Service: {service}")
                print(f"Username: {entry['username']}")
                print(f"Password: {entry['password']}")
            else:
                print(f" No password found for {service}")
                
        elif choice == "3":
            pm.list_services()
            
        elif choice == "4":
            service = input("Service name to delete: ").strip()
            pm.delete_password(service)
            
        elif choice == "5":
            pm.change_master_password()
            
        elif choice == "6":
            length = input("Password length (default 20): ").strip()
            length = int(length) if length.isdigit() else 20
            password = pm._generate_secure_password(length)
            print(f"Generated: {password}")
            
        elif choice == "7":
            filename = input("Export filename (default: export.json): ").strip()
            if not filename:
                filename = "export.json"
            pm.export_data(filename)
            
        elif choice == "0":
            print("👋 Goodbye!")
            break
            
        else:
            print(" Invalid option!")

if __name__ == "__main__":
    main()