Python Password Manager
A secure, local CLI password manager with military-grade encryption.

Features
 AES-128 encryption
 Master password (OS keyring)
 Auto-generate secure passwords
 Encrypted storage
Install
bash


pip install cryptography keyring
python password_manager.py
Usage


1. Add password
2. Get password  
3. List services
4. Delete
5. Change master pw
0. Quit
First run: Set master password.

Files
passwords.enc - Encrypted data BACKUP THIS
salt.bin - Salt BACKUP THIS
Security
Fernet (AES-128 + HMAC)
PBKDF2 (100k iterations)
Zero-knowledge
 Without passwords.enc + salt.bin = data lost forever.

License
MIT

