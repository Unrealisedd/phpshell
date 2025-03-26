# PHP Web Shell Controller

This is an advanced command and control tool for managing PHP web shells. It provides a comprehensive set of features for interacting with deployed PHP shells, managing files, executing commands, and maintaining persistence.

## Features

- **Encrypted Communication**: All traffic between the controller and shell is encrypted using AES-256-CBC with HMAC integrity verification
- **Multiple Transport Methods**: Supports communication via HTTP headers, POST data, and GET parameters
- **Interactive Shell**: Provides an interactive command-line interface to the remote system
- **File Management**: Browse, upload, download, and edit files on the remote system
- **Process Management**: View and control running processes
- **Network Tools**: Scan networks, check connections, and enumerate interfaces
- **Persistence Management**: Check and repair persistence mechanisms
- **Stealth Features**: Clean logs, create polymorphic shell variants, and use memory-only mode

## Requirements

- Python 3.6+
- Required Python packages:
  - requests
  - pycryptodome
  - colorama
  - tabulate

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/username/php-shell-controller.git
   cd php-shell-controller
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Shell Controller

The main controller provides an interactive interface to manage PHP shells:

```
python shell_controller.py [-u URL] [-k KEY] [-p PROXY] [-a AGENT] [-c CONFIG]
```

Options:
- `-u, --url`: URL of the PHP shell
- `-k, --key`: Encryption key
- `-p, --proxy`: Proxy URL (e.g., http://127.0.0.1:8080)
- `-a, --agent`: Custom User-Agent string
- `-c, --config`: Load configuration from file

### Shell Utilities

Additional utilities for working with PHP shells:

```
python shell_utilities.py COMMAND [options]
```

Commands:
- `genkey`: Generate an encryption key
- `encrypt`: Encrypt a PHP payload
- `oneliner`: Generate a one-liner to deploy the shell
- `scan`: Scan a target for PHP shells

## Controller Commands

Once connected to a shell, the following commands are available:

- `info`: Display system information
- `shell`: Start an interactive shell session
- `files`: Browse and manage files
- `processes`: Manage processes
- `network`: Network tools and information
- `persist check|repair`: Check or repair persistence mechanisms
- `revshell <ip> [port]`: Create a reverse shell
- `clean`: Clean logs on the remote system
- `polymorphic`: Create a polymorphic variant of the shell
- `memory`: Activate memory-only mode
- `exec <command>`: Execute a single command
- `save [filename]`: Save the current configuration
- `load [filename]`: Load configuration from a file
- `exit` or `quit`: Exit the controller

## Security Notice

This tool is intended for legitimate security testing and system administration purposes only. Unauthorized access to computer systems is illegal and unethical. Always obtain proper authorization before using this tool on any system.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
```
