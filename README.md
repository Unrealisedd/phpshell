# PHP Web Shell Controller - QUICK NOTE: CUSTOM COMMANDS DONT WORK YET, ITS PURELY A SHELL FOR NOW

This is an advanced command and control tool for managing PHP web shells. It provides a comprehensive set of features for interacting with deployed PHP shells, managing files, executing commands, and maintaining persistence.

## Features

- **Encrypted Communication**: All traffic between the controller and shell is encrypted
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

## flowcharts (in dutch)

### general workflow
┌─────────────────────────────────────────────────────────────┐
│ Gebruiker/Student                                          │
│ (Wil een polymorphic shell maken en daarna ermee werken)   │
└─────────────────────────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. shell_gen.py                                            │
│  - Lees main_shell.php & shell_loader.php                  │
│  - Versleutel en genereer ultimate_polymorphic_shell.php   │
└─────────────────────────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Upload ultimate_polymorphic_shell.php                   │
│    naar een doelserver, zodat hij elders draait.           │
└─────────────────────────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. shell_controller.py                                     │
│  - ShellController-klasse maakt verbinding met de shell    │
│  - Gebruiker kan commando's intypen in de CLI (ShellControllerCLI)  │
│  - Script versleutelt commando's -> stuurt naar shell ->   │
│    ontvangt versleutelde output -> decrypt -> toont in CLI │
└─────────────────────────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ Gebruiker heeft nu interactief een remote web shell        │
│ (Bestanden beheren, processen killen, netwerk scannen,     │
│ reverse shell opzetten, etc.)                              │
└─────────────────────────────────────────────────────────────┘

### shell_gen.py
┌─────────────────────────────────────────────────────────────────────┐
│                Start script: shell_gen.py                          │
└─────────────────────────────────────────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Generate random key                                             │
│    - key = secrets.token_hex(8)                                    │
└─────────────────────────────────────────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 2. Lees main_shell.php (de 'echte' shell-code)                     │
│    - Verwijder eventuele <?php en ?> tags                          │
│    - Sla de (ruwe) shell-code op in een string                     │
└─────────────────────────────────────────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 3. Lees shell_loader.php (loader template)                         │
│    - Hier staan placeholders als:                                   │
│        $key = "my_secret_key"                                      │
│        $payload = "ENCRYPTED_PAYLOAD_PLACEHOLDER"                  │
└─────────────────────────────────────────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 4. Encrypt main_shell-code met de gegenereerde key                 │
│    - (Zie “Encryptie Subflow” hieronder voor details)              │
│    - Resultaat = versleutelde payload (string)                     │
└─────────────────────────────────────────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 5. Plaats key en versleutelde payload in de loader_template        │
│    - Vervang $key door de random key                               │
│    - Vervang $payload door de versleutelde string                  │
└─────────────────────────────────────────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 6. Schrijf het resulterende script uit als                         │
│    ultimate_polymorphic_shell.php                                  │
│    - Print ook de gebruikte key en size op het scherm              │
└─────────────────────────────────────────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Einde shell_gen.py: De polymorphic shell is succesvol gegeneerd.   │
└─────────────────────────────────────────────────────────────────────┘

###subflow encryption/decryption
┌─────────────────────────────────────────────────────┐
│   (Encryptie: shell_gen)                           │
│   Input: main_shell code, key                      │
└─────────────────────────────────────────────────────┘
            ▼
┌─────────────────────────────────────────────────────┐
│ 1. Zlib compress main_shell                        │
│ 2. Base64-encode de gecomprimeerde data            │
│ 3. XOR elke byte met bytes uit SHA256(key)         │
│ 4. Resultaat weer base64-encode.                   │
│ = ENCRYPTED_PAYLOAD (string)                       │
└─────────────────────────────────────────────────────┘
            ▼
┌─────────────────────────────────────────────────────┐
│ Output: ENCRYPTED_PAYLOAD                          │
└─────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────┐
│   (Decryptie: shell_controller)                    │
│   Input: ENCRYPTED_PAYLOAD, key                    │
└─────────────────────────────────────────────────────┘
            ▼
┌─────────────────────────────────────────────────────┐
│ 1. Base64-decode om XOR-versleutelde data te krijgen│
│ 2. XOR elke byte met bytes uit SHA256(key)         │
│ 3. Base64-decode het resultaat                     │
│ 4. Zlib decompress                                 │
│ = Oorspronkelijke (plaintext) inhoud               │
└─────────────────────────────────────────────────────┘
            ▼
┌─────────────────────────────────────────────────────┐
│ Output: Plaintext shell-code of commando-output    │
└─────────────────────────────────────────────────────┘

### flowchart shellcontroller.py CLI
┌──────────────────────────────────────────────────────────────────────┐
│               Start script: shell_controller.py                    │
│               (bijv. via main() of direct CLI)                     │
└──────────────────────────────────────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 1. ShellControllerCLI wordt geïnitialiseerd                         │
│    - Print banner, wacht op user-commando's (cmdloop)               │
└──────────────────────────────────────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 2. Gebruiker typt “connect <url> [key]” in de CLI                   │
│    => ShellController.__init__                                      │
│       - Slaat target_url, encryption_key, headers e.d. op           │
│       - Maakt requests.Session() en stelt User-Agent in             │
└──────────────────────────────────────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 3. ShellController.test_connection()                                │
│    - Probeert “echo ShellTest” via headers, POST, en GET            │
│    - Ontvangt de versleutelde response (mits shell werkt),          │
│      decrypt, check op “ShellTest”                                  │
└──────────────────────────────────────────────────────────────────────┘
                     ▼
         ┌───────────────────────────┐
         │ Connection geslaagd?      │
         └───────────────────────────┘
              /          \
             /Yes         \No
            ▼              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 4. get_system_info()                                                │
│    - Stuur “SYSINFO” command                                        │
│    - Ontvang JSON en sla op in self.shell_info (OS, user, etc.)     │
└──────────────────────────────────────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 5. Gebruiker kan diverse CLI-commando’s uitvoeren:                  │
│    - shell (interactieve shell)                                     │
│    - files (bestandsbeheer)                                         │
│    - processes (process manager)                                    │
│    - network (network manager)                                      │
│    - revshell <ip> [port]                                           │
│    - polymorphic / memory / persist-check / repair, etc.            │
└──────────────────────────────────────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 6. Ieder CLI-commando -> ShellController.execute_command(cmd)       │
│    - Encrypt command (XOR + Base64 + zlib)                          │
│    - Probeer HTTP-header, daarna POST, dan GET (in die volgorde)    │
│    - De shell (ultimate_polymorphic_shell.php) ontvangt, voert uit, │
│      versleutelt de output en stuurt terug.                         │
│    - De controller decrypt de output en geeft het aan de CLI.       │
└──────────────────────────────────────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 7. CLI toont de gedecrypte response.                                │
│    - Gebruiker kan weer een nieuw commando intypen.                │
└──────────────────────────────────────────────────────────────────────┘
                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 8. Als gebruiker “exit” of “quit” typt -> CLI stopt cmdloop()       │
│    Einde shell_controller.py                                        │
└──────────────────────────────────────────────────────────────────────┘

## Security Notice

This tool is intended for legitimate security testing and system administration purposes only. Unauthorized access to computer systems is illegal and unethical. Always obtain proper authorization before using this tool on any system.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
```
