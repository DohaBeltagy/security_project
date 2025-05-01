rule AES_With_Base64 {
    meta:
        description = "Detects AES encryption patterns potentially used in ransomware, including Base64 encoded data"
        score = 7  
    strings:
        // AES Patterns
        $aes1 = "AES_encrypt" wide ascii
        $aes2 = "AES_set_encrypt_key" wide ascii
        $aes3 = "AES_CBC_encrypt" wide ascii
        
        // OpenSSL Patterns
        $openssl1 = "EVP_aes_256_cbc" wide ascii
        $openssl2 = "EVP_EncryptInit" wide ascii
        
        // Key Patterns
        $key1 = /[0-9a-f]{32}/  // 128-bit key
        $key2 = /[0-9a-f]{64}/  // 256-bit key
        
        // Base64 (improved to reduce false positives)
        $b64 = /[A-Za-z0-9+\/=]{30,}/  
    condition:
        // Logical grouping for better detection
        (
            (any of ($aes*) or any of ($openssl*)) and 
            ($b64 or any of ($key*))
        ) or 
        (
            (2 of ($key*)) or 
            (3 of ($b64*))  // Multiple long Base64 strings
        )
}