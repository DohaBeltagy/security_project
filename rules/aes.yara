rule Crypto_Algorithms {
    meta:
        score = 5
        description = "Encryption API used in ransomware"
    strings:
        $aes = "AES_encrypt" ascii wide
        $rsa = "RSA_public_encrypt" ascii wide
        $openssl = "EVP_aes_256_cbc" ascii
        $chacha = "chacha20" ascii
    condition:
        2 of them
}
