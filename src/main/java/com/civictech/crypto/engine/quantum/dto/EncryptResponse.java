package com.civictech.crypto.engine.quantum.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record EncryptResponse(
    @JsonProperty("kem_ciphertext") String kemCiphertext,
    @JsonProperty("iv") String iv,
    @JsonProperty("encrypted_message") String encryptedMessage,
    @JsonProperty("algorithm") String algorithm,
    @JsonProperty("shared_secret_hash") String sharedSecretHash
) {}
