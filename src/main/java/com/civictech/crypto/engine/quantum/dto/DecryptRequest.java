package com.civictech.crypto.engine.quantum.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record DecryptRequest(
    @NotBlank(message = "private_key is required")
    @JsonProperty("private_key") String privateKey,

    @NotBlank(message = "kem_ciphertext is required")
    @JsonProperty("kem_ciphertext") String kemCiphertext,

    @NotBlank(message = "iv is required")
    @JsonProperty("iv") String iv,

    @NotBlank(message = "encrypted_message is required")
    @JsonProperty("encrypted_message") String encryptedMessage
) {}
