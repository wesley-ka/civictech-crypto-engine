package com.civictech.crypto.engine.quantum.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record DecryptResponse(
    @JsonProperty("decrypted_text") String decryptedText,
    @JsonProperty("algorithm") String algorithm,
    @JsonProperty("shared_secret_hash") String sharedSecretHash
) {}
