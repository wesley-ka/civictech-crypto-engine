package com.civictech.crypto.engine.vault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record EncryptResponse(
    @JsonProperty("ciphertext") String ciphertext,
    @JsonProperty("iv") String iv,
    @JsonProperty("auth_tag") String authTag
) {}
