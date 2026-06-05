package com.civictech.crypto.engine.vault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record DecryptRequest(
    @NotBlank(message = "ciphertext is required")
    @JsonProperty("ciphertext") String ciphertext,

    @NotBlank(message = "iv is required")
    @JsonProperty("iv") String iv,

    @NotBlank(message = "auth_tag is required")
    @JsonProperty("auth_tag") String authTag
) {}
