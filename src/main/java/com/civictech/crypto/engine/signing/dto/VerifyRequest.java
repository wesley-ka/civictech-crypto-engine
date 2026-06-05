package com.civictech.crypto.engine.signing.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record VerifyRequest(
    @NotBlank(message = "original_payload is required")
    @JsonProperty("original_payload") String originalPayload,

    @NotNull(message = "payload_is_hash is required")
    @JsonProperty("payload_is_hash") Boolean payloadIsHash,

    @NotBlank(message = "signature is required")
    @JsonProperty("signature") String signature,

    @NotBlank(message = "public_key_x is required")
    @JsonProperty("public_key_x") String publicKeyX,

    @NotBlank(message = "public_key_y is required")
    @JsonProperty("public_key_y") String publicKeyY
) {}
