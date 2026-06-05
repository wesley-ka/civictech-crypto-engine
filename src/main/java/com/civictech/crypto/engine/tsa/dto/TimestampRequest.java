package com.civictech.crypto.engine.tsa.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record TimestampRequest(
    @NotBlank(message = "document_hash is required")
    @JsonProperty("document_hash") String documentHash,

    @JsonProperty("nonce") String nonce
) {}
