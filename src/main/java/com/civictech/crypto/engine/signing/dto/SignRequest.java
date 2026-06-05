package com.civictech.crypto.engine.signing.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record SignRequest(
    @JsonProperty("file_checksum") String fileChecksum,
    @JsonProperty("payload_base64") String payloadBase64
) {
    public SignRequest {
        if ((fileChecksum == null || fileChecksum.isBlank()) && (payloadBase64 == null || payloadBase64.isBlank())) {
            throw new IllegalArgumentException("Either 'file_checksum' or 'payload_base64' must be provided.");
        }
    }
}
