package com.civictech.crypto.engine.quantum.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record EncryptRequest(
    @NotBlank(message = "recipient_public_key is required")
    @JsonProperty("recipient_public_key") String recipientPublicKey,

    @NotBlank(message = "message_text is required")
    @JsonProperty("message_text") String messageText
) {}
