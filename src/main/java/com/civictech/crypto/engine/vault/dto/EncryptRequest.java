package com.civictech.crypto.engine.vault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotEmpty;
import java.util.Map;

public record EncryptRequest(
    @NotEmpty(message = "sensitive_data must not be empty")
    @JsonProperty("sensitive_data") Map<String, Object> sensitiveData
) {}
