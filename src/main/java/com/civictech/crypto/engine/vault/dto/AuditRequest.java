package com.civictech.crypto.engine.vault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record AuditRequest(
    @NotBlank(message = "log_entry must not be blank")
    @JsonProperty("log_entry") String logEntry
) {}
