package com.civictech.crypto.engine.certificates.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record ParseCertificateRequest(
    @NotBlank(message = "certificate_base64 is required")
    @JsonProperty("certificate_base64") String certificateBase64
) {}
