package com.civictech.crypto.engine.certificates.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;

public record ParseCertificateResponse(
    @JsonProperty("subject_dn") String subjectDn,
    @JsonProperty("issuer_dn") String issuerDn,
    @JsonProperty("serial_number") String serialNumber,
    @JsonProperty("valid_from") Instant validFrom,
    @JsonProperty("valid_to") Instant validTo,
    @JsonProperty("key_usage") List<String> keyUsage,
    @JsonProperty("is_expired") boolean isExpired,
    @JsonProperty("signature_algorithm") String signatureAlgorithm,
    @JsonProperty("signature_valid") boolean signatureValid,
    @JsonProperty("validation_log") List<String> validationLog
) {}
