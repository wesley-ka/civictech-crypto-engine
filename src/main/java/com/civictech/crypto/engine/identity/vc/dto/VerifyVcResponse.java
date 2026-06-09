package com.civictech.crypto.engine.identity.vc.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record VerifyVcResponse(
    @JsonProperty("verified") boolean verified,
    @JsonProperty("checks") VcChecks checks,
    @JsonProperty("issuer") String issuer,
    @JsonProperty("subject") String subject,
    @JsonProperty("verifiedAt") Instant verifiedAt
) {
    public record VcChecks(
        @JsonProperty("signatureValid") boolean signatureValid,
        @JsonProperty("notExpired") boolean notExpired,
        @JsonProperty("integrityIntact") boolean integrityIntact
    ) {}
}
