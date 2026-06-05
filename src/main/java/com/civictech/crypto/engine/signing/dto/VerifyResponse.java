package com.civictech.crypto.engine.signing.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record VerifyResponse(
    @JsonProperty("valid") boolean valid,
    @JsonProperty("issuer") String issuer,
    @JsonProperty("timestamp") Instant timestamp
) {}
