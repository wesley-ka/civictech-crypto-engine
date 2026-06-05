package com.civictech.crypto.engine.signing.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record SignResponse(
    @JsonProperty("signature") String signature,
    @JsonProperty("public_key_x") String publicKeyX,
    @JsonProperty("public_key_y") String publicKeyY,
    @JsonProperty("algorithm") String algorithm,
    @JsonProperty("timestamp") Instant timestamp
) {}
