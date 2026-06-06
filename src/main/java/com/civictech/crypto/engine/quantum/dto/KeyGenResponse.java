package com.civictech.crypto.engine.quantum.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record KeyGenResponse(
    @JsonProperty("publicKey") String publicKey,
    @JsonProperty("privateKey") String privateKey,
    @JsonProperty("algorithm") String algorithm,
    @JsonProperty("publicKeyLength") int publicKeyLength,
    @JsonProperty("privateKeyLength") int privateKeyLength
) {}
