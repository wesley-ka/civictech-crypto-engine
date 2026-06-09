package com.civictech.crypto.engine.identity.vc.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CredentialProof(
    @JsonProperty("type") String type,
    @JsonProperty("created") String created,
    @JsonProperty("proofPurpose") String proofPurpose,
    @JsonProperty("verificationMethod") String verificationMethod,
    @JsonProperty("publicKeyX") String publicKeyX,
    @JsonProperty("publicKeyY") String publicKeyY,
    @JsonProperty("proofValue") String proofValue
) {}
