package com.civictech.crypto.engine.identity.vc.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

public record VerifiableCredential(
    @JsonProperty("@context") List<String> context,
    @JsonProperty("id") String id,
    @JsonProperty("type") List<String> type,
    @JsonProperty("issuer") String issuer,
    @JsonProperty("issuanceDate") String issuanceDate,
    @JsonProperty("expirationDate") String expirationDate,
    @JsonProperty("credentialSubject") Map<String, Object> credentialSubject,
    @JsonProperty("proof") CredentialProof proof
) {}
