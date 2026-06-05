package com.civictech.crypto.engine.tsa.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record TimestampResponse(
    @JsonProperty("token_base64") String tokenBase64,
    @JsonProperty("serial_number") String serialNumber,
    @JsonProperty("timestamp") Instant timestamp,
    @JsonProperty("nonce") String nonce,
    @JsonProperty("hash_algorithm") String hashAlgorithm,
    @JsonProperty("document_hash") String documentHash,
    @JsonProperty("signature") String signature,
    @JsonProperty("tsa_public_key_x") String tsaPublicKeyX,
    @JsonProperty("tsa_public_key_y") String tsaPublicKeyY
) {}
