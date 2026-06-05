package com.civictech.crypto.engine.identity.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record ZkpVerifyRequest(
    @NotBlank(message = "commitment_hash is required")
    @JsonProperty("commitment_hash") String commitmentHash,

    @NotBlank(message = "commitment_x is required")
    @JsonProperty("commitment_x") String commitmentX,

    @NotBlank(message = "commitment_y is required")
    @JsonProperty("commitment_y") String commitmentY,

    @NotBlank(message = "challenge is required")
    @JsonProperty("challenge") String challenge,

    @NotBlank(message = "response is required")
    @JsonProperty("response") String response,

    @NotBlank(message = "public_key_x is required")
    @JsonProperty("public_key_x") String publicKeyX,

    @NotBlank(message = "public_key_y is required")
    @JsonProperty("public_key_y") String publicKeyY,

    @JsonProperty("base_point_x") String basePointX,
    @JsonProperty("base_point_y") String basePointY
) {}
