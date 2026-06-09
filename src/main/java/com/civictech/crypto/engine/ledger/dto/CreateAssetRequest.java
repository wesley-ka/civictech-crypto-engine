package com.civictech.crypto.engine.ledger.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;

public record CreateAssetRequest(
    @NotBlank(message = "assetId is required")
    @JsonProperty("assetId") String assetId,

    @NotBlank(message = "assetType is required")
    @JsonProperty("assetType") String assetType,

    @NotBlank(message = "custodian is required")
    @JsonProperty("custodian") String custodian,

    @JsonProperty("meta") Map<String, Object> meta
) {}
