package com.civictech.crypto.engine.ledger.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;

public record AppendEventRequest(
    @NotBlank(message = "assetId is required")
    @JsonProperty("assetId") String assetId,

    @NotBlank(message = "eventType is required")
    @JsonProperty("eventType") String eventType,

    @NotBlank(message = "custodian is required")
    @JsonProperty("custodian") String custodian,

    @JsonProperty("location") String location,

    @NotBlank(message = "previousBlockHash is required")
    @JsonProperty("previousBlockHash") String previousBlockHash,

    @JsonProperty("meta") Map<String, Object> meta
) {}
