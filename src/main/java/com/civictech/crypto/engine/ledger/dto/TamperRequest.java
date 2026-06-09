package com.civictech.crypto.engine.ledger.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;

public record TamperRequest(
    @NotNull(message = "index is required")
    @JsonProperty("index") int index,

    @JsonProperty("location") String location,
    @JsonProperty("custodian") String custodian
) {}
