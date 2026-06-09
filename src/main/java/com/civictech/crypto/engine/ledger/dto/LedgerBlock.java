package com.civictech.crypto.engine.ledger.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public record LedgerBlock(
    @JsonProperty("index") int index,
    @JsonProperty("timestamp") String timestamp,
    @JsonProperty("assetId") String assetId,
    @JsonProperty("eventType") String eventType,
    @JsonProperty("custodian") String custodian,
    @JsonProperty("location") String location,
    @JsonProperty("previousBlockHash") String previousBlockHash,
    @JsonProperty("blockHash") String blockHash,
    @JsonProperty("signature") String signature,
    @JsonProperty("meta") Map<String, Object> meta
) {}
