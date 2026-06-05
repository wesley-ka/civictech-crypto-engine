package com.civictech.crypto.engine.vault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record AuditResponse(
    @JsonProperty("index") int index,
    @JsonProperty("timestamp") Instant timestamp,
    @JsonProperty("log_entry") String logEntry,
    @JsonProperty("previous_hash") String previousHash,
    @JsonProperty("block_hash") String blockHash,
    @JsonProperty("merkle_root") String merkleRoot
) {}
