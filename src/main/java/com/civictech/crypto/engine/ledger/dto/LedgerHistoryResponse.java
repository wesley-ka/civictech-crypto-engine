package com.civictech.crypto.engine.ledger.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record LedgerHistoryResponse(
    @JsonProperty("assetId") String assetId,
    @JsonProperty("totalBlocks") int totalBlocks,
    @JsonProperty("blocks") List<LedgerBlock> blocks
) {}
