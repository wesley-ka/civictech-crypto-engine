package com.civictech.crypto.engine.ledger.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record LedgerVerificationResponse(
    @JsonProperty("assetId") String assetId,
    @JsonProperty("validChain") boolean validChain,
    @JsonProperty("blockCount") int blockCount,
    @JsonProperty("auditReport") List<BlockAuditReport> auditReport
) {
    public record BlockAuditReport(
        @JsonProperty("index") int index,
        @JsonProperty("hashMatches") boolean hashMatches,
        @JsonProperty("signatureValid") boolean signatureValid,
        @JsonProperty("blockHash") String blockHash
    ) {}
}
