package com.civictech.crypto.engine.voting.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public record VotingResultsResponse(
    @JsonProperty("status") String status,
    @JsonProperty("title") String title,
    @JsonProperty("expires_at") String expiresAt,
    @JsonProperty("tallies") Map<String, Integer> tallies,
    @JsonProperty("total_votes") int totalVotes,
    @JsonProperty("audit_package") Map<String, Object> auditPackage,
    @JsonProperty("verification_guide") String verificationGuide
) {}
