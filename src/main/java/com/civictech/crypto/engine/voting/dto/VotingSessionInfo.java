package com.civictech.crypto.engine.voting.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record VotingSessionInfo(
    @JsonProperty("vote_id") String voteId,
    @JsonProperty("title") String title,
    @JsonProperty("candidates") List<String> candidates,
    @JsonProperty("expires_at") String expiresAt,
    @JsonProperty("active") boolean active
) {}
