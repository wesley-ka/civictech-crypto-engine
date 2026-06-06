package com.civictech.crypto.engine.voting.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CreateVotingSessionResponse(
    @JsonProperty("vote_id") String voteId,
    @JsonProperty("expires_at") String expiresAt,
    @JsonProperty("creator_token") String creatorToken
) {}
