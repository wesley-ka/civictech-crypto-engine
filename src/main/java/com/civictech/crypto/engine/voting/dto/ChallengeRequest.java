package com.civictech.crypto.engine.voting.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record ChallengeRequest(
    @NotBlank(message = "vote_id is required")
    @JsonProperty("vote_id") String voteId,

    @NotBlank(message = "nullifier is required")
    @JsonProperty("nullifier") String nullifier,

    @NotBlank(message = "public_key_x is required")
    @JsonProperty("public_key_x") String publicKeyX,

    @NotBlank(message = "public_key_y is required")
    @JsonProperty("public_key_y") String publicKeyY
) {}
