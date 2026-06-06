package com.civictech.crypto.engine.voting.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ChallengeResponse(
    @JsonProperty("challenge") String challenge
) {}
