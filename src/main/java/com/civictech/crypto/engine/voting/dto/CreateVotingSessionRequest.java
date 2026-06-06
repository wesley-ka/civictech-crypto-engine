package com.civictech.crypto.engine.voting.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

public record CreateVotingSessionRequest(
    @NotBlank(message = "title is required")
    @JsonProperty("title") String title,

    @NotEmpty(message = "candidates list cannot be empty")
    @JsonProperty("candidates") List<String> candidates,

    @Min(value = 1, message = "duration must be at least 1 minute")
    @JsonProperty("duration_minutes") int durationMinutes,

    @JsonProperty("delivery_target") String deliveryTarget
) {}
