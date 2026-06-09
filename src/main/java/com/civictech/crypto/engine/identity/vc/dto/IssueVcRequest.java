package com.civictech.crypto.engine.identity.vc.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Map;

public record IssueVcRequest(
    @NotBlank(message = "subjectId is required")
    @JsonProperty("subjectId") String subjectId,

    @NotBlank(message = "fullName is required")
    @JsonProperty("fullName") String fullName,

    @NotNull(message = "attributes map is required")
    @JsonProperty("attributes") Map<String, Object> attributes,

    @JsonProperty("expirationDays") Integer expirationDays
) {}
