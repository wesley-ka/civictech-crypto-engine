package com.civictech.crypto.engine.identity.vc.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record IssueVcResponse(
    @JsonProperty("vcId") String vcId,
    @JsonProperty("shareUrl") String shareUrl,
    @JsonProperty("credential") VerifiableCredential credential
) {}
