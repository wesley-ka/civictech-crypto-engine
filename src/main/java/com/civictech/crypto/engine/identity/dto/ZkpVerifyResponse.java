package com.civictech.crypto.engine.identity.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record ZkpVerifyResponse(
    @JsonProperty("verified") boolean verified,
    @JsonProperty("proof_log") List<String> proofLog
) {}
