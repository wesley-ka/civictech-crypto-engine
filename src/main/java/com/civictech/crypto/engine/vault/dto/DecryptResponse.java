package com.civictech.crypto.engine.vault.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public record DecryptResponse(
    @JsonProperty("decrypted_data") Map<String, Object> decryptedData
) {}
