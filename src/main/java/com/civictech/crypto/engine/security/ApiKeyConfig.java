package com.civictech.crypto.engine.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.HexFormat;

@Component
public class ApiKeyConfig {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyConfig.class);

    @Value("${crypto.api-key:}")
    private String configuredApiKey;

    private String apiKey;

    @PostConstruct
    public void init() {
        if (configuredApiKey != null && !configuredApiKey.trim().isEmpty()) {
            apiKey = configuredApiKey.trim();
            log.info("API key loaded from configuration.");
        } else {
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            apiKey = HexFormat.of().formatHex(keyBytes);
            log.warn("No API key configured (crypto.api-key). Generated ephemeral key: {}", apiKey);
            log.warn("Set CRYPTO_API_KEY environment variable to make this persistent across restarts.");
        }
    }

    public String getApiKey() {
        return apiKey;
    }
}
