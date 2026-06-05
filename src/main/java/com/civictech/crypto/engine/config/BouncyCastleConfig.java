package com.civictech.crypto.engine.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

@Configuration
public class BouncyCastleConfig {

    private static final Logger log = LoggerFactory.getLogger(BouncyCastleConfig.class);

    public BouncyCastleConfig() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            log.info("Bouncy Castle security provider successfully registered.");
        } else {
            log.info("Bouncy Castle security provider already registered.");
        }
    }
}
