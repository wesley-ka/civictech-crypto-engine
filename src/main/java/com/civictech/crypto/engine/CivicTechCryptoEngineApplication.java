package com.civictech.crypto.engine;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class CivicTechCryptoEngineApplication {

    static {
        // Register BouncyCastle Security Provider globally
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(CivicTechCryptoEngineApplication.class, args);
    }
}
