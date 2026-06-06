package com.civictech.crypto.engine.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import java.net.URI;

@Configuration
public class S3Config {
    private static final Logger log = LoggerFactory.getLogger(S3Config.class);

    @Value("${voting.storage.b2.endpoint:}")
    private String endpoint;

    @Value("${voting.storage.b2.access-key:}")
    private String accessKey;

    @Value("${voting.storage.b2.secret-key:}")
    private String secretKey;

    @Value("${voting.storage.b2.region:us-east-1}")
    private String region;

    @Bean
    public S3Client s3Client() {
        if (accessKey == null || accessKey.isBlank() || secretKey == null || secretKey.isBlank()) {
            log.info("Backblaze B2 credentials not fully configured. S3Client bean will not be initialized (falling back to local filesystem storage).");
            return null;
        }

        log.info("Initializing Backblaze B2 S3 Client (Endpoint: {}, Region: {})", endpoint, region);
        
        URI endpointUri;
        try {
            String formattedEndpoint = endpoint.trim();
            if (!formattedEndpoint.startsWith("http://") && !formattedEndpoint.startsWith("https://")) {
                formattedEndpoint = "https://" + formattedEndpoint;
            }
            endpointUri = URI.create(formattedEndpoint);
        } catch (Exception e) {
            log.error("Invalid Backblaze B2 endpoint override URI: {}. Falling back to null S3Client.", endpoint, e);
            return null;
        }

        return S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKey.trim(), secretKey.trim())
                ))
                .region(Region.of(region.trim()))
                .endpointOverride(endpointUri)
                .forcePathStyle(true) // B2 requires path-style access
                .build();
    }
}
