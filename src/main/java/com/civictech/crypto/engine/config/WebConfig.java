package com.civictech.crypto.engine.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // Allow local development and testing tools to consume the cryptographic engine APIs
        registry.addMapping("/v1/**")
                .allowedOrigins("*")
                .allowedMethods("POST", "GET", "OPTIONS")
                .allowedHeaders("*")
                .maxAge(3600);
    }
}
