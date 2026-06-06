package com.civictech.crypto.engine.voting;

import java.util.Map;

public interface VotingResultDeliveryService {
    void deliver(String target, String title, Map<String, Object> auditPackage, String verificationGuide);
    boolean supports(String target);
}
