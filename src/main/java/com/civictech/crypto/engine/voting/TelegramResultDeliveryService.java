package com.civictech.crypto.engine.voting;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.Map;
import java.util.List;

@Service
public class TelegramResultDeliveryService implements VotingResultDeliveryService {
    private static final Logger log = LoggerFactory.getLogger(TelegramResultDeliveryService.class);
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${voting.telegram.bot-token:}")
    private String botToken;

    @Override
    public boolean supports(String target) {
        // Support any non-blank target. If it doesn't have a prefix, we assume it is a Telegram chat ID
        // (as Telegram is the only currently supported reporting mechanism).
        return target != null && !target.isBlank();
    }

    @SuppressWarnings("unchecked")
    @Override
    public void deliver(String target, String title, Map<String, Object> auditPackage, String verificationGuide) {
        String chatId = target.trim();
        if (chatId.startsWith("telegram:")) {
            chatId = chatId.substring("telegram:".length()).trim();
        }
        log.info("Delivering results for '{}' to Telegram chat ID: {}", title, chatId);

        if (botToken == null || botToken.isBlank()) {
            log.warn("Telegram Bot Token is not configured (voting.telegram.bot-token). Skipping delivery.");
            return;
        }

        // 1. Calculate tallies from audit package
        List<String> candidates = (List<String>) auditPackage.getOrDefault("candidates", List.of());
        List<Map<String, Object>> ballots = (List<Map<String, Object>>) auditPackage.getOrDefault("ballots", List.of());
        
        Map<String, Integer> tallies = new java.util.HashMap<>();
        for (String c : candidates) {
            tallies.put(c, 0);
        }
        for (Map<String, Object> ballot : ballots) {
            String candidateId = (String) ballot.get("candidate_id");
            if (candidateId != null) {
                String matchedCandidate = candidates.stream()
                        .filter(c -> c.equalsIgnoreCase(candidateId))
                        .findFirst()
                        .orElse(candidateId);
                tallies.put(matchedCandidate, tallies.getOrDefault(matchedCandidate, 0) + 1);
            }
        }

        // 2. Generate a clean and safe Telegram markdown message (avoiding unescaped LaTeX/brackets/etc.)
        StringBuilder sb = new StringBuilder();
        sb.append("🗳️ *Election Results: ").append(title).append("*\n\n");
        sb.append("*Status:* COMPLETED\n");
        sb.append("*Total Votes Cast:* ").append(ballots.size()).append("\n\n");
        
        sb.append("*Results Tally:*\n");
        for (Map.Entry<String, Integer> entry : tallies.entrySet()) {
            sb.append("• ").append(entry.getKey()).append(": ").append(entry.getValue()).append(" votes\n");
        }
        sb.append("\n---\n");
        sb.append("🔒 *Cryptographic Audit:*\n");
        sb.append("The full verification guide, voter nullifiers list, and ZKP audit package can be accessed in the static JSON results file via the API.");

        String messageText = sb.toString();

        if (messageText.length() > 4000) {
            messageText = messageText.substring(0, 3950) + "\n\n...[Truncated]...";
        }

        String url = String.format("https://api.telegram.org/bot%s/sendMessage", botToken);
        Map<String, Object> body = Map.of(
                "chat_id", chatId,
                "text", messageText,
                "parse_mode", "Markdown"
        );

        try {
            restTemplate.postForObject(url, body, String.class);
            log.info("Telegram notification sent successfully to chat: {}", chatId);
        } catch (Exception e) {
            log.error("Failed to send results via Telegram bot", e);
        }
    }
}
