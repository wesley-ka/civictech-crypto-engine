package com.civictech.crypto.engine.voting;

import com.civictech.crypto.engine.error.CryptoException;
import com.civictech.crypto.engine.identity.ZkpService;
import com.civictech.crypto.engine.identity.dto.ZkpVerifyRequest;
import com.civictech.crypto.engine.identity.dto.ZkpVerifyResponse;
import com.civictech.crypto.engine.voting.dto.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HexFormat;

@Service
public class VotingService {

    private static final Logger log = LoggerFactory.getLogger(VotingService.class);

    private final ZkpService zkpService;
    private final ObjectMapper objectMapper;
    private final List<VotingResultDeliveryService> deliveryServices;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Path storageRoot = Paths.get("./voting-storage");

    private final Map<String, ChallengeSession> activeChallenges = new ConcurrentHashMap<>();
    private static final long SESSION_EXPIRATION_MS = 300_000; // 5 minutes

    @Value("${voting.storage.type:local}")
    private String storageType;

    @Value("${voting.storage.b2.bucket-name:}")
    private String bucketName;

    private final S3Client s3Client;

    public record ChallengeSession(String challenge, String publicKeyX, String publicKeyY, long createdAt) {}

    public VotingService(ZkpService zkpService,
                         ObjectMapper objectMapper,
                         List<VotingResultDeliveryService> deliveryServices,
                         @Autowired(required = false) S3Client s3Client) {
        this.zkpService = zkpService;
        this.objectMapper = objectMapper;
        this.deliveryServices = deliveryServices;
        this.s3Client = s3Client;
        // In cloud environments (e.g. Cloud Run) the filesystem may be read-only.
        // Local directory creation is best-effort: a warning is logged on failure
        // rather than crashing startup. When B2 is configured, local storage is
        // not required for normal operation.
        try {
            Files.createDirectories(storageRoot);
        } catch (IOException e) {
            log.warn("Could not create local voting-storage directory ({}). " +
                     "This is expected in read-only cloud environments when B2 storage is configured. " +
                     "Error: {}", storageRoot.toAbsolutePath(), e.getMessage());
        }
    }

    public CreateVotingSessionResponse createSession(CreateVotingSessionRequest request) {
        String voteId = UUID.randomUUID().toString();
        Instant expiresAt = Instant.now().plusSeconds(request.durationMinutes() * 60L);
        String creatorToken = "ct_" + HexFormat.of().formatHex(secureRandom.generateSeed(16));

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("vote_id", voteId);
        metadata.put("title", request.title());
        metadata.put("candidates", request.candidates());
        metadata.put("expires_at", expiresAt.toString());
        metadata.put("creator_token", creatorToken);
        metadata.put("delivery_target", request.deliveryTarget() != null ? request.deliveryTarget().trim() : "");
        metadata.put("status", "ACTIVE");

        try {
            Path sessionDir = storageRoot.resolve(voteId);
            Files.createDirectories(sessionDir.resolve("nullifiers"));
            Files.createDirectories(sessionDir.resolve("ballots"));

            // Write metadata file
            Files.writeString(sessionDir.resolve("metadata.json"), objectMapper.writeValueAsString(metadata));
        } catch (IOException e) {
            throw new CryptoException("Failed to create voting session directories", e);
        }

        return new CreateVotingSessionResponse(voteId, expiresAt.toString(), creatorToken);
    }

    public VotingSessionInfo getSessionInfo(String voteId) {
        Path metadataPath = storageRoot.resolve(voteId).resolve("metadata.json");
        if (!Files.exists(metadataPath)) {
            throw new IllegalArgumentException("Voting session not found.");
        }

        try {
            Map<String, Object> meta = objectMapper.readValue(metadataPath.toFile(), Map.class);
            Instant expiresAt = Instant.parse((String) meta.get("expires_at"));
            
            // Check active status
            String status = (String) meta.getOrDefault("status", "ACTIVE");
            boolean active = "ACTIVE".equalsIgnoreCase(status) && Instant.now().isBefore(expiresAt);

            return new VotingSessionInfo(
                    voteId,
                    (String) meta.get("title"),
                    (List<String>) meta.get("candidates"),
                    expiresAt.toString(),
                    active
            );
        } catch (IOException e) {
            throw new CryptoException("Failed to read voting session metadata", e);
        }
    }

    public ChallengeResponse generateChallenge(ChallengeRequest request) {
        String voteId = request.voteId().trim();
        String nullifier = request.nullifier().trim().toLowerCase();
        
        // 1. Verify session exists and is active
        VotingSessionInfo info = getSessionInfo(voteId);
        if (!info.active()) {
            throw new IllegalArgumentException("Voting session has expired or is completed.");
        }

        // 2. Check if nullifier has already voted (Double voting prevention)
        Path nullifierPath = storageRoot.resolve(voteId).resolve("nullifiers").resolve(nullifier);
        if (Files.exists(nullifierPath)) {
            throw new IllegalArgumentException("Voter nullifier has already cast a vote in this session.");
        }

        // 3. Generate random challenge
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        String challengeHex = HexFormat.of().formatHex(challengeBytes);

        // 4. Store active challenge session in-memory
        String sessionKey = voteId + ":" + nullifier;
        activeChallenges.put(sessionKey, new ChallengeSession(
                challengeHex,
                request.publicKeyX().trim(),
                request.publicKeyY().trim(),
                Instant.now().toEpochMilli()
        ));

        return new ChallengeResponse(challengeHex);
    }

    public void castVote(CastVoteRequest request) {
        String voteId = request.voteId().trim();
        String nullifier = request.nullifier().trim().toLowerCase();
        String candidateId = request.candidateId().trim().toLowerCase();

        // 1. Verify session active
        VotingSessionInfo info = getSessionInfo(voteId);
        if (!info.active()) {
            throw new IllegalArgumentException("Voting session has expired or is completed.");
        }

        boolean candidateValid = info.candidates().stream()
                .anyMatch(c -> c.trim().equalsIgnoreCase(request.candidateId().trim()));
        if (!candidateValid) {
            throw new IllegalArgumentException("Candidate is not valid in this session.");
        }

        // 2. Check active challenge session
        String sessionKey = voteId + ":" + nullifier;
        ChallengeSession challengeSession = activeChallenges.get(sessionKey);
        if (challengeSession == null) {
            throw new IllegalArgumentException("No challenge session found for this nullifier.");
        }

        if (Instant.now().toEpochMilli() - challengeSession.createdAt() > SESSION_EXPIRATION_MS) {
            activeChallenges.remove(sessionKey);
            throw new IllegalArgumentException("Challenge has expired. Request a new one.");
        }

        if (!challengeSession.challenge().equalsIgnoreCase(request.challenge().trim())) {
            throw new IllegalArgumentException("Challenge mismatch.");
        }

        if (!challengeSession.publicKeyX().equalsIgnoreCase(request.publicKeyX().trim()) ||
            !challengeSession.publicKeyY().equalsIgnoreCase(request.publicKeyY().trim())) {
            throw new IllegalArgumentException("Public key mismatch with challenge session.");
        }

        // 3. Verify ZKP math using Bouncy Castle
        ZkpVerifyRequest zkpRequest = new ZkpVerifyRequest(
                request.commitmentHash(),
                request.commitmentX(),
                request.commitmentY(),
                request.challenge(),
                request.response(),
                request.publicKeyX(),
                request.publicKeyY(),
                request.basePointX(),
                request.basePointY()
        );

        ZkpVerifyResponse zkpResponse = zkpService.verifyZkp(zkpRequest);
        if (!zkpResponse.verified()) {
            throw new CryptoException("Invalid zero-knowledge proof verification failed.");
        }

        // 4. Double Vote Prevention: Write nullifier atomically
        Path nullifierPath = storageRoot.resolve(voteId).resolve("nullifiers").resolve(nullifier);
        try {
            Files.createFile(nullifierPath);
        } catch (IOException e) {
            throw new IllegalArgumentException("Double voting detected. Nullifier already used.");
        }

        // 5. Save ballot anonymously (Write to a random UUID to decouple vote from nullifier)
        String ballotId = UUID.randomUUID().toString();
        Path ballotPath = storageRoot.resolve(voteId).resolve("ballots").resolve(ballotId + ".json");
        
        Map<String, Object> ballotData = Map.of(
                "candidate_id", candidateId,
                "commitment_hash", request.commitmentHash(),
                "public_key_x", request.publicKeyX(),
                "public_key_y", request.publicKeyY(),
                "challenge", request.challenge(),
                "response", request.response()
        );

        try {
            Files.writeString(ballotPath, objectMapper.writeValueAsString(ballotData));
        } catch (IOException e) {
            try { Files.deleteIfExists(nullifierPath); } catch (Exception ignored) {}
            throw new CryptoException("Failed to store anonymized ballot.", e);
        }

        // 6. Cleanup challenge session
        activeChallenges.remove(sessionKey);
    }

    public String getResultsUrl(String voteId, String requestScheme, String requestServerName, int requestServerPort, String contextPath) {
        Path sessionDir = storageRoot.resolve(voteId);
        Path metadataPath = sessionDir.resolve("metadata.json");
        if (!Files.exists(metadataPath)) {
            throw new IllegalArgumentException("Voting session not found.");
        }

        try {
            Map<String, Object> meta = objectMapper.readValue(metadataPath.toFile(), Map.class);
            
            // Check status. If completed, load direct results
            String status = (String) meta.getOrDefault("status", "ACTIVE");
            if ("ACTIVE".equalsIgnoreCase(status)) {
                Instant expiresAt = Instant.parse((String) meta.get("expires_at"));
                if (Instant.now().isBefore(expiresAt)) {
                    throw new IllegalArgumentException("Voting session is still active. Results will be released at " + expiresAt);
                }
                // If expired but not marked completed, finalize now
                finalizeSession(voteId, meta);
            }

            // Return S3/B2 CDN URL if configured, otherwise fallback to local redirect
            String cdnUrl = System.getenv("B2_CDN_URL");
            if (cdnUrl != null && !cdnUrl.isBlank()) {
                return cdnUrl.trim() + "/" + voteId + "/results.json";
            }

            // Local fallback redirect URL (relative path to preserve proxying/origins)
            return contextPath + "/v1/voting/static/" + voteId + "/results.json";

        } catch (IOException e) {
            throw new CryptoException("Failed to read voting session metadata", e);
        }
    }

    public byte[] getStaticResultsFile(String voteId) {
        if ("b2".equalsIgnoreCase(storageType) && s3Client != null) {
            try {
                log.info("Fetching static results from Backblaze B2 for voteId: {}", voteId);
                ResponseBytes<GetObjectResponse> s3Object = s3Client.getObjectAsBytes(GetObjectRequest.builder()
                        .bucket(bucketName)
                        .key(voteId + "/results.json")
                        .build());
                return s3Object.asByteArray();
            } catch (Exception e) {
                log.warn("Failed to fetch static results from B2 for voteId: {}, falling back to local file checks", voteId, e);
            }
        }

        Path path = storageRoot.resolve(voteId).resolve("results.json");
        if (!Files.exists(path)) {
            throw new IllegalArgumentException("Finalized results not found.");
        }
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new CryptoException("Failed to read static results file", e);
        }
    }

    private synchronized void finalizeSession(String voteId, Map<String, Object> meta) throws IOException {
        Path sessionDir = storageRoot.resolve(voteId);
        
        // Re-read metadata to ensure no double-finalization
        Map<String, Object> currentMeta = objectMapper.readValue(sessionDir.resolve("metadata.json").toFile(), Map.class);
        if ("COMPLETED".equalsIgnoreCase((String) currentMeta.getOrDefault("status", "ACTIVE"))) {
            return;
        }

        log.info("Finalizing voting session: {}", voteId);

        // Read all nullifiers
        File[] nullifierFiles = sessionDir.resolve("nullifiers").toFile().listFiles();
        List<String> nullifiersList = new ArrayList<>();
        if (nullifierFiles != null) {
            for (File f : nullifierFiles) {
                nullifiersList.add(f.getName());
            }
        }

        // Read all ballots and calculate tallies
        File[] ballotFiles = sessionDir.resolve("ballots").toFile().listFiles();
        List<Map<String, Object>> ballotsList = new ArrayList<>();
        Map<String, Integer> tallies = new HashMap<>();
        
        List<String> candidateList = (List<String>) currentMeta.get("candidates");
        for (String candidate : candidateList) {
            tallies.put(candidate.toLowerCase(), 0);
        }

        int totalVotes = 0;
        if (ballotFiles != null) {
            for (File f : ballotFiles) {
                Map<String, Object> ballot = objectMapper.readValue(f, Map.class);
                ballotsList.add(ballot);
                String candidateId = ((String) ballot.get("candidate_id")).toLowerCase();
                if (tallies.containsKey(candidateId)) {
                    tallies.put(candidateId, tallies.get(candidateId) + 1);
                    totalVotes++;
                }
            }
        }

        Map<String, Object> auditPackage = Map.of(
                "candidates", candidateList,
                "nullifiers", nullifiersList,
                "ballots", ballotsList
        );

        String verificationGuide = generateVerificationGuideMarkdown(currentMeta, tallies, totalVotes, auditPackage);

        // Create results payload
        VotingResultsResponse resultsResponse = new VotingResultsResponse(
                "COMPLETED",
                (String) currentMeta.get("title"),
                (String) currentMeta.get("expires_at"),
                tallies,
                totalVotes,
                auditPackage,
                verificationGuide
        );

        // Write results.json file to Backblaze B2 (falling back to local storage if disabled or fails)
        boolean uploadedToB2 = false;
        byte[] resultsBytes = objectMapper.writeValueAsBytes(resultsResponse);

        if ("b2".equalsIgnoreCase(storageType) && s3Client != null) {
            try {
                log.info("Uploading finalized results to Backblaze B2 bucket '{}' key '{}/results.json'", bucketName, voteId);
                s3Client.putObject(PutObjectRequest.builder()
                        .bucket(bucketName)
                        .key(voteId + "/results.json")
                        .contentType("application/json")
                        .build(),
                        RequestBody.fromBytes(resultsBytes));
                uploadedToB2 = true;
                log.info("Successfully uploaded results to Backblaze B2!");
            } catch (Exception e) {
                log.error("Failed to upload finalized results to Backblaze B2 (falling back to local storage)", e);
            }
        }

        if (!uploadedToB2) {
            log.info("Writing finalized results to local storage fallback for voteId: {}", voteId);
            Files.write(sessionDir.resolve("results.json"), resultsBytes);
        }

        // Update metadata status
        Map<String, Object> updatedMeta = new HashMap<>(currentMeta);
        updatedMeta.put("status", "COMPLETED");
        Files.writeString(sessionDir.resolve("metadata.json"), objectMapper.writeValueAsString(updatedMeta));

        // Purge individual ballots and nullifiers folders (Ephemeral Storage savings)
        deleteDirectory(sessionDir.resolve("ballots").toFile());
        deleteDirectory(sessionDir.resolve("nullifiers").toFile());

        // Deliver results if delivery target exists
        String deliveryTarget = (String) currentMeta.getOrDefault("delivery_target", "");
        if (deliveryTarget != null && !deliveryTarget.isBlank()) {
            for (VotingResultDeliveryService service : deliveryServices) {
                if (service.supports(deliveryTarget)) {
                    try {
                        service.deliver(deliveryTarget, (String) currentMeta.get("title"), auditPackage, verificationGuide);
                    } catch (Exception e) {
                        log.error("Failed to deliver results to target: {}", deliveryTarget, e);
                    }
                }
            }
        }
    }

    @Scheduled(fixedRate = 15000) // Run every 15 seconds to detect expired sessions
    public void scanAndFinalizeExpiredSessions() {
        File[] sessionDirs = storageRoot.toFile().listFiles(File::isDirectory);
        if (sessionDirs == null) return;

        for (File dir : sessionDirs) {
            Path metadataPath = dir.toPath().resolve("metadata.json");
            if (Files.exists(metadataPath)) {
                try {
                    Map<String, Object> meta = objectMapper.readValue(metadataPath.toFile(), Map.class);
                    String status = (String) meta.getOrDefault("status", "ACTIVE");
                    if ("ACTIVE".equalsIgnoreCase(status)) {
                        Instant expiresAt = Instant.parse((String) meta.get("expires_at"));
                        if (Instant.now().isAfter(expiresAt)) {
                            finalizeSession(dir.getName(), meta);
                        }
                    }
                } catch (Exception e) {
                    log.error("Error processing auto-finalization for session: {}", dir.getName(), e);
                }
            }
        }
    }

    private void deleteDirectory(File directoryToBeDeleted) {
        File[] allContents = directoryToBeDeleted.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectory(file);
            }
        }
        directoryToBeDeleted.delete();
    }

    private String generateVerificationGuideMarkdown(Map<String, Object> metadata, Map<String, Integer> tallies, int totalVotes, Map<String, Object> auditPackage) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Cryptographic Election Audit Report\n\n");
        sb.append("This report contains the raw mathematical proofs and audit trail for the election: **").append(metadata.get("title")).append("**.\n");
        sb.append("To maximize public trust, this election has been executed using a Zero-Knowledge Proof (ZKP) verification scheme over NIST P-256 (secp256r1).\n\n");
        
        sb.append("## Election Summary\n");
        sb.append("*   **Vote Session ID:** `").append(metadata.get("vote_id")).append("`\n");
        sb.append("*   **Expires At:** `").append(metadata.get("expires_at")).append("`\n");
        sb.append("*   **Total Cast Ballots:** `").append(totalVotes).append("`\n\n");

        sb.append("## Election Results\n");
        sb.append("| Candidate | Votes Received |\n");
        sb.append("| :--- | :--- |\n");
        for (Map.Entry<String, Integer> entry : tallies.entrySet()) {
            sb.append("| ").append(entry.getKey()).append(" | ").append(entry.getValue()).append(" |\n");
        }
        sb.append("\n");

        sb.append("## How to Verify the Integrity of This Election\n");
        sb.append("The integrity of this voting session rests on three mathematical layers. Any citizen or auditor can execute verification scripts using the raw JSON audit package supplied alongside this guide:\n\n");
        
        sb.append("### 1. Verification of Voter Eligibility and One-Vote Constraint\n");
        sb.append("We verify that the number of ballots matches the list of unique voter nullifiers. If a nullifier is reused, it is blocked at the storage layer. \n");
        sb.append("- Check that the count of unique hashes in `audit_package.nullifiers` equals `audit_package.ballots` length.\n");
        sb.append("- Ensure there are no duplicate nullifiers in the list.\n\n");

        sb.append("### 2. Verification of Schnorr Signatures (ZKPs)\n");
        sb.append("Every ballot contains a non-interactive proof showing knowledge of the private key matching the public key $(X, Y)$ of an authorized voter, without revealing the private key. For every ballot in `audit_package.ballots`, you must verify:\n");
        sb.append("$$s \\cdot G == R + c \\cdot Y$$\n");
        sb.append("Where:\n");
        sb.append("- $G$ is the standard secp256r1 generator point.\n");
        sb.append("- $Y = (\\text{public\\_key\\_x}, \\text{public\\_key\\_y})$ is the voter's public key.\n");
        sb.append("- $R = (\\text{commitment\\_x}, \\text{commitment\\_y})$ is reconstructed using the commitment hash.\n");
        sb.append("- $c$ is the scalar challenge sent by the server.\n");
        sb.append("- $s$ is the scalar response of the prover.\n\n");
        
        sb.append("### 3. Anonymity Verification (No-Link Audit)\n");
        sb.append("Because the `nullifiers` are registered in an isolated directory and the `ballots` are stored as randomized JSON objects with no metadata linking them back to the nullifier, there is zero correlation between a voter's public identifier and their actual candidate selection. An auditor can verify that the list of ballots contains no matching timestamps, indexing, or transaction logs that link them to specific nullifiers.");

        return sb.toString();
    }
}
