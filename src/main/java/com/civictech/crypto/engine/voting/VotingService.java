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
import software.amazon.awssdk.services.s3.model.*;

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

    // Only used when storageType=local
    private final Path storageRoot;

    private final Map<String, ChallengeSession> activeChallenges = new ConcurrentHashMap<>();
    private static final long SESSION_EXPIRATION_MS = 300_000; // 5 minutes

    private final String storageType;
    private final String bucketName;
    private final S3Client s3Client;

    public record ChallengeSession(String challenge, String publicKeyX, String publicKeyY, long createdAt) {}

    public VotingService(ZkpService zkpService,
                         ObjectMapper objectMapper,
                         List<VotingResultDeliveryService> deliveryServices,
                         @Autowired(required = false) S3Client s3Client,
                         @Value("${voting.storage.type:local}") String storageType,
                         @Value("${voting.storage.b2.bucket-name:}") String bucketName) {
        this.zkpService = zkpService;
        this.objectMapper = objectMapper;
        this.deliveryServices = deliveryServices;
        this.s3Client = s3Client;
        this.storageType = storageType;
        this.bucketName = bucketName;

        // Local filesystem storage is only used when storageType=local.
        // When storageType=b2, all state lives in Backblaze B2 — no local disk needed.
        this.storageRoot = Paths.get("./local-storage/voting");
        if (!isB2()) {
            try {
                Files.createDirectories(storageRoot);
            } catch (IOException e) {
                throw new RuntimeException(
                    "Failed to create local voting storage directory '" + storageRoot.toAbsolutePath() + "'", e);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Storage routing helpers
    // -----------------------------------------------------------------------

    private boolean isB2() {
        return "b2".equalsIgnoreCase(storageType) && s3Client != null;
    }

    /** Read a B2 object as bytes. Returns empty Optional if key does not exist. */
    private Optional<byte[]> b2Get(String key) {
        try {
            ResponseBytes<GetObjectResponse> obj = s3Client.getObjectAsBytes(
                GetObjectRequest.builder().bucket(bucketName).key(key).build());
            return Optional.of(obj.asByteArray());
        } catch (NoSuchKeyException e) {
            return Optional.empty();
        }
    }

    /** Write bytes to a B2 key. */
    private void b2Put(String key, byte[] data, String contentType) {
        s3Client.putObject(PutObjectRequest.builder()
                .bucket(bucketName)
                .key(key)
                .contentType(contentType)
                .build(),
                RequestBody.fromBytes(data));
    }

    /** Returns true if a B2 key exists (zero-byte HEAD). */
    private boolean b2Exists(String key) {
        try {
            s3Client.headObject(HeadObjectRequest.builder().bucket(bucketName).key(key).build());
            return true;
        } catch (NoSuchKeyException e) {
            return false;
        }
    }

    /** List B2 keys under a common prefix. */
    private List<String> b2List(String prefix) {
        List<String> keys = new ArrayList<>();
        ListObjectsV2Response response = s3Client.listObjectsV2(
                ListObjectsV2Request.builder().bucket(bucketName).prefix(prefix).build());
        for (S3Object obj : response.contents()) {
            keys.add(obj.key());
        }
        return keys;
    }

    /** Read + deserialize a JSON object from B2. Returns empty Optional if missing. */
    private Optional<Map<String, Object>> b2GetJson(String key) {
        return b2Get(key).map(bytes -> {
            try {
                return objectMapper.readValue(bytes, Map.class);
            } catch (IOException e) {
                throw new CryptoException("Failed to deserialize B2 object: " + key, e);
            }
        });
    }

    /** Serialize + write a JSON object to B2. */
    private void b2PutJson(String key, Object value) {
        try {
            b2Put(key, objectMapper.writeValueAsBytes(value), "application/json");
        } catch (IOException e) {
            throw new CryptoException("Failed to serialize B2 object: " + key, e);
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

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

        if (isB2()) {
            // All session state lives in B2 — no local disk required
            b2PutJson("voting/" + voteId + "/metadata.json", metadata);
            log.info("Created voting session in B2: {}", voteId);
        } else {
            try {
                Path sessionDir = storageRoot.resolve(voteId);
                Files.createDirectories(sessionDir.resolve("nullifiers"));
                Files.createDirectories(sessionDir.resolve("ballots"));
                Files.writeString(sessionDir.resolve("metadata.json"), objectMapper.writeValueAsString(metadata));
            } catch (IOException e) {
                throw new CryptoException("Failed to create voting session directories", e);
            }
        }

        return new CreateVotingSessionResponse(voteId, expiresAt.toString(), creatorToken);
    }

    public VotingSessionInfo getSessionInfo(String voteId) {
        Map<String, Object> meta;

        if (isB2()) {
            meta = b2GetJson("voting/" + voteId + "/metadata.json")
                    .orElseThrow(() -> new IllegalArgumentException("Voting session not found."));
        } else {
            Path metadataPath = storageRoot.resolve(voteId).resolve("metadata.json");
            if (!Files.exists(metadataPath)) {
                throw new IllegalArgumentException("Voting session not found.");
            }
            try {
                meta = objectMapper.readValue(metadataPath.toFile(), Map.class);
            } catch (IOException e) {
                throw new CryptoException("Failed to read voting session metadata", e);
            }
        }

        Instant expiresAt = Instant.parse((String) meta.get("expires_at"));
        String status = (String) meta.getOrDefault("status", "ACTIVE");
        boolean active = "ACTIVE".equalsIgnoreCase(status) && Instant.now().isBefore(expiresAt);

        return new VotingSessionInfo(
                voteId,
                (String) meta.get("title"),
                (List<String>) meta.get("candidates"),
                expiresAt.toString(),
                active
        );
    }

    public ChallengeResponse generateChallenge(ChallengeRequest request) {
        String voteId = request.voteId().trim();
        String nullifier = request.nullifier().trim().toLowerCase();

        // 1. Verify session exists and is active
        VotingSessionInfo info = getSessionInfo(voteId);
        if (!info.active()) {
            throw new IllegalArgumentException("Voting session has expired or is completed.");
        }

        // 2. Check if nullifier has already voted (double vote prevention)
        boolean nullifierUsed;
        if (isB2()) {
            nullifierUsed = b2Exists("voting/" + voteId + "/nullifiers/" + nullifier);
        } else {
            nullifierUsed = Files.exists(storageRoot.resolve(voteId).resolve("nullifiers").resolve(nullifier));
        }
        if (nullifierUsed) {
            throw new IllegalArgumentException("Voter nullifier has already cast a vote in this session.");
        }

        // 3. Generate random challenge
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        String challengeHex = HexFormat.of().formatHex(challengeBytes);

        // 4. Store active challenge session in-memory (short-lived, 5 min TTL)
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

        // 4. Double Vote Prevention: write nullifier marker atomically
        if (isB2()) {
            if (b2Exists("voting/" + voteId + "/nullifiers/" + nullifier)) {
                throw new IllegalArgumentException("Double voting detected. Nullifier already used.");
            }
            b2Put("voting/" + voteId + "/nullifiers/" + nullifier, new byte[0], "application/octet-stream");
        } else {
            Path nullifierPath = storageRoot.resolve(voteId).resolve("nullifiers").resolve(nullifier);
            try {
                Files.createFile(nullifierPath);
            } catch (IOException e) {
                throw new IllegalArgumentException("Double voting detected. Nullifier already used.");
            }
        }

        // 5. Save ballot anonymously (random UUID decouples vote from nullifier)
        String ballotId = UUID.randomUUID().toString();
        Map<String, Object> ballotData = Map.of(
                "candidate_id", candidateId,
                "commitment_hash", request.commitmentHash(),
                "public_key_x", request.publicKeyX(),
                "public_key_y", request.publicKeyY(),
                "challenge", request.challenge(),
                "response", request.response()
        );

        if (isB2()) {
            b2PutJson("voting/" + voteId + "/ballots/" + ballotId + ".json", ballotData);
        } else {
            Path ballotPath = storageRoot.resolve(voteId).resolve("ballots").resolve(ballotId + ".json");
            try {
                Files.writeString(ballotPath, objectMapper.writeValueAsString(ballotData));
            } catch (IOException e) {
                // Rollback nullifier on ballot write failure (local only)
                try {
                    Files.deleteIfExists(storageRoot.resolve(voteId).resolve("nullifiers").resolve(nullifier));
                } catch (Exception ignored) {}
                throw new CryptoException("Failed to store anonymized ballot.", e);
            }
        }

        // 6. Cleanup challenge session
        activeChallenges.remove(sessionKey);
    }

    public String getResultsUrl(String voteId, String requestScheme, String requestServerName,
                                int requestServerPort, String contextPath) {
        Map<String, Object> meta;
        if (isB2()) {
            meta = b2GetJson("voting/" + voteId + "/metadata.json")
                    .orElseThrow(() -> new IllegalArgumentException("Voting session not found."));
        } else {
            Path metadataPath = storageRoot.resolve(voteId).resolve("metadata.json");
            if (!Files.exists(metadataPath)) {
                throw new IllegalArgumentException("Voting session not found.");
            }
            try {
                meta = objectMapper.readValue(metadataPath.toFile(), Map.class);
            } catch (IOException e) {
                throw new CryptoException("Failed to read voting session metadata", e);
            }
        }

        String status = (String) meta.getOrDefault("status", "ACTIVE");
        if ("ACTIVE".equalsIgnoreCase(status)) {
            Instant expiresAt = Instant.parse((String) meta.get("expires_at"));
            if (Instant.now().isBefore(expiresAt)) {
                throw new IllegalArgumentException("Voting session is still active. Results will be released at " + expiresAt);
            }
            // Expired but not yet finalized — do it now
            try {
                finalizeSession(voteId, meta);
            } catch (IOException e) {
                throw new CryptoException("Failed to finalize voting session", e);
            }
        }

        // Return B2 CDN URL if configured, otherwise fallback to local static endpoint
        String cdnUrl = System.getenv("B2_CDN_URL");
        if (cdnUrl != null && !cdnUrl.isBlank()) {
            return cdnUrl.trim() + "/voting/" + voteId + "/results.json";
        }

        return contextPath + "/v1/voting/static/" + voteId + "/results.json";
    }

    public byte[] getStaticResultsFile(String voteId) {
        if (isB2()) {
            return b2Get("voting/" + voteId + "/results.json")
                    .orElseThrow(() -> new IllegalArgumentException("Finalized results not found."));
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

    // -----------------------------------------------------------------------
    // Finalization
    // -----------------------------------------------------------------------

    private synchronized void finalizeSession(String voteId, Map<String, Object> meta) throws IOException {
        // Re-read metadata to prevent double-finalization
        Map<String, Object> currentMeta;
        if (isB2()) {
            currentMeta = b2GetJson("voting/" + voteId + "/metadata.json")
                    .orElseThrow(() -> new IllegalArgumentException("Voting session not found during finalization."));
        } else {
            Path sessionDir = storageRoot.resolve(voteId);
            currentMeta = objectMapper.readValue(sessionDir.resolve("metadata.json").toFile(), Map.class);
        }

        if ("COMPLETED".equalsIgnoreCase((String) currentMeta.getOrDefault("status", "ACTIVE"))) {
            return;
        }

        log.info("Finalizing voting session: {}", voteId);

        // Collect nullifiers
        List<String> nullifiersList = new ArrayList<>();
        if (isB2()) {
            for (String key : b2List("voting/" + voteId + "/nullifiers/")) {
                nullifiersList.add(key.substring(("voting/" + voteId + "/nullifiers/").length()));
            }
        } else {
            File[] nullifierFiles = storageRoot.resolve(voteId).resolve("nullifiers").toFile().listFiles();
            if (nullifierFiles != null) {
                for (File f : nullifierFiles) nullifiersList.add(f.getName());
            }
        }

        // Collect ballots and tally
        List<Map<String, Object>> ballotsList = new ArrayList<>();
        Map<String, Integer> tallies = new HashMap<>();
        List<String> candidateList = (List<String>) currentMeta.get("candidates");
        for (String candidate : candidateList) {
            tallies.put(candidate.toLowerCase(), 0);
        }

        int totalVotes = 0;
        if (isB2()) {
            for (String key : b2List("voting/" + voteId + "/ballots/")) {
                b2Get(key).ifPresent(bytes -> {
                    try {
                        ballotsList.add(objectMapper.readValue(bytes, Map.class));
                    } catch (IOException e) {
                        log.warn("Failed to deserialize ballot from B2 key: {}", key, e);
                    }
                });
            }
        } else {
            File[] ballotFiles = storageRoot.resolve(voteId).resolve("ballots").toFile().listFiles();
            if (ballotFiles != null) {
                for (File f : ballotFiles) {
                    ballotsList.add(objectMapper.readValue(f, Map.class));
                }
            }
        }

        for (Map<String, Object> ballot : ballotsList) {
            String candidateId = ((String) ballot.get("candidate_id")).toLowerCase();
            if (tallies.containsKey(candidateId)) {
                tallies.put(candidateId, tallies.get(candidateId) + 1);
                totalVotes++;
            }
        }

        Map<String, Object> auditPackage = Map.of(
                "candidates", candidateList,
                "nullifiers", nullifiersList,
                "ballots", ballotsList
        );

        String verificationGuide = generateVerificationGuideMarkdown(currentMeta, tallies, totalVotes, auditPackage);

        VotingResultsResponse resultsResponse = new VotingResultsResponse(
                "COMPLETED",
                (String) currentMeta.get("title"),
                (String) currentMeta.get("expires_at"),
                tallies,
                totalVotes,
                auditPackage,
                verificationGuide
        );

        byte[] resultsBytes = objectMapper.writeValueAsBytes(resultsResponse);

        if (isB2()) {
            log.info("Uploading finalized results to Backblaze B2 bucket '{}' key 'voting/{}/results.json'", bucketName, voteId);
            b2Put("voting/" + voteId + "/results.json", resultsBytes, "application/json");
            log.info("Successfully uploaded results to Backblaze B2!");

            // Update metadata status in B2
            Map<String, Object> updatedMeta = new HashMap<>(currentMeta);
            updatedMeta.put("status", "COMPLETED");
            b2PutJson("voting/" + voteId + "/metadata.json", updatedMeta);

            // Delete individual ballot and nullifier objects from B2 (ephemeral by design)
            for (String key : b2List("voting/" + voteId + "/ballots/")) {
                try { s3Client.deleteObject(DeleteObjectRequest.builder().bucket(bucketName).key(key).build()); }
                catch (Exception e) { log.warn("Failed to delete B2 ballot object: {}", key, e); }
            }
            for (String key : b2List("voting/" + voteId + "/nullifiers/")) {
                try { s3Client.deleteObject(DeleteObjectRequest.builder().bucket(bucketName).key(key).build()); }
                catch (Exception e) { log.warn("Failed to delete B2 nullifier object: {}", key, e); }
            }
        } else {
            Path sessionDir = storageRoot.resolve(voteId);
            log.info("Writing finalized results to local storage for voteId: {}", voteId);
            Files.write(sessionDir.resolve("results.json"), resultsBytes);

            Map<String, Object> updatedMeta = new HashMap<>(currentMeta);
            updatedMeta.put("status", "COMPLETED");
            Files.writeString(sessionDir.resolve("metadata.json"), objectMapper.writeValueAsString(updatedMeta));

            deleteDirectory(sessionDir.resolve("ballots").toFile());
            deleteDirectory(sessionDir.resolve("nullifiers").toFile());
        }

        // Deliver results via configured delivery channels
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

    // -----------------------------------------------------------------------
    // Background expiry scanner
    // -----------------------------------------------------------------------

    @Scheduled(fixedRate = 15000) // Run every 15 seconds to detect expired sessions
    public void scanAndFinalizeExpiredSessions() {
        if (isB2()) {
            // Scan all metadata.json objects in the B2 bucket under the voting prefix
            List<String> metadataKeys = b2List("voting/");
            for (String key : metadataKeys) {
                if (!key.endsWith("/metadata.json")) continue;
                String voteId = key.substring("voting/".length(), key.indexOf("/metadata.json"));
                try {
                    Map<String, Object> meta = b2GetJson(key).orElse(null);
                    if (meta == null) continue;
                    String status = (String) meta.getOrDefault("status", "ACTIVE");
                    if ("ACTIVE".equalsIgnoreCase(status)) {
                        Instant expiresAt = Instant.parse((String) meta.get("expires_at"));
                        if (Instant.now().isAfter(expiresAt)) {
                            finalizeSession(voteId, meta);
                        }
                    }
                } catch (Exception e) {
                    log.error("Error processing auto-finalization for B2 session: {}", voteId, e);
                }
            }
        } else {
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
    }


    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void deleteDirectory(File directoryToBeDeleted) {
        File[] allContents = directoryToBeDeleted.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectory(file);
            }
        }
        directoryToBeDeleted.delete();
    }

    private String generateVerificationGuideMarkdown(Map<String, Object> metadata, Map<String, Integer> tallies,
                                                      int totalVotes, Map<String, Object> auditPackage) {
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
