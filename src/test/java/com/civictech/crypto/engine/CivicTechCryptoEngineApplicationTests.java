package com.civictech.crypto.engine;

import com.civictech.crypto.engine.certificates.CertificateService;
import com.civictech.crypto.engine.certificates.dto.ParseCertificateRequest;
import com.civictech.crypto.engine.certificates.dto.ParseCertificateResponse;
import com.civictech.crypto.engine.identity.ZkpService;
import com.civictech.crypto.engine.identity.dto.ZkpVerifyRequest;
import com.civictech.crypto.engine.identity.dto.ZkpVerifyResponse;
import com.civictech.crypto.engine.voting.VotingService;
import com.civictech.crypto.engine.voting.dto.*;
import com.civictech.crypto.engine.identity.vc.VcService;
import com.civictech.crypto.engine.identity.vc.dto.*;
import com.civictech.crypto.engine.ledger.LedgerService;
import com.civictech.crypto.engine.ledger.dto.*;
import com.civictech.crypto.engine.cleanup.StorageCleanupService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import com.civictech.crypto.engine.signing.SigningService;
import com.civictech.crypto.engine.signing.dto.SignRequest;
import com.civictech.crypto.engine.signing.dto.SignResponse;
import com.civictech.crypto.engine.signing.dto.VerifyRequest;
import com.civictech.crypto.engine.signing.dto.VerifyResponse;
import com.civictech.crypto.engine.tsa.TsaService;
import com.civictech.crypto.engine.tsa.dto.TimestampRequest;
import com.civictech.crypto.engine.tsa.dto.TimestampResponse;
import com.civictech.crypto.engine.vault.VaultService;
import com.civictech.crypto.engine.vault.dto.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;


import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@AutoConfigureMockMvc
class CivicTechCryptoEngineApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SigningService signingService;

    @Autowired
    private ZkpService zkpService;

    @Autowired
    private VaultService vaultService;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private TsaService tsaService;

    @Autowired
    private VotingService votingService;

    @Autowired
    private VcService vcService;

    @Autowired
    private LedgerService ledgerService;

    @Autowired
    private StorageCleanupService storageCleanupService;

    @Autowired
    private com.fasterxml.jackson.databind.ObjectMapper objectMapper;

    @Autowired(required = false)
    private S3Client s3Client;

    @Value("${voting.storage.type:local}")
    private String storageType;

    @Value("${voting.storage.b2.bucket-name:}")
    private String bucketName;


    @Test
    void contextLoads() {
        // Verifies Spring context bootstraps correctly
    }

    @Test
    void testModule1_SigningAndVerification() {
        // Sign raw payload
        String testPayloadBase64 = Base64.getEncoder().encodeToString("CivicTech Digital Sign Test".getBytes());
        SignRequest signRequest = new SignRequest(null, testPayloadBase64);
        SignResponse signResponse = signingService.sign(signRequest);

        assertNotNull(signResponse.signature());
        assertNotNull(signResponse.publicKeyX());
        assertNotNull(signResponse.publicKeyY());
        assertEquals("SHA256withECDSA", signResponse.algorithm());

        // Verify signature
        VerifyRequest verifyRequest = new VerifyRequest(
                testPayloadBase64,
                false,
                signResponse.signature(),
                signResponse.publicKeyX(),
                signResponse.publicKeyY()
        );
        VerifyResponse verifyResponse = signingService.verify(verifyRequest);

        assertTrue(verifyResponse.valid());
        assertEquals("CivicTech Digital Signing Engine", verifyResponse.issuer());
    }

    @Test
    void testModule2_ZeroKnowledgeAgeVerifier() throws Exception {
        // Mathematically generate a valid Schnorr proof over secp256r1
        org.bouncycastle.asn1.x9.X9ECParameters curveParams = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256r1");
        ECPoint g = curveParams.getG();
        BigInteger n = curveParams.getN();

        // Citizen secret credential private key x, public key Y = x * G
        BigInteger x = new BigInteger("98765432101234567890");
        ECPoint y = g.multiply(x).normalize();

        // Ephemeral nonce k, commitment point R = k * G
        BigInteger k = new BigInteger("1234567890987654321");
        ECPoint r = g.multiply(k).normalize();

        // Commitment hash
        byte[] rEncoded = r.getEncoded(true);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] computedRHash = digest.digest(rEncoded);
        String commitmentHash = Hex.toHexString(computedRHash);

        // Challenge c
        BigInteger c = new BigInteger("9999");

        // Response s = k + c * x (mod n)
        BigInteger s = k.add(c.multiply(x)).mod(n);

        // Map request
        ZkpVerifyRequest request = new ZkpVerifyRequest(
                commitmentHash,
                r.getAffineXCoord().toBigInteger().toString(16),
                r.getAffineYCoord().toBigInteger().toString(16),
                c.toString(16),
                s.toString(16),
                y.getAffineXCoord().toBigInteger().toString(16),
                y.getAffineYCoord().toBigInteger().toString(16),
                g.getAffineXCoord().toBigInteger().toString(16),
                g.getAffineYCoord().toBigInteger().toString(16)
        );

        ZkpVerifyResponse response = zkpService.verifyZkp(request);
        assertTrue(response.verified(), "Schnorr mathematical proof verification failed.");
        assertFalse(response.proofLog().isEmpty());
    }

    @Test
    void testModule3_VaultAndAuditTrail() {
        // Encryption
        Map<String, Object> testData = Map.of("key1", "value1", "key2", 12345);
        EncryptRequest encryptRequest = new EncryptRequest(testData);
        EncryptResponse encryptResponse = vaultService.encrypt(encryptRequest);

        assertNotNull(encryptResponse.ciphertext());
        assertNotNull(encryptResponse.iv());
        assertNotNull(encryptResponse.authTag());

        // Decryption
        DecryptRequest decryptRequest = new DecryptRequest(
                encryptResponse.ciphertext(),
                encryptResponse.iv(),
                encryptResponse.authTag()
        );
        DecryptResponse decryptResponse = vaultService.decrypt(decryptRequest);
        assertNotNull(decryptResponse.decryptedData());
        assertEquals("value1", decryptResponse.decryptedData().get("key1"));
        assertEquals(12345, decryptResponse.decryptedData().get("key2"));

        // Audit Trail
        AuditRequest auditRequest1 = new AuditRequest("ACTION_STORE_DATA");
        AuditResponse auditResponse1 = vaultService.audit(auditRequest1);
        assertNotNull(auditResponse1.blockHash());
        assertNotNull(auditResponse1.merkleRoot());

        AuditRequest auditRequest2 = new AuditRequest("ACTION_MODIFY_DATA");
        AuditResponse auditResponse2 = vaultService.audit(auditRequest2);
        assertNotEquals(auditResponse1.blockHash(), auditResponse2.blockHash());
        assertNotEquals(auditResponse1.merkleRoot(), auditResponse2.merkleRoot());
    }

    @Test
    void testModule4_CertificateParser() throws Exception {
        // Dynamically generate a self-signed X.509 certificate for parser validation
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        X500Name name = new X500Name("CN=Citizen Juana, O=CivicTech, C=ES");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date from = new Date();
        Date to = new Date(from.getTime() + 1000L * 60 * 60 * 24); // 1 day

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                name, serial, from, to, name, keyPair.getPublic());

        // Add Key Usage (Digital Signature, Non Repudiation)
        org.bouncycastle.asn1.x509.KeyUsage usage = new org.bouncycastle.asn1.x509.KeyUsage(
                org.bouncycastle.asn1.x509.KeyUsage.digitalSignature | org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation);
        certBuilder.addExtension(Extension.keyUsage, true, usage);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        String certBase64 = Base64.getEncoder().encodeToString(certHolder.getEncoded());

        // Parse and check
        ParseCertificateRequest request = new ParseCertificateRequest(certBase64);
        ParseCertificateResponse response = certificateService.parseCertificate(request);

        assertNotNull(response.subjectDn());
        assertNotNull(response.issuerDn());
        assertEquals(serial.toString(16).toUpperCase(), response.serialNumber());
        assertTrue(response.keyUsage().contains("digitalSignature"));
        assertTrue(response.keyUsage().contains("nonRepudiation"));
        assertFalse(response.isExpired());
        assertTrue(response.signatureValid()); // Since it's self-signed, parser should verify signature
    }

    @Test
    void testModule5_TsaService() {
        String testHashHex = Hex.toHexString(new byte[32]); // Dummy SHA-256 hash (32 bytes)
        TimestampRequest request = new TimestampRequest(testHashHex, "1A2B3C4D");
        TimestampResponse response = tsaService.generateTimestamp(request);

        assertNotNull(response.tokenBase64());
        assertNotNull(response.serialNumber());
        assertNotNull(response.timestamp());
        assertEquals("1A2B3C4D", response.nonce());
        assertEquals("SHA-256", response.hashAlgorithm());
        assertEquals(testHashHex, response.documentHash());
        assertNotNull(response.signature());
    }

    @Test
    void testModule6_ZkpVotingService() throws Exception {
        // 1. Create a voting session
        CreateVotingSessionRequest createReq = new CreateVotingSessionRequest(
                "Test Election",
                List.of("Alice", "Bob", "Charlie"),
                1, // 1 minute
                "telegram:123456"
        );
        CreateVotingSessionResponse createRes = votingService.createSession(createReq);
        String voteId = createRes.voteId();
        assertNotNull(voteId);

        // 2. Fetch info and verify active
        VotingSessionInfo info = votingService.getSessionInfo(voteId);
        assertTrue(info.active());
        assertEquals("Test Election", info.title());

        // 3. Verify early results retrieval throws exception
        assertThrows(IllegalArgumentException.class, () -> votingService.getResultsUrl(voteId, "http", "localhost", 8080, "/api"));

        // 4. Mathematically generate a valid Schnorr proof over secp256r1
        org.bouncycastle.asn1.x9.X9ECParameters curveParams = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256r1");
        org.bouncycastle.math.ec.ECPoint g = curveParams.getG();
        BigInteger n = curveParams.getN();

        BigInteger x = new BigInteger("98765432101234567890");
        org.bouncycastle.math.ec.ECPoint y = g.multiply(x).normalize();

        // 5. Request a challenge
        String nullifier = "nullifier-test-hash-123";
        ChallengeRequest challengeReq = new ChallengeRequest(
                voteId,
                nullifier,
                y.getAffineXCoord().toBigInteger().toString(16),
                y.getAffineYCoord().toBigInteger().toString(16)
        );
        ChallengeResponse challengeRes = votingService.generateChallenge(challengeReq);
        String challengeHex = challengeRes.challenge();
        assertNotNull(challengeHex);

        // 6. Generate proof response s = k + c * x (mod n)
        BigInteger k = new BigInteger("1234567890987654321");
        org.bouncycastle.math.ec.ECPoint r = g.multiply(k).normalize();
        byte[] rEncoded = r.getEncoded(true);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] computedRHash = digest.digest(rEncoded);
        String commitmentHash = Hex.toHexString(computedRHash);

        BigInteger c = new BigInteger(challengeHex, 16);
        BigInteger s = k.add(c.multiply(x)).mod(n);

        // 7. Cast vote
        CastVoteRequest castReq = new CastVoteRequest(
                voteId,
                nullifier,
                "Alice",
                commitmentHash,
                r.getAffineXCoord().toBigInteger().toString(16),
                r.getAffineYCoord().toBigInteger().toString(16),
                challengeHex,
                s.toString(16),
                y.getAffineXCoord().toBigInteger().toString(16),
                y.getAffineYCoord().toBigInteger().toString(16),
                null,
                null
        );
        votingService.castVote(castReq);

        // 8. Verify double-voting is rejected
        assertThrows(IllegalArgumentException.class, () -> votingService.castVote(castReq));

        // 9. Manually expire the session by modifying metadata.json
        Map<String, Object> metadataMap;
        boolean isB2Storage = "b2".equalsIgnoreCase(storageType) && s3Client != null;
        if (isB2Storage) {
            String s3Key = "voting/" + voteId + "/metadata.json";
            ResponseBytes<GetObjectResponse> obj = s3Client.getObjectAsBytes(
                GetObjectRequest.builder().bucket(bucketName).key(s3Key).build());
            metadataMap = objectMapper.readValue(obj.asByteArray(), Map.class);
            metadataMap.put("expires_at", Instant.now().minusSeconds(10).toString());
            s3Client.putObject(PutObjectRequest.builder()
                .bucket(bucketName).key(s3Key).contentType("application/json").build(),
                RequestBody.fromBytes(objectMapper.writeValueAsBytes(metadataMap)));
        } else {
            Path metadataPath = Paths.get("./local-storage/voting").resolve(voteId).resolve("metadata.json");
            metadataMap = objectMapper.readValue(metadataPath.toFile(), Map.class);
            metadataMap.put("expires_at", Instant.now().minusSeconds(10).toString());
            Files.writeString(metadataPath, objectMapper.writeValueAsString(metadataMap));
        }

        // 10. Fetch results URL (this triggers finalization, deletion of subdirs and delivery)
        String redirectUrl = votingService.getResultsUrl(voteId, "http", "localhost", 8080, "/api");
        assertNotNull(redirectUrl);
        assertTrue(redirectUrl.contains("/v1/voting/static/" + voteId + "/results.json"));

        // 11. Read the static results file from storage (simulating S3 get)
        byte[] resultsBytes = votingService.getStaticResultsFile(voteId);
        VotingResultsResponse results = objectMapper.readValue(resultsBytes, VotingResultsResponse.class);
        
        assertEquals("COMPLETED", results.status());
        assertEquals(1, results.totalVotes());
        assertEquals(1, results.tallies().get("alice"));
        assertEquals(0, results.tallies().get("bob"));
        assertNotNull(results.verificationGuide());
        assertFalse(results.verificationGuide().isEmpty());

        // Verify folders are purged
        Path nullifiersDir = Paths.get("./local-storage/voting").resolve(voteId).resolve("nullifiers");
        Path ballotsDir = Paths.get("./local-storage/voting").resolve(voteId).resolve("ballots");
        assertFalse(Files.exists(nullifiersDir));
        assertFalse(Files.exists(ballotsDir));
    }

    @Test
    void testModule7_VerifiableCredentials() throws Exception {
        // 1. Issue VC
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("eligibleToVote", true);
        attributes.put("jurisdiction", "Madrid");
        IssueVcRequest issueRequest = new IssueVcRequest("did:example:citizen123", "Juana de Arco", attributes, 10);
        IssueVcResponse issueResponse = vcService.issueCredential(issueRequest);

        assertNotNull(issueResponse.vcId());
        assertNotNull(issueResponse.shareUrl());
        assertNotNull(issueResponse.credential());
        assertEquals("did:web:engine.civictech.org", issueResponse.credential().issuer());

        // 2. Fetch shared VC
        VerifiableCredential fetchedCred = vcService.getSharedCredential(issueResponse.vcId());
        assertNotNull(fetchedCred);
        assertEquals(issueResponse.credential().id(), fetchedCred.id());

        // 3. Verify VC (Valid)
        VerifyVcResponse verifyResponse = vcService.verifyCredential(fetchedCred);
        assertTrue(verifyResponse.verified());
        assertTrue(verifyResponse.checks().signatureValid());
        assertTrue(verifyResponse.checks().notExpired());
        assertTrue(verifyResponse.checks().integrityIntact());

        // 4. Verify VC (Tampered)
        // We modify a field in credentialSubject to simulate tampering
        Map<String, Object> modifiedSubject = new HashMap<>(fetchedCred.credentialSubject());
        modifiedSubject.put("fullName", "Malicious Actor");
        VerifiableCredential tamperedCred = new VerifiableCredential(
                fetchedCred.context(),
                fetchedCred.id(),
                fetchedCred.type(),
                fetchedCred.issuer(),
                fetchedCred.issuanceDate(),
                fetchedCred.expirationDate(),
                modifiedSubject,
                fetchedCred.proof()
        );

        VerifyVcResponse verifyResponseTampered = vcService.verifyCredential(tamperedCred);
        assertFalse(verifyResponseTampered.verified());
        assertFalse(verifyResponseTampered.checks().signatureValid());
        assertFalse(verifyResponseTampered.checks().integrityIntact());
    }

    @Test
    void testModule8_CryptographicProvenanceLedger() throws Exception {
        String assetId = "VM-TEST-" + System.currentTimeMillis();

        // 1. Create Genesis Asset
        Map<String, Object> genesisMeta = new HashMap<>();
        genesisMeta.put("batch", "B-2026");
        CreateAssetRequest createRequest = new CreateAssetRequest(assetId, "VOTING_MACHINE", "Central Election Office", genesisMeta);
        LedgerBlock genesisBlock = ledgerService.createGenesisAsset(createRequest);

        assertNotNull(genesisBlock);
        assertEquals(0, genesisBlock.index());
        assertEquals("GENESIS", genesisBlock.eventType());
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000", genesisBlock.previousBlockHash());
        assertNotNull(genesisBlock.blockHash());
        assertNotNull(genesisBlock.signature());

        // 2. Append event
        Map<String, Object> appendMeta = new HashMap<>();
        appendMeta.put("carrier", "DHL");
        AppendEventRequest appendRequest = new AppendEventRequest(
                assetId,
                "CUSTODY_TRANSFER",
                "Carrier Alpha",
                "Warehouse Madrid",
                genesisBlock.blockHash(),
                appendMeta
        );
        LedgerBlock nextBlock = ledgerService.appendEvent(appendRequest);

        assertNotNull(nextBlock);
        assertEquals(1, nextBlock.index());
        assertEquals("CUSTODY_TRANSFER", nextBlock.eventType());
        assertEquals(genesisBlock.blockHash(), nextBlock.previousBlockHash());

        // 3. Verify mismatch rejected
        AppendEventRequest invalidAppend = new AppendEventRequest(
                assetId,
                "CUSTODY_TRANSFER",
                "Carrier Alpha",
                "Warehouse Madrid",
                "invalid-previous-hash-value-123",
                appendMeta
        );
        assertThrows(IllegalArgumentException.class, () -> ledgerService.appendEvent(invalidAppend));

        // 4. History check
        LedgerHistoryResponse history = ledgerService.getAssetHistory(assetId);
        assertEquals(2, history.totalBlocks());
        assertEquals(0, history.blocks().get(0).index());
        assertEquals(1, history.blocks().get(1).index());

        // 5. Verification check (Valid)
        LedgerVerificationResponse verifyResponse = ledgerService.verifyLedger(assetId);
        assertTrue(verifyResponse.validChain());
        assertEquals(2, verifyResponse.blockCount());
        assertTrue(verifyResponse.auditReport().get(0).hashMatches());
        assertTrue(verifyResponse.auditReport().get(0).signatureValid());
        assertTrue(verifyResponse.auditReport().get(1).hashMatches());
        assertTrue(verifyResponse.auditReport().get(1).signatureValid());

        // 6. Tamper check (by writing tampered block file directly)
        Path block0Path = Paths.get("./local-storage/ledger").resolve(assetId).resolve("block_0.json");
        if (Files.exists(block0Path)) {
            // Read, modify, and overwrite
            Map<String, Object> blockMap = objectMapper.readValue(block0Path.toFile(), Map.class);
            blockMap.put("custodian", "Hacker");
            Files.writeString(block0Path, objectMapper.writeValueAsString(blockMap));

            // Run verification again
            LedgerVerificationResponse verifyResponseTampered = ledgerService.verifyLedger(assetId);
            assertFalse(verifyResponseTampered.validChain());
            // Either signature or hash verification (or linkage) must fail for index 0
            assertFalse(verifyResponseTampered.auditReport().get(0).hashMatches() &&
                        verifyResponseTampered.auditReport().get(0).signatureValid());
        }

        // 7. REST Controller endpoint mapping check via MockMvc
        mockMvc.perform(get("/v1/ledger/" + assetId + "/latest")
                .header("Authorization", "Bearer dev-api-key-sample"))
                .andExpect(status().isOk());

        // 8. Test Simulated Tampering REST API
        String tamperPayload = "{\"index\":1,\"location\":\"Unknown Warehouse\"}";
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/v1/ledger/" + assetId + "/tamper")
                .header("Authorization", "Bearer dev-api-key-sample")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .content(tamperPayload))
                .andExpect(status().isOk());

        // Verify it was tampered via API (validChain should now be false)
        mockMvc.perform(get("/v1/ledger/" + assetId + "/verify")
                .header("Authorization", "Bearer dev-api-key-sample"))
                .andExpect(status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.validChain").value(false));

        // 9. Test Reset Ledger REST API (DELETE)
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/v1/ledger/" + assetId)
                .header("Authorization", "Bearer dev-api-key-sample"))
                .andExpect(status().isNoContent());

        // Verify history is empty now
        mockMvc.perform(get("/v1/ledger/" + assetId + "/history")
                .header("Authorization", "Bearer dev-api-key-sample"))
                .andExpect(status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.totalBlocks").value(0));
    }

    @Test
    void testModule8_StorageCleanupService() throws Exception {
        if (!"local".equalsIgnoreCase(storageType)) {
            // Skip local file cleanup test if running against actual B2
            return;
        }

        Path root = Paths.get("./local-storage");
        Path votingExpired = root.resolve("voting/expired-session");
        Path votingActive = root.resolve("voting/active-session");
        Path ledgerExpired = root.resolve("ledger/expired-ledger");
        Path vcExpired = root.resolve("vc/expired-vc.json");
        Path vcActive = root.resolve("vc/active-vc.json");

        // Create directories and files
        Files.createDirectories(votingExpired);
        Files.createDirectories(votingActive);
        Files.createDirectories(ledgerExpired);
        Files.createDirectories(root.resolve("vc"));

        Path file1 = votingExpired.resolve("metadata.json");
        Path file2 = votingActive.resolve("metadata.json");
        Path file3 = ledgerExpired.resolve("block_0.json");

        Files.writeString(file1, "expired");
        Files.writeString(file2, "active");
        Files.writeString(file3, "expired-ledger");
        Files.writeString(vcExpired, "expired-vc");
        Files.writeString(vcActive, "active-vc");

        // Backdate the expired ones
        long eightDaysAgo = Instant.now().minus(8, java.time.temporal.ChronoUnit.DAYS).toEpochMilli();
        file1.toFile().setLastModified(eightDaysAgo);
        votingExpired.toFile().setLastModified(eightDaysAgo);
        file3.toFile().setLastModified(eightDaysAgo);
        ledgerExpired.toFile().setLastModified(eightDaysAgo);
        vcExpired.toFile().setLastModified(eightDaysAgo);

        // Run cleanup
        storageCleanupService.cleanupOldData();

        // Assertions
        assertFalse(Files.exists(votingExpired), "Expired voting session folder should be deleted");
        assertTrue(Files.exists(votingActive), "Active voting session folder should exist");
        assertFalse(Files.exists(ledgerExpired), "Expired ledger folder should be deleted");
        assertFalse(Files.exists(vcExpired), "Expired VC file should be deleted");
        assertTrue(Files.exists(vcActive), "Active VC file should exist");

        // Cleanup the test files
        try {
            Files.deleteIfExists(file2);
            Files.deleteIfExists(votingActive);
            Files.deleteIfExists(vcActive);
        } catch (Exception ignored) {}
    }
}

