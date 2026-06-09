package com.civictech.crypto.engine.ledger;

import com.civictech.crypto.engine.config.CryptographicKeysConfig;
import com.civictech.crypto.engine.error.CryptoException;
import com.civictech.crypto.engine.ledger.dto.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class LedgerService {

    private static final Logger log = LoggerFactory.getLogger(LedgerService.class);
    private static final String GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    private final CryptographicKeysConfig keysConfig;
    private final ObjectMapper objectMapper;
    private final S3Client s3Client;
    private final String storageType;
    private final String bucketName;
    private final Path storageRoot;

    public LedgerService(CryptographicKeysConfig keysConfig,
                         ObjectMapper objectMapper,
                         @Autowired(required = false) S3Client s3Client,
                         @Value("${voting.storage.type:local}") String storageType,
                         @Value("${voting.storage.b2.bucket-name:}") String bucketName) {
        this.keysConfig = keysConfig;
        this.objectMapper = objectMapper;
        this.s3Client = s3Client;
        this.storageType = storageType;
        this.bucketName = bucketName;
        this.storageRoot = Paths.get("./local-storage/ledger");

        if (!isB2()) {
            try {
                Files.createDirectories(storageRoot);
            } catch (IOException e) {
                throw new RuntimeException("Failed to create local ledger storage directory", e);
            }
        }
    }

    private boolean isB2() {
        return "b2".equalsIgnoreCase(storageType) && s3Client != null;
    }

    public LedgerBlock createGenesisAsset(CreateAssetRequest request) {
        try {
            String assetId = request.assetId().trim();
            String timestamp = Instant.now().toString();

            // Verify if asset already exists
            List<LedgerBlock> existing = getBlocks(assetId);
            if (!existing.isEmpty()) {
                throw new IllegalArgumentException("Asset ledger already initialized for assetId: " + assetId);
            }

            // Calculate block hash
            byte[] blockHashBytes = calculateBlockHashBytes(0, timestamp, assetId, "GENESIS", 
                    request.custodian(), null, GENESIS_PREV_HASH, request.meta());
            String blockHash = Hex.toHexString(blockHashBytes);

            // Sign using ECDSA
            PrivateKey privateKey = keysConfig.getSigningKeyPair().getPrivate();
            Signature ecdsa = Signature.getInstance("NONEwithECDSA", BouncyCastleProvider.PROVIDER_NAME);
            ecdsa.initSign(privateKey);
            ecdsa.update(blockHashBytes);
            byte[] signatureBytes = ecdsa.sign();
            String signature = Base64.getEncoder().encodeToString(signatureBytes);

            LedgerBlock genesisBlock = new LedgerBlock(
                    0,
                    timestamp,
                    assetId,
                    "GENESIS",
                    request.custodian(),
                    null,
                    GENESIS_PREV_HASH,
                    blockHash,
                    signature,
                    request.meta() != null ? new TreeMap<>(request.meta()) : Collections.emptyMap()
            );

            saveBlock(assetId, genesisBlock);
            return genesisBlock;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to create Genesis Block for asset", e);
            throw new CryptoException("Asset creation failed", e);
        }
    }

    public LedgerBlock appendEvent(AppendEventRequest request) {
        try {
            String assetId = request.assetId().trim();
            String timestamp = Instant.now().toString();

            List<LedgerBlock> existing = getBlocks(assetId);
            if (existing.isEmpty()) {
                throw new IllegalArgumentException("Asset ledger has not been initialized. Create it first.");
            }

            LedgerBlock lastBlock = existing.get(existing.size() - 1);
            String clientPrevHash = request.previousBlockHash().trim();
            if (!lastBlock.blockHash().equalsIgnoreCase(clientPrevHash)) {
                throw new IllegalArgumentException("Conflict: previousBlockHash mismatch. Last recorded hash: " + lastBlock.blockHash());
            }

            int newIndex = lastBlock.index() + 1;

            byte[] newHashBytes = calculateBlockHashBytes(
                    newIndex,
                    timestamp,
                    assetId,
                    request.eventType(),
                    request.custodian(),
                    request.location(),
                    lastBlock.blockHash(),
                    request.meta()
            );
            String newHash = Hex.toHexString(newHashBytes);

            // Sign new block
            PrivateKey privateKey = keysConfig.getSigningKeyPair().getPrivate();
            Signature ecdsa = Signature.getInstance("NONEwithECDSA", BouncyCastleProvider.PROVIDER_NAME);
            ecdsa.initSign(privateKey);
            ecdsa.update(newHashBytes);
            byte[] signatureBytes = ecdsa.sign();
            String signature = Base64.getEncoder().encodeToString(signatureBytes);

            LedgerBlock newBlock = new LedgerBlock(
                    newIndex,
                    timestamp,
                    assetId,
                    request.eventType(),
                    request.custodian(),
                    request.location(),
                    lastBlock.blockHash(),
                    newHash,
                    signature,
                    request.meta() != null ? new TreeMap<>(request.meta()) : Collections.emptyMap()
            );

            saveBlock(assetId, newBlock);
            return newBlock;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to append event to ledger", e);
            throw new CryptoException("Event append failed", e);
        }
    }

    public LedgerHistoryResponse getAssetHistory(String assetId) {
        List<LedgerBlock> blocks = getBlocks(assetId);
        return new LedgerHistoryResponse(assetId, blocks.size(), blocks);
    }

    public LedgerBlock getLatestBlock(String assetId) {
        List<LedgerBlock> blocks = getBlocks(assetId);
        if (blocks.isEmpty()) {
            throw new IllegalArgumentException("No ledger blocks found for assetId: " + assetId);
        }
        return blocks.get(blocks.size() - 1);
    }

    public LedgerVerificationResponse verifyLedger(String assetId) {
        List<LedgerBlock> blocks = getBlocks(assetId);
        if (blocks.isEmpty()) {
            return new LedgerVerificationResponse(assetId, true, 0, Collections.emptyList());
        }

        List<LedgerVerificationResponse.BlockAuditReport> report = new ArrayList<>();
        boolean validChain = true;

        PublicKey serverPublicKey = keysConfig.getSigningKeyPair().getPublic();

        for (int i = 0; i < blocks.size(); i++) {
            LedgerBlock block = blocks.get(i);
            boolean hashMatches = false;
            boolean signatureValid = false;

            try {
                // 1. Recalculate block hash
                byte[] calculatedHashBytes = calculateBlockHashBytes(
                        block.index(),
                        block.timestamp(),
                        block.assetId(),
                        block.eventType(),
                        block.custodian(),
                        block.location(),
                        block.previousBlockHash(),
                        block.meta()
                );
                String calculatedHashStr = Hex.toHexString(calculatedHashBytes);
                hashMatches = calculatedHashStr.equalsIgnoreCase(block.blockHash());

                // 2. Validate digital signature
                byte[] signatureBytes = Base64.getDecoder().decode(block.signature());
                Signature ecdsa = Signature.getInstance("NONEwithECDSA", BouncyCastleProvider.PROVIDER_NAME);
                ecdsa.initVerify(serverPublicKey);
                ecdsa.update(calculatedHashBytes);
                signatureValid = ecdsa.verify(signatureBytes);

                // 3. Linkage verification
                if (i == 0) {
                    if (!GENESIS_PREV_HASH.equalsIgnoreCase(block.previousBlockHash())) {
                        hashMatches = false;
                    }
                } else {
                    LedgerBlock prevBlock = blocks.get(i - 1);
                    if (!prevBlock.blockHash().equalsIgnoreCase(block.previousBlockHash())) {
                        hashMatches = false;
                    }
                }

            } catch (Exception e) {
                log.warn("Verification exception on block {}", block.index(), e);
            }

            if (!hashMatches || !signatureValid) {
                validChain = false;
            }

            report.add(new LedgerVerificationResponse.BlockAuditReport(
                    block.index(),
                    hashMatches,
                    signatureValid,
                    block.blockHash()
            ));
        }

        return new LedgerVerificationResponse(assetId, validChain, blocks.size(), report);
    }

    public void resetLedger(String assetId) {
        String cleanAssetId = assetId.trim();
        log.info("Resetting/deleting ledger for assetId: {}", cleanAssetId);

        if (isB2()) {
            try {
                String prefix = "ledger/" + cleanAssetId + "/";
                ListObjectsV2Response response = s3Client.listObjectsV2(ListObjectsV2Request.builder()
                        .bucket(bucketName)
                        .prefix(prefix)
                        .build());
                for (S3Object obj : response.contents()) {
                    s3Client.deleteObject(DeleteObjectRequest.builder().bucket(bucketName).key(obj.key()).build());
                    log.info("Deleted block object from B2: {}", obj.key());
                }
            } catch (Exception e) {
                log.error("Failed to delete ledger from B2 for assetId: {}", cleanAssetId, e);
                throw new CryptoException("Failed to reset ledger in B2", e);
            }
        } else {
            Path dir = storageRoot.resolve(cleanAssetId);
            if (Files.exists(dir)) {
                try {
                    Files.walk(dir)
                            .sorted(Comparator.reverseOrder())
                            .map(Path::toFile)
                            .forEach(java.io.File::delete);
                    log.info("Deleted local ledger directory for assetId: {}", cleanAssetId);
                } catch (IOException e) {
                    log.error("Failed to delete local ledger directory for assetId: {}", cleanAssetId, e);
                    throw new CryptoException("Failed to reset local ledger", e);
                }
            }
        }
    }

    public LedgerBlock tamperLedger(String assetId, TamperRequest request) {
        String cleanAssetId = assetId.trim();
        List<LedgerBlock> blocks = getBlocks(cleanAssetId);

        LedgerBlock targetBlock = null;
        for (LedgerBlock b : blocks) {
            if (b.index() == request.index()) {
                targetBlock = b;
                break;
            }
        }

        if (targetBlock == null) {
            throw new IllegalArgumentException("Block with index " + request.index() + " not found for assetId: " + cleanAssetId);
        }

        String newLocation = request.location() != null ? request.location() : targetBlock.location();
        String newCustodian = request.custodian() != null ? request.custodian() : targetBlock.custodian();

        // Construct the tampered block: modified fields, but ORIGINAL hash and signature
        LedgerBlock tamperedBlock = new LedgerBlock(
                targetBlock.index(),
                targetBlock.timestamp(),
                targetBlock.assetId(),
                targetBlock.eventType(),
                newCustodian,
                newLocation,
                targetBlock.previousBlockHash(),
                targetBlock.blockHash(), // Keeps original hash
                targetBlock.signature(), // Keeps original signature
                targetBlock.meta()
        );

        try {
            saveBlock(cleanAssetId, tamperedBlock);
            log.info("Successfully tampered block {} of assetId: {}", request.index(), cleanAssetId);
            return tamperedBlock;
        } catch (IOException e) {
            log.error("Failed to write tampered block", e);
            throw new CryptoException("Failed to tamper ledger", e);
        }
    }

    private byte[] calculateBlockHashBytes(int index, String timestamp, String assetId, String eventType,
                                          String custodian, String location, String previousBlockHash,
                                          Map<String, Object> meta) throws Exception {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("index", index);
        map.put("timestamp", timestamp);
        map.put("assetId", assetId);
        map.put("eventType", eventType);
        map.put("custodian", custodian);
        map.put("location", location != null ? location : "");
        map.put("previousBlockHash", previousBlockHash);
        map.put("meta", meta != null ? new TreeMap<>(meta) : Collections.emptyMap());

        byte[] serialized = objectMapper.writeValueAsBytes(map);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(serialized);
    }

    private List<LedgerBlock> getBlocks(String assetId) {
        List<LedgerBlock> blocks = new ArrayList<>();
        String prefix = "ledger/" + assetId + "/";

        try {
            if (isB2()) {
                ListObjectsV2Response response = s3Client.listObjectsV2(ListObjectsV2Request.builder()
                        .bucket(bucketName)
                        .prefix(prefix)
                        .build());

                for (S3Object obj : response.contents()) {
                    if (!obj.key().endsWith(".json")) continue;
                    ResponseBytes<GetObjectResponse> data = s3Client.getObjectAsBytes(GetObjectRequest.builder()
                            .bucket(bucketName)
                            .key(obj.key())
                            .build());
                    blocks.add(objectMapper.readValue(data.asByteArray(), LedgerBlock.class));
                }
            } else {
                Path dir = storageRoot.resolve(assetId);
                if (Files.exists(dir) && Files.isDirectory(dir)) {
                    File[] files = dir.toFile().listFiles((d, name) -> name.endsWith(".json"));
                    if (files != null) {
                        for (File f : files) {
                            blocks.add(objectMapper.readValue(f, LedgerBlock.class));
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to read ledger blocks for asset: {}", assetId, e);
            throw new CryptoException("Ledger retrieval failed", e);
        }

        blocks.sort(Comparator.comparingInt(LedgerBlock::index));
        return blocks;
    }

    private void saveBlock(String assetId, LedgerBlock block) throws IOException {
        byte[] blockBytes = objectMapper.writeValueAsBytes(block);
        String key = "ledger/" + assetId + "/block_" + block.index() + ".json";

        if (isB2()) {
            s3Client.putObject(PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .contentType("application/json")
                    .build(),
                    RequestBody.fromBytes(blockBytes));
            log.info("Saved ledger block to B2: {}", key);
        } else {
            Path dir = storageRoot.resolve(assetId);
            Files.createDirectories(dir);
            Files.write(dir.resolve("block_" + block.index() + ".json"), blockBytes);
            log.info("Saved ledger block to local storage: {}", dir.resolve("block_" + block.index() + ".json"));
        }
    }
}
