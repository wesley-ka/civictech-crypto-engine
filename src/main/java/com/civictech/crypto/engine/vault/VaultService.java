package com.civictech.crypto.engine.vault;

import com.civictech.crypto.engine.config.CryptographicKeysConfig;
import com.civictech.crypto.engine.error.CryptoException;
import com.civictech.crypto.engine.vault.dto.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class VaultService {

    private static final Logger log = LoggerFactory.getLogger(VaultService.class);
    private static final int GCM_IV_LENGTH = 12; // 96 bits standard IV for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128 bits standard authentication tag
    private static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    private final CryptographicKeysConfig keysConfig;
    private final ObjectMapper objectMapper;
    private final SecureRandom secureRandom;
    
    // Thread-safe in-memory blockchain audit trail
    private final List<AuditBlock> auditTrail = new CopyOnWriteArrayList<>();

    public record AuditBlock(
        int index,
        Instant timestamp,
        String logEntry,
        String previousHash,
        String blockHash
    ) {}

    public VaultService(CryptographicKeysConfig keysConfig, ObjectMapper objectMapper) {
        this.keysConfig = keysConfig;
        this.objectMapper = objectMapper;
        this.secureRandom = new SecureRandom();
        
        // Initialize the audit trail with a Genesis block
        createGenesisBlock();
    }

    private void createGenesisBlock() {
        Instant now = Instant.parse("2026-06-05T00:00:00Z");
        String entry = "GENESIS_BLOCK_CIVICTECH_AUDIT_TRAIL";
        String blockHash = calculateBlockHash(0, now, entry, GENESIS_HASH);
        auditTrail.add(new AuditBlock(0, now, entry, GENESIS_HASH, blockHash));
        log.info("Genesis block created for audit trail. Hash: {}", blockHash);
    }

    public EncryptResponse encrypt(EncryptRequest request) {
        try {
            byte[] plaintextBytes = objectMapper.writeValueAsBytes(request.sensitiveData());

            // Generate unique 12-byte IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            SecretKey secretKey = keysConfig.getVaultKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            byte[] encryptedDataWithTag = cipher.doFinal(plaintextBytes);

            // Separate Ciphertext and Auth Tag
            int ciphertextLength = encryptedDataWithTag.length - (GCM_TAG_LENGTH / 8);
            byte[] ciphertext = new byte[ciphertextLength];
            byte[] tag = new byte[GCM_TAG_LENGTH / 8];

            System.arraycopy(encryptedDataWithTag, 0, ciphertext, 0, ciphertextLength);
            System.arraycopy(encryptedDataWithTag, ciphertextLength, tag, 0, tag.length);

            log.info("Successfully encrypted vault entry. Ciphertext size: {} bytes", ciphertext.length);

            return new EncryptResponse(
                    Base64.getEncoder().encodeToString(ciphertext),
                    Base64.getEncoder().encodeToString(iv),
                    Base64.getEncoder().encodeToString(tag)
            );

        } catch (Exception e) {
            log.error("Encryption failure in secure vault", e);
            throw new CryptoException("Encryption operation failed", e);
        }
    }

    public DecryptResponse decrypt(DecryptRequest request) {
        try {
            byte[] ciphertext = Base64.getDecoder().decode(request.ciphertext());
            byte[] iv = Base64.getDecoder().decode(request.iv());
            byte[] tag = Base64.getDecoder().decode(request.authTag());

            // Combine ciphertext and Auth Tag
            byte[] combinedBytes = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, combinedBytes, 0, ciphertext.length);
            System.arraycopy(tag, 0, combinedBytes, ciphertext.length, tag.length);

            SecretKey secretKey = keysConfig.getVaultKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            byte[] decryptedBytes = cipher.doFinal(combinedBytes);
            Map<String, Object> decryptedData = objectMapper.readValue(decryptedBytes, new TypeReference<Map<String, Object>>() {});

            log.info("Successfully decrypted vault entry.");
            return new DecryptResponse(decryptedData);

        } catch (Exception e) {
            log.error("Decryption failure in secure vault", e);
            throw new CryptoException("Decryption operation failed. The payload might be tampered or keys are invalid.", e);
        }
    }

    public synchronized AuditResponse audit(AuditRequest request) {
        AuditBlock lastBlock = auditTrail.get(auditTrail.size() - 1);
        int nextIndex = lastBlock.index() + 1;
        Instant now = Instant.now();
        String entry = request.logEntry().trim();
        String prevHash = lastBlock.blockHash();

        String blockHash = calculateBlockHash(nextIndex, now, entry, prevHash);
        AuditBlock newBlock = new AuditBlock(nextIndex, now, entry, prevHash, blockHash);
        auditTrail.add(newBlock);

        // Gather all block hashes to compute Merkle Tree root
        List<String> allHashes = auditTrail.stream().map(AuditBlock::blockHash).toList();
        String merkleRoot = computeMerkleRoot(allHashes);

        log.info("Audit entry registered. Block Index: {}, Root: {}", nextIndex, merkleRoot);

        return new AuditResponse(
                newBlock.index(),
                newBlock.timestamp(),
                newBlock.logEntry(),
                newBlock.previousHash(),
                newBlock.blockHash(),
                merkleRoot
        );
    }

    private String calculateBlockHash(int index, Instant timestamp, String logEntry, String previousHash) {
        try {
            String rawInput = index + timestamp.toString() + logEntry + previousHash;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawInput.getBytes(StandardCharsets.UTF_8));
            return Hex.toHexString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Hash algorithm SHA-256 missing", e);
        }
    }

    private String computeMerkleRoot(List<String> hashes) {
        if (hashes == null || hashes.isEmpty()) {
            return GENESIS_HASH;
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            List<byte[]> currentLevel = new ArrayList<>();
            for (String h : hashes) {
                currentLevel.add(Hex.decode(h));
            }

            while (currentLevel.size() > 1) {
                List<byte[]> nextLevel = new ArrayList<>();
                for (int i = 0; i < currentLevel.size(); i += 2) {
                    byte[] left = currentLevel.get(i);
                    byte[] right = (i + 1 < currentLevel.size()) ? currentLevel.get(i + 1) : left;

                    byte[] combined = new byte[left.length + right.length];
                    System.arraycopy(left, 0, combined, 0, left.length);
                    System.arraycopy(right, 0, combined, left.length, right.length);

                    nextLevel.add(digest.digest(combined));
                }
                currentLevel = nextLevel;
            }

            return Hex.toHexString(currentLevel.get(0));
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Hash algorithm SHA-256 missing during Merkle computation", e);
        }
    }
}
