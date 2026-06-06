package com.civictech.crypto.engine.quantum;

import com.civictech.crypto.engine.error.CryptoException;
import com.civictech.crypto.engine.quantum.dto.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class QuantumService {

    private static final Logger log = LoggerFactory.getLogger(QuantumService.class);

    private static final int AES_KEY_SIZE_BYTES = 32; // 256 bits
    private static final int GCM_IV_LENGTH_BYTES = 12; // 96 bits
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private final SecureRandom secureRandom;

    public QuantumService() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generates a new ML-KEM-768 keypair.
     */
    public KeyGenResponse generateKeyPair() {
        try {
            KyberKeyPairGenerator keyPairGen = new KyberKeyPairGenerator();
            keyPairGen.init(new KyberKeyGenerationParameters(secureRandom, KyberParameters.kyber768));
            AsymmetricCipherKeyPair keyPair = keyPairGen.generateKeyPair();

            KyberPublicKeyParameters pubKey = (KyberPublicKeyParameters) keyPair.getPublic();
            KyberPrivateKeyParameters privKey = (KyberPrivateKeyParameters) keyPair.getPrivate();

            byte[] pubKeyBytes = pubKey.getEncoded();
            byte[] privKeyBytes = privKey.getEncoded();

            String pubKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(pubKeyBytes);
            String privKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(privKeyBytes);

            log.info("Successfully generated ML-KEM-768 keypair. Public key length: {} bytes, Private key length: {} bytes",
                    pubKeyBytes.length, privKeyBytes.length);

            return new KeyGenResponse(
                    pubKeyBase64,
                    privKeyBase64,
                    "ML-KEM-768",
                    pubKeyBytes.length,
                    privKeyBytes.length
            );
        } catch (Exception e) {
            log.error("Failed to generate ML-KEM-768 keypair", e);
            throw new CryptoException("Keypair generation failed", e);
        }
    }

    /**
     * Performs Hybrid Encryption (ML-KEM-768 encapsulation + HKDF-SHA256 + AES-256-GCM).
     */
    public EncryptResponse encrypt(EncryptRequest request) {
        try {
            // Decode the public key
            byte[] pubKeyBytes = Base64.getUrlDecoder().decode(request.recipientPublicKey());
            if (pubKeyBytes.length != 1184) {
                throw new IllegalArgumentException("Invalid public key length. Expected 1184 bytes for ML-KEM-768, got " + pubKeyBytes.length);
            }

            // Instantiate ML-KEM public key
            KyberPublicKeyParameters pubKeyParams = new KyberPublicKeyParameters(KyberParameters.kyber768, pubKeyBytes);

            // Generate shared secret and KEM ciphertext
            KyberKEMGenerator kemGen = new KyberKEMGenerator(secureRandom);
            var secretWithEncapsulation = kemGen.generateEncapsulated(pubKeyParams);
            byte[] sharedSecret = secretWithEncapsulation.getSecret(); // 32 bytes
            byte[] kemCiphertext = secretWithEncapsulation.getEncapsulation(); // 1088 bytes

            // Derive AES key using HKDF-SHA256
            byte[] aesKeyBytes = deriveAesKey(sharedSecret);

            // Generate cryptographically secure random 12-byte IV
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            // Encrypt message text using AES-256-GCM
            byte[] plaintextBytes = request.messageText().getBytes(StandardCharsets.UTF_8);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
            byte[] encryptedMessageBytes = cipher.doFinal(plaintextBytes); // Contains 16-byte authentication tag at the end

            // Hash the shared secret
            String sharedSecretHash = hashSharedSecret(sharedSecret);

            // Base64URL-encode outputs
            String kemCiphertextBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(kemCiphertext);
            String ivBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(iv);
            String encryptedMessageBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedMessageBytes);

            log.info("Successfully performed hybrid encryption. KEM ciphertext: {} bytes, Encrypted message: {} bytes",
                    kemCiphertext.length, encryptedMessageBytes.length);

            return new EncryptResponse(
                    kemCiphertextBase64,
                    ivBase64,
                    encryptedMessageBase64,
                    "ML-KEM-768 + AES-256-GCM",
                    sharedSecretHash
            );
        } catch (IllegalArgumentException e) {
            log.warn("Invalid input for encryption: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Hybrid encryption failed", e);
            throw new CryptoException("Encryption operation failed", e);
        }
    }

    /**
     * Performs Hybrid Decryption (ML-KEM-768 decapsulation + HKDF-SHA256 + AES-256-GCM).
     */
    public DecryptResponse decrypt(DecryptRequest request) {
        try {
            // Decode inputs
            byte[] privKeyBytes = Base64.getUrlDecoder().decode(request.privateKey());
            byte[] kemCiphertext = Base64.getUrlDecoder().decode(request.kemCiphertext());
            byte[] iv = Base64.getUrlDecoder().decode(request.iv());
            byte[] encryptedMessage = Base64.getUrlDecoder().decode(request.encryptedMessage());

            if (privKeyBytes.length != 2400) {
                throw new IllegalArgumentException("Invalid private key length. Expected 2400 bytes for ML-KEM-768, got " + privKeyBytes.length);
            }
            if (kemCiphertext.length != 1088) {
                throw new IllegalArgumentException("Invalid KEM ciphertext length. Expected 1088 bytes for ML-KEM-768, got " + kemCiphertext.length);
            }
            if (iv.length != GCM_IV_LENGTH_BYTES) {
                throw new IllegalArgumentException("Invalid IV length. Expected 12 bytes, got " + iv.length);
            }

            // Instantiate ML-KEM private key
            KyberPrivateKeyParameters privKeyParams = new KyberPrivateKeyParameters(KyberParameters.kyber768, privKeyBytes);

            // Recover shared secret from KEM ciphertext
            KyberKEMExtractor kemExtract = new KyberKEMExtractor(privKeyParams);
            byte[] sharedSecret = kemExtract.extractSecret(kemCiphertext); // 32 bytes

            // Derive AES key using HKDF-SHA256
            byte[] aesKeyBytes = deriveAesKey(sharedSecret);

            // Decrypt message using AES-256-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            SecretKeySpec keySpec = new SecretKeySpec(aesKeyBytes, "AES");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
            byte[] decryptedBytes = cipher.doFinal(encryptedMessage);

            String plaintext = new String(decryptedBytes, StandardCharsets.UTF_8);

            // Hash the shared secret
            String sharedSecretHash = hashSharedSecret(sharedSecret);

            log.info("Successfully decrypted message. Plaintext length: {} chars", plaintext.length());

            return new DecryptResponse(
                    plaintext,
                    "ML-KEM-768 + AES-256-GCM",
                    sharedSecretHash
            );
        } catch (IllegalArgumentException e) {
            log.warn("Invalid input for decryption: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Hybrid decryption failed", e);
            throw new CryptoException("Decryption operation failed. The payload might be tampered or keys are invalid.", e);
        }
    }

    private byte[] deriveAesKey(byte[] sharedSecret) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(sharedSecret, null, null));
        byte[] aesKey = new byte[AES_KEY_SIZE_BYTES];
        hkdf.generateBytes(aesKey, 0, AES_KEY_SIZE_BYTES);
        return aesKey;
    }

    private String hashSharedSecret(byte[] sharedSecret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(sharedSecret);
        return Hex.toHexString(hash);
    }
}
