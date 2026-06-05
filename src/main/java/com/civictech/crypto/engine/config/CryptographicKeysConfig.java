package com.civictech.crypto.engine.config;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Configuration
public class CryptographicKeysConfig {

    private static final Logger log = LoggerFactory.getLogger(CryptographicKeysConfig.class);

    @Value("${crypto.keys.signing-private-key-base64:}")
    private String configuredSigningKeyBase64;

    @Value("${crypto.keys.tsa-private-key-base64:}")
    private String configuredTsaKeyBase64;

    @Value("${crypto.keys.vault-key-hex:}")
    private String configuredVaultKeyHex;

    private KeyPair signingKeyPair;
    private KeyPair tsaKeyPair;
    private SecretKey vaultKey;

    @PostConstruct
    public void initKeys() {
        try {
            initSigningKeys();
            initTsaKeys();
            initVaultKey();
        } catch (Exception e) {
            log.error("Failed to initialize cryptographic keys", e);
            throw new IllegalStateException("Cryptographic key initialization failure", e);
        }
    }

    private void initSigningKeys() throws Exception {
        if (configuredSigningKeyBase64 != null && !configuredSigningKeyBase64.trim().isEmpty()) {
            log.info("Loading configured ECDSA signing private key...");
            byte[] keyBytes = Base64.getDecoder().decode(configuredSigningKeyBase64.trim());
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            
            PublicKey publicKey = deriveECPublicKey((PrivateKey) privateKey);
            this.signingKeyPair = new KeyPair(publicKey, privateKey);
            log.info("Configured ECDSA signing key successfully loaded.");
        } else {
            log.info("No signing key configured. Generating a secure ephemeral ECDSA secp256r1 keypair...");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            this.signingKeyPair = kpg.generateKeyPair();
            log.info("Ephemeral ECDSA signing keypair generated.");
        }
    }

    private void initTsaKeys() throws Exception {
        if (configuredTsaKeyBase64 != null && !configuredTsaKeyBase64.trim().isEmpty()) {
            log.info("Loading configured ECDSA TSA private key...");
            byte[] keyBytes = Base64.getDecoder().decode(configuredTsaKeyBase64.trim());
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            
            PublicKey publicKey = deriveECPublicKey((PrivateKey) privateKey);
            this.tsaKeyPair = new KeyPair(publicKey, privateKey);
            log.info("Configured ECDSA TSA key successfully loaded.");
        } else {
            log.info("No TSA key configured. Generating a secure ephemeral ECDSA secp256r1 keypair for TSA...");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            this.tsaKeyPair = kpg.generateKeyPair();
            log.info("Ephemeral ECDSA TSA keypair generated.");
        }
    }

    private void initVaultKey() throws Exception {
        if (configuredVaultKeyHex != null && !configuredVaultKeyHex.trim().isEmpty()) {
            log.info("Loading configured AES Vault key...");
            byte[] keyBytes = Hex.decode(configuredVaultKeyHex.trim());
            if (keyBytes.length != 32) {
                throw new IllegalArgumentException("Vault key must be exactly 256 bits (32 bytes) hex-encoded.");
            }
            this.vaultKey = new SecretKeySpec(keyBytes, "AES");
            log.info("Configured AES Vault key successfully loaded.");
        } else {
            log.info("No Vault key configured. Generating a secure ephemeral AES-256 key...");
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", BouncyCastleProvider.PROVIDER_NAME);
            keyGen.init(256, new SecureRandom());
            this.vaultKey = keyGen.generateKey();
            log.info("Ephemeral AES-256 Vault key generated.");
        }
    }

    /**
     * Derives the EC Public Key from an EC Private Key using curve parameters.
     */
    private PublicKey deriveECPublicKey(PrivateKey privateKey) throws Exception {
        if (!(privateKey instanceof ECPrivateKey ecPrivateKey)) {
            throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
        }
        ECParameterSpec ecSpec = ecPrivateKey.getParameters();
        ECPoint q = ecSpec.getG().multiply(ecPrivateKey.getD());
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(q, ecSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePublic(pubSpec);
    }

    public KeyPair getSigningKeyPair() {
        return signingKeyPair;
    }

    public KeyPair getTsaKeyPair() {
        return tsaKeyPair;
    }

    public SecretKey getVaultKey() {
        return vaultKey;
    }
}
