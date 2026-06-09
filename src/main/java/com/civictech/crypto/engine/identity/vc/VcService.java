package com.civictech.crypto.engine.identity.vc;

import com.civictech.crypto.engine.config.CryptographicKeysConfig;
import com.civictech.crypto.engine.error.CryptoException;
import com.civictech.crypto.engine.identity.vc.dto.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class VcService {

    private static final Logger log = LoggerFactory.getLogger(VcService.class);

    private final CryptographicKeysConfig keysConfig;
    private final ObjectMapper objectMapper;
    private final S3Client s3Client;
    private final String storageType;
    private final String bucketName;
    private final Path storageRoot;

    public VcService(CryptographicKeysConfig keysConfig,
                     ObjectMapper objectMapper,
                     @Autowired(required = false) S3Client s3Client,
                     @Value("${voting.storage.type:local}") String storageType,
                     @Value("${voting.storage.b2.bucket-name:}") String bucketName) {
        this.keysConfig = keysConfig;
        this.objectMapper = objectMapper;
        this.s3Client = s3Client;
        this.storageType = storageType;
        this.bucketName = bucketName;
        this.storageRoot = Paths.get("./local-storage/vc");

        if (!isB2()) {
            try {
                Files.createDirectories(storageRoot);
            } catch (IOException e) {
                throw new RuntimeException("Failed to create local VC storage directory", e);
            }
        }
    }

    private boolean isB2() {
        return "b2".equalsIgnoreCase(storageType) && s3Client != null;
    }

    public IssueVcResponse issueCredential(IssueVcRequest request) {
        try {
            String vcId = UUID.randomUUID().toString();
            Instant now = Instant.now();
            int days = request.expirationDays() != null ? request.expirationDays() : 30;
            Instant expiry = now.plus(days, ChronoUnit.DAYS);

            // Construct credentialSubject map
            Map<String, Object> subject = new LinkedHashMap<>();
            subject.put("id", request.subjectId());
            subject.put("fullName", request.fullName());
            if (request.attributes() != null) {
                // Keep ordering sorted to maintain consistency
                new TreeMap<>(request.attributes()).forEach(subject::put);
            }

            // Create temporary credential object to compute the hash
            VerifiableCredential tempCred = new VerifiableCredential(
                    List.of("https://www.w3.org/2018/credentials/v1", "https://schema.org"),
                    "urn:uuid:" + vcId,
                    List.of("VerifiableCredential", "CivicCitizenCredential"),
                    "did:web:engine.civictech.org",
                    now.toString(),
                    expiry.toString(),
                    subject,
                    null
            );

            // Calculate Hash
            byte[] hashToSign = computeCredentialHash(tempCred);

            // Sign using ECDSA private key
            PrivateKey privateKey = keysConfig.getSigningKeyPair().getPrivate();
            Signature ecdsa = Signature.getInstance("NONEwithECDSA", BouncyCastleProvider.PROVIDER_NAME);
            ecdsa.initSign(privateKey);
            ecdsa.update(hashToSign);
            byte[] signatureBytes = ecdsa.sign();
            String base64Signature = Base64.getEncoder().encodeToString(signatureBytes);

            // Get Public Key Coordinates
            ECPublicKey publicKey = (ECPublicKey) keysConfig.getSigningKeyPair().getPublic();
            org.bouncycastle.math.ec.ECPoint q = publicKey.getQ();
            String xHex = q.getAffineXCoord().toBigInteger().toString(16);
            String yHex = q.getAffineYCoord().toBigInteger().toString(16);

            // Create final proof
            CredentialProof proof = new CredentialProof(
                    "JsonWebSignature2020",
                    now.toString(),
                    "assertionMethod",
                    "did:web:engine.civictech.org#key-1",
                    xHex,
                    yHex,
                    base64Signature
            );

            // Assemble final VC
            VerifiableCredential finalCred = new VerifiableCredential(
                    tempCred.context(),
                    tempCred.id(),
                    tempCred.type(),
                    tempCred.issuer(),
                    tempCred.issuanceDate(),
                    tempCred.expirationDate(),
                    tempCred.credentialSubject(),
                    proof
            );

            // Save VC to storage
            byte[] vcBytes = objectMapper.writeValueAsBytes(finalCred);
            String storageKey = "vc/" + vcId + ".json";

            if (isB2()) {
                s3Client.putObject(PutObjectRequest.builder()
                        .bucket(bucketName)
                        .key(storageKey)
                        .contentType("application/json")
                        .build(),
                        RequestBody.fromBytes(vcBytes));
                log.info("Saved Verifiable Credential to B2: {}", vcId);
            } else {
                Files.write(storageRoot.resolve(vcId + ".json"), vcBytes);
                log.info("Saved Verifiable Credential to local storage: {}", vcId);
            }

            String shareUrl = "/v1/identity/vc/share/" + vcId;

            return new IssueVcResponse(vcId, shareUrl, finalCred);

        } catch (Exception e) {
            log.error("Failed to issue Verifiable Credential", e);
            throw new CryptoException("Credential issuance failed", e);
        }
    }

    public VerifiableCredential getSharedCredential(String vcId) {
        String storageKey = "vc/" + vcId + ".json";
        try {
            if (isB2()) {
                ResponseBytes<GetObjectResponse> obj = s3Client.getObjectAsBytes(GetObjectRequest.builder()
                        .bucket(bucketName)
                        .key(storageKey)
                        .build());
                return objectMapper.readValue(obj.asByteArray(), VerifiableCredential.class);
            } else {
                Path path = storageRoot.resolve(vcId + ".json");
                if (!Files.exists(path)) {
                    throw new IllegalArgumentException("Credential not found.");
                }
                return objectMapper.readValue(path.toFile(), VerifiableCredential.class);
            }
        } catch (NoSuchKeyException e) {
            throw new IllegalArgumentException("Credential not found.");
        } catch (IOException e) {
            log.error("Failed to retrieve shared credential: {}", vcId, e);
            throw new CryptoException("Credential retrieval failed", e);
        }
    }

    public VerifyVcResponse verifyCredential(VerifiableCredential credential) {
        try {
            boolean signatureValid = false;
            boolean notExpired = false;
            boolean integrityIntact = false;

            // 1. Expiration check
            if (credential.expirationDate() != null) {
                Instant expiry = Instant.parse(credential.expirationDate());
                notExpired = Instant.now().isBefore(expiry);
            } else {
                notExpired = true; // No expiration date means it doesn't expire
            }

            // 2. Signature and Integrity check
            CredentialProof proof = credential.proof();
            if (proof != null && proof.proofValue() != null) {
                // Reconstruct VC without proof to get the verified data
                VerifiableCredential unsignedCred = new VerifiableCredential(
                        credential.context(),
                        credential.id(),
                        credential.type(),
                        credential.issuer(),
                        credential.issuanceDate(),
                        credential.expirationDate(),
                        credential.credentialSubject(),
                        null
                );

                byte[] verifiedHash = computeCredentialHash(unsignedCred);
                byte[] signatureBytes = Base64.getDecoder().decode(proof.proofValue());

                // Reconstruct Issuer's Public Key from proof coordinates
                PublicKey publicKey = reconstructPublicKey(proof.publicKeyX(), proof.publicKeyY());

                Signature ecdsa = Signature.getInstance("NONEwithECDSA", BouncyCastleProvider.PROVIDER_NAME);
                ecdsa.initVerify(publicKey);
                ecdsa.update(verifiedHash);
                signatureValid = ecdsa.verify(signatureBytes);
                integrityIntact = signatureValid; // Since signature holds on the hashed contents
            }

            boolean overallVerified = signatureValid && notExpired && integrityIntact;
            VerifyVcResponse.VcChecks checks = new VerifyVcResponse.VcChecks(signatureValid, notExpired, integrityIntact);

            String subjectId = credential.credentialSubject() != null ? 
                    String.valueOf(credential.credentialSubject().get("id")) : "unknown";

            return new VerifyVcResponse(
                    overallVerified,
                    checks,
                    credential.issuer(),
                    subjectId,
                    Instant.now()
            );

        } catch (Exception e) {
            log.error("Failed to verify credential", e);
            return new VerifyVcResponse(
                    false,
                    new VerifyVcResponse.VcChecks(false, false, false),
                    credential.issuer(),
                    "unknown",
                    Instant.now()
            );
        }
    }

    private byte[] computeCredentialHash(VerifiableCredential credential) throws Exception {
        // We serialize properties in a deterministic LinkedHashMap
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("@context", credential.context());
        map.put("id", credential.id());
        map.put("type", credential.type());
        map.put("issuer", credential.issuer());
        map.put("issuanceDate", credential.issuanceDate());
        map.put("expirationDate", credential.expirationDate());
        map.put("credentialSubject", credential.credentialSubject());

        byte[] serializedBytes = objectMapper.writeValueAsBytes(map);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(serializedBytes);
    }

    private PublicKey reconstructPublicKey(String xHex, String yHex) throws GeneralSecurityException {
        try {
            X9ECParameters ecParameters = ECNamedCurveTable.getByName("secp256r1");
            BigInteger x = new BigInteger(xHex.trim(), 16);
            BigInteger y = new BigInteger(yHex.trim(), 16);

            org.bouncycastle.math.ec.ECPoint q = ecParameters.getCurve().createPoint(x, y);

            org.bouncycastle.jce.spec.ECParameterSpec ecSpec = new org.bouncycastle.jce.spec.ECParameterSpec(
                    ecParameters.getCurve(),
                    ecParameters.getG(),
                    ecParameters.getN(),
                    ecParameters.getH()
            );
            org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(q, ecSpec);

            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePublic(pubSpec);
        } catch (Exception e) {
            throw new InvalidKeySpecException("Invalid public key coordinates", e);
        }
    }
}
