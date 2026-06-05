package com.civictech.crypto.engine;

import com.civictech.crypto.engine.certificates.CertificateService;
import com.civictech.crypto.engine.certificates.dto.ParseCertificateRequest;
import com.civictech.crypto.engine.certificates.dto.ParseCertificateResponse;
import com.civictech.crypto.engine.identity.ZkpService;
import com.civictech.crypto.engine.identity.dto.ZkpVerifyRequest;
import com.civictech.crypto.engine.identity.dto.ZkpVerifyResponse;
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
import org.springframework.boot.test.context.SpringBootTest;


import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class CivicTechCryptoEngineApplicationTests {

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
}

