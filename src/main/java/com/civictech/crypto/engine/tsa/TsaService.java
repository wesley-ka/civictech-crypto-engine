package com.civictech.crypto.engine.tsa;

import com.civictech.crypto.engine.config.CryptographicKeysConfig;
import com.civictech.crypto.engine.error.CryptoException;
import com.civictech.crypto.engine.tsa.dto.TimestampRequest;
import com.civictech.crypto.engine.tsa.dto.TimestampResponse;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Service
public class TsaService {

    private static final Logger log = LoggerFactory.getLogger(TsaService.class);

    private final CryptographicKeysConfig keysConfig;
    private TimeStampTokenGenerator tokenGenerator;

    public TsaService(CryptographicKeysConfig keysConfig) {
        this.keysConfig = keysConfig;
    }

    @PostConstruct
    public void init() {
        try {
            KeyPair keyPair = keysConfig.getTsaKeyPair();
            X500Name name = new X500Name("CN=CivicTech TSA, O=CivicTech, C=ES");
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Date from = new Date(System.currentTimeMillis() - 1000L * 60 * 60); // 1 hour ago
            Date to = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365); // 1 year

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    name,
                    serial,
                    from,
                    to,
                    name,
                    keyPair.getPublic()
            );

            // Add Extended Key Usage for Time Stamping (critical as per RFC 3161)
            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping);
            certBuilder.addExtension(Extension.extendedKeyUsage, true, extendedKeyUsage);

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keyPair.getPrivate());

            X509CertificateHolder certHolder = certBuilder.build(signer);

            DigestCalculatorProvider digestCalcProvider = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build();

            // Build SignerInfoGenerator as required by TimeStampTokenGenerator
            SignerInfoGenerator signerInfoGen = new JcaSignerInfoGeneratorBuilder(digestCalcProvider)
                    .build(signer, certHolder);

            // Custom Enterprise TSA policy OID
            ASN1ObjectIdentifier policyOid = new ASN1ObjectIdentifier("1.3.6.1.4.1.13762.3");

            this.tokenGenerator = new TimeStampTokenGenerator(
                    signerInfoGen,
                    digestCalcProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                    policyOid
            );

            this.tokenGenerator.addCertificates(new CollectionStore<>(List.of(certHolder)));
            log.info("TSA Service successfully initialized with self-signed certificate.");

        } catch (Exception e) {
            log.error("Failed to initialize TSA Service", e);
            throw new IllegalStateException("TSA Service initialization failed", e);
        }
    }

    public TimestampResponse generateTimestamp(TimestampRequest request) {
        try {
            byte[] hashBytes = decodeHash(request.documentHash());

            BigInteger nonce;
            if (request.nonce() != null && !request.nonce().isBlank()) {
                nonce = new BigInteger(request.nonce().trim(), 16);
            } else {
                nonce = new BigInteger(64, new SecureRandom());
            }

            TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
            reqGen.setCertReq(true);
            TimeStampRequest tsRequest = reqGen.generate(
                    NISTObjectIdentifiers.id_sha256,
                    hashBytes,
                    nonce
            );

            java.util.Set<ASN1ObjectIdentifier> acceptedAlgorithms = java.util.Set.of(NISTObjectIdentifiers.id_sha256);
            TimeStampResponseGenerator respGen = new TimeStampResponseGenerator(
                    tokenGenerator,
                    acceptedAlgorithms
            );

            Date time = new Date();
            BigInteger serial = BigInteger.valueOf(System.nanoTime()); // Serial number of token

            org.bouncycastle.tsp.TimeStampResponse tsResponse = respGen.generate(tsRequest, serial, time);
            tsResponse.validate(tsRequest);

            TimeStampToken token = tsResponse.getTimeStampToken();
            byte[] encodedToken = token.getEncoded();
            String base64Token = Base64.getEncoder().encodeToString(encodedToken);

            java.util.Collection<SignerInformation> signers = token.toCMSSignedData().getSignerInfos().getSigners();
            byte[] rawSignatureBytes = signers.isEmpty() ? new byte[0] : signers.iterator().next().getSignature();
            String base64Signature = Base64.getEncoder().encodeToString(rawSignatureBytes);

            ECPublicKey publicKey = (ECPublicKey) keysConfig.getTsaKeyPair().getPublic();
            String xHex = publicKey.getQ().getAffineXCoord().toBigInteger().toString(16);
            String yHex = publicKey.getQ().getAffineYCoord().toBigInteger().toString(16);

            log.info("TSA Token generated. Serial: {}, Hash: {}", serial.toString(16).toUpperCase(), Hex.toHexString(hashBytes));

            return new TimestampResponse(
                    base64Token,
                    serial.toString(16).toUpperCase(),
                    time.toInstant(),
                    nonce.toString(16).toUpperCase(),
                    "SHA-256",
                    Hex.toHexString(hashBytes),
                    base64Signature,
                    xHex,
                    yHex
            );

        } catch (Exception e) {
            log.error("Failed to generate cryptographic timestamp token", e);
            throw new CryptoException("Error during TSA timestamp token creation", e);
        }
    }

    private byte[] decodeHash(String hash) {
        String clean = hash.trim();
        if (clean.length() == 64) {
            return Hex.decode(clean);
        } else {
            return Base64.getDecoder().decode(clean);
        }
    }
}
