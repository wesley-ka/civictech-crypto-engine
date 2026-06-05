package com.civictech.crypto.engine.signing;

import com.civictech.crypto.engine.config.CryptographicKeysConfig;
import com.civictech.crypto.engine.error.CryptoException;
import com.civictech.crypto.engine.signing.dto.SignRequest;
import com.civictech.crypto.engine.signing.dto.SignResponse;
import com.civictech.crypto.engine.signing.dto.VerifyRequest;
import com.civictech.crypto.engine.signing.dto.VerifyResponse;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Base64;

@Service
public class SigningService {

    private static final Logger log = LoggerFactory.getLogger(SigningService.class);
    private final CryptographicKeysConfig keysConfig;

    public SigningService(CryptographicKeysConfig keysConfig) {
        this.keysConfig = keysConfig;
    }

    public SignResponse sign(SignRequest request) {
        try {
            byte[] hashToSign;
            if (request.fileChecksum() != null && !request.fileChecksum().isBlank()) {
                hashToSign = decodeChecksum(request.fileChecksum());
            } else {
                byte[] rawData = Base64.getDecoder().decode(request.payloadBase64());
                hashToSign = computeSha256(rawData);
            }

            if (hashToSign.length != 32) {
                throw new IllegalArgumentException("The hash/checksum to sign must be exactly 32 bytes (SHA-256).");
            }

            // Perform ECDSA signature on the pre-computed hash
            PrivateKey privateKey = keysConfig.getSigningKeyPair().getPrivate();
            Signature ecdsa = Signature.getInstance("NONEwithECDSA", BouncyCastleProvider.PROVIDER_NAME);
            ecdsa.initSign(privateKey);
            ecdsa.update(hashToSign);
            byte[] signatureBytes = ecdsa.sign();

            String base64Signature = Base64.getEncoder().encodeToString(signatureBytes);

            // Get Public Key coordinates
            ECPublicKey publicKey = (ECPublicKey) keysConfig.getSigningKeyPair().getPublic();
            org.bouncycastle.math.ec.ECPoint q = publicKey.getQ();
            String xHex = q.getAffineXCoord().toBigInteger().toString(16);
            String yHex = q.getAffineYCoord().toBigInteger().toString(16);

            log.info("Successfully signed payload. Signature size: {} bytes", signatureBytes.length);

            return new SignResponse(
                    base64Signature,
                    xHex,
                    yHex,
                    "SHA256withECDSA",
                    Instant.now()
            );

        } catch (GeneralSecurityException e) {
            log.error("Failed to perform signing operation", e);
            throw new CryptoException("Error during signing operation", e);
        }
    }

    public VerifyResponse verify(VerifyRequest request) {
        try {
            byte[] hashToVerify;
            if (request.payloadIsHash()) {
                hashToVerify = decodeChecksum(request.originalPayload());
            } else {
                byte[] rawData = Base64.getDecoder().decode(request.originalPayload());
                hashToVerify = computeSha256(rawData);
            }

            byte[] signatureBytes = Base64.getDecoder().decode(request.signature());

            // Reconstruct Public Key from X and Y coordinates
            PublicKey publicKey = reconstructPublicKey(request.publicKeyX(), request.publicKeyY());

            Signature ecdsa = Signature.getInstance("NONEwithECDSA", BouncyCastleProvider.PROVIDER_NAME);
            ecdsa.initVerify(publicKey);
            ecdsa.update(hashToVerify);
            boolean isValid = ecdsa.verify(signatureBytes);

            log.info("Signature verification result: {}", isValid);

            return new VerifyResponse(
                    isValid,
                    "CivicTech Digital Signing Engine",
                    Instant.now()
            );

        } catch (GeneralSecurityException e) {
            log.error("Failed to perform signature verification", e);
            throw new CryptoException("Error during signature verification", e);
        }
    }

    private byte[] decodeChecksum(String checksum) {
        String clean = checksum.trim();
        if (clean.length() == 64) {
            // Hex format (64 chars for 32 bytes)
            return Hex.decode(clean);
        } else {
            // Assume Base64 format
            return Base64.getDecoder().decode(clean);
        }
    }

    private byte[] computeSha256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    private PublicKey reconstructPublicKey(String xHex, String yHex) throws GeneralSecurityException {
        try {
            X9ECParameters ecParameters = ECNamedCurveTable.getByName("secp256r1");
            ECDomainParameters domainParameters = new ECDomainParameters(
                    ecParameters.getCurve(),
                    ecParameters.getG(),
                    ecParameters.getN(),
                    ecParameters.getH()
            );

            BigInteger x = new BigInteger(xHex.trim(), 16);
            BigInteger y = new BigInteger(yHex.trim(), 16);

            org.bouncycastle.math.ec.ECPoint q = ecParameters.getCurve().createPoint(x, y);

            // Reconstruct utilizing KeyFactory
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
            throw new InvalidKeySpecException("Invalid coordinates for public key reconstruction", e);
        }
    }
}
