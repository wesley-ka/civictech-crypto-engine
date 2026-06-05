package com.civictech.crypto.engine.identity;

import com.civictech.crypto.engine.error.CryptoException;
import com.civictech.crypto.engine.identity.dto.ZkpVerifyRequest;
import com.civictech.crypto.engine.identity.dto.ZkpVerifyResponse;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

@Service
public class ZkpService {

    private static final Logger log = LoggerFactory.getLogger(ZkpService.class);

    public ZkpVerifyResponse verifyZkp(ZkpVerifyRequest request) {
        List<String> proofLog = new ArrayList<>();
        try {
            // 1. Get curve parameters for secp256r1
            X9ECParameters curveParams = ECNamedCurveTable.getByName("secp256r1");
            if (curveParams == null) {
                throw new CryptoException("secp256r1 curve not supported by Bouncy Castle provider.");
            }
            proofLog.add("Initialized elliptic curve secp256r1 (NIST P-256).");

            // 2. Determine base point G
            ECPoint g;
            if (request.basePointX() != null && !request.basePointX().isBlank() &&
                request.basePointY() != null && !request.basePointY().isBlank()) {
                proofLog.add("Using custom base point G.");
                g = curveParams.getCurve().createPoint(
                        new BigInteger(request.basePointX().trim(), 16),
                        new BigInteger(request.basePointY().trim(), 16)
                );
            } else {
                g = curveParams.getG();
                proofLog.add("Using standard curve generator G.");
            }
            proofLog.add(String.format("G_x = %s", g.getAffineXCoord().toBigInteger().toString(16)));
            proofLog.add(String.format("G_y = %s", g.getAffineYCoord().toBigInteger().toString(16)));

            // 3. Reconstruct commitment point R
            ECPoint r = curveParams.getCurve().createPoint(
                    new BigInteger(request.commitmentX().trim(), 16),
                    new BigInteger(request.commitmentY().trim(), 16)
            );
            proofLog.add("Reconstructed commitment point R.");
            proofLog.add(String.format("R_x = %s", r.getAffineXCoord().toBigInteger().toString(16)));
            proofLog.add(String.format("R_y = %s", r.getAffineYCoord().toBigInteger().toString(16)));

            // 4. Verify commitment hash
            byte[] rEncoded = r.getEncoded(true); // Compressed encoding
            byte[] computedRHash = computeSha256(rEncoded);
            String computedRHashHex = Hex.toHexString(computedRHash);
            proofLog.add(String.format("Computed commitment hash from R: %s", computedRHashHex));
            
            boolean hashMatches = computedRHashHex.equalsIgnoreCase(request.commitmentHash().trim());
            if (!hashMatches) {
                proofLog.add("CRITICAL: Commitment hash mismatch! Verification failed.");
                return new ZkpVerifyResponse(false, proofLog);
            }
            proofLog.add("Commitment hash verified successfully.");

            // 5. Reconstruct public key Y
            ECPoint y = curveParams.getCurve().createPoint(
                    new BigInteger(request.publicKeyX().trim(), 16),
                    new BigInteger(request.publicKeyY().trim(), 16)
            );
            proofLog.add("Reconstructed citizen's public identity key Y.");
            proofLog.add(String.format("Y_x = %s", y.getAffineXCoord().toBigInteger().toString(16)));
            proofLog.add(String.format("Y_y = %s", y.getAffineYCoord().toBigInteger().toString(16)));

            // 6. Parse scalar challenge and response
            BigInteger c = new BigInteger(request.challenge().trim(), 16);
            BigInteger s = new BigInteger(request.response().trim(), 16);
            proofLog.add(String.format("Parsed scalar challenge c: %s", c.toString(10)));
            proofLog.add(String.format("Parsed scalar response s: %s", s.toString(10)));

            // 7. Compute LHS: s * G
            ECPoint lhs = g.multiply(s).normalize();
            proofLog.add("Computed LHS: s * G.");
            proofLog.add(String.format("LHS_x = %s", lhs.getAffineXCoord().toBigInteger().toString(16)));
            proofLog.add(String.format("LHS_y = %s", lhs.getAffineYCoord().toBigInteger().toString(16)));

            // 8. Compute RHS: R + c * Y
            ECPoint rhs = r.add(y.multiply(c)).normalize();
            proofLog.add("Computed RHS: R + c * Y.");
            proofLog.add(String.format("RHS_x = %s", rhs.getAffineXCoord().toBigInteger().toString(16)));
            proofLog.add(String.format("RHS_y = %s", rhs.getAffineYCoord().toBigInteger().toString(16)));

            // 9. Compare LHS and RHS
            boolean verified = lhs.equals(rhs);
            if (verified) {
                proofLog.add("Verification Success: s * G equals R + c * Y. Decentralized age proof is mathematically valid.");
            } else {
                proofLog.add("Verification Failure: s * G does NOT equal R + c * Y. Proof is invalid.");
            }

            return new ZkpVerifyResponse(verified, proofLog);

        } catch (IllegalArgumentException | ArithmeticException e) {
            log.error("Mathematical error during Schnorr validation", e);
            proofLog.add(String.format("Error: Mathematical processing failure (%s)", e.getMessage()));
            return new ZkpVerifyResponse(false, proofLog);
        } catch (Exception e) {
            log.error("Unexpected error during ZKP verification", e);
            throw new CryptoException("Internal error during zero-knowledge proof verification", e);
        }
    }

    private byte[] computeSha256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
}
