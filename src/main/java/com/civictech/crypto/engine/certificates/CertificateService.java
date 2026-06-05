package com.civictech.crypto.engine.certificates;

import com.civictech.crypto.engine.certificates.dto.ParseCertificateRequest;
import com.civictech.crypto.engine.certificates.dto.ParseCertificateResponse;
import com.civictech.crypto.engine.error.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class CertificateService {

    private static final Logger log = LoggerFactory.getLogger(CertificateService.class);

    private static final String[] KEY_USAGE_NAMES = {
            "digitalSignature", // 0
            "nonRepudiation",   // 1
            "keyEncipherment",  // 2
            "dataEncipherment", // 3
            "keyAgreement",     // 4
            "keyCertSign",      // 5
            "cRLSign",          // 6
            "encipherOnly",     // 7
            "decipherOnly"      // 8
    };

    public ParseCertificateResponse parseCertificate(ParseCertificateRequest request) {
        List<String> validationLog = new ArrayList<>();
        try {
            byte[] certBytes = decodeCertificate(request.certificateBase64());
            
            CertificateFactory factory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));

            validationLog.add("Successfully parsed certificate structure as X.509 v" + cert.getVersion());

            String subjectDn = cert.getSubjectX500Principal().getName();
            String issuerDn = cert.getIssuerX500Principal().getName();
            String serialNumber = cert.getSerialNumber().toString(16).toUpperCase();
            Instant validFrom = cert.getNotBefore().toInstant();
            Instant validTo = cert.getNotAfter().toInstant();
            String sigAlg = cert.getSigAlgName();

            validationLog.add("Subject DN: " + subjectDn);
            validationLog.add("Issuer DN: " + issuerDn);
            validationLog.add("Serial Number (HEX): " + serialNumber);
            validationLog.add("Signature Algorithm: " + sigAlg);

            // Check validity dates
            Instant now = Instant.now();
            boolean isExpired = now.isAfter(validTo);
            boolean isNotYetValid = now.isBefore(validFrom);

            if (isExpired) {
                validationLog.add("WARNING: Certificate is EXPIRED. Expiration date: " + validTo);
            } else if (isNotYetValid) {
                validationLog.add("WARNING: Certificate is not yet valid. Activation date: " + validFrom);
            } else {
                validationLog.add("Success: Certificate is currently within its validity period.");
            }

            // Map Key Usage bits
            List<String> keyUsages = new ArrayList<>();
            boolean[] certKeyUsage = cert.getKeyUsage();
            if (certKeyUsage != null) {
                for (int i = 0; i < KEY_USAGE_NAMES.length && i < certKeyUsage.length; i++) {
                    if (certKeyUsage[i]) {
                        keyUsages.add(KEY_USAGE_NAMES[i]);
                    }
                }
                validationLog.add("Mapped Key Usage extensions: " + keyUsages);
            } else {
                validationLog.add("No Key Usage extensions defined in the certificate.");
            }

            // Cryptographic signature check
            boolean signatureValid = false;
            if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                validationLog.add("Certificate is self-signed. Verifying cryptographic signature against its own public key...");
                try {
                    cert.verify(cert.getPublicKey());
                    signatureValid = true;
                    validationLog.add("Success: Self-signed signature verified and matches the public key.");
                } catch (Exception e) {
                    validationLog.add("ERROR: Self-signed signature is INVALID: " + e.getMessage());
                }
            } else {
                validationLog.add("Certificate is issued by an external Authority (CA).");
                validationLog.add("Note: Full path verification requires loading the issuer's public key from a TrustStore.");
                // As a fallback validation step for isolated verification, we check if we can verify it (normally throws unless parent key matches)
                validationLog.add("Cryptographic self-consistency check skipped (requires parent CA certificate).");
                // For external certificates, we cannot prove validity without CA cert, but if we parsed it without structural errors, it's structurally valid.
                // We return signatureValid = true if it has valid structural components and is not expired, or false to represent "unverified".
                // Let's set signatureValid to false, reflecting that it is unverified by a CA in this isolated call, but indicate structure is correct.
                signatureValid = false; 
            }

            return new ParseCertificateResponse(
                    subjectDn,
                    issuerDn,
                    serialNumber,
                    validFrom,
                    validTo,
                    keyUsages,
                    isExpired,
                    sigAlg,
                    signatureValid,
                    validationLog
            );

        } catch (Exception e) {
            log.error("Failed to parse X.509 certificate", e);
            throw new CryptoException("Failed to parse the provided certificate. Make sure it is a valid PEM/DER encoded X.509 certificate.", e);
        }
    }

    private byte[] decodeCertificate(String input) {
        String cleaned = input.trim();
        // Remove PEM headers if present
        if (cleaned.contains("-----BEGIN CERTIFICATE-----")) {
            cleaned = cleaned
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", ""); // Remove all whitespace/newlines
        }
        return Base64.getDecoder().decode(cleaned);
    }
}
