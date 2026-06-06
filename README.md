# CivicTech Cryptographic Engine

[![Java Version](https://img.shields.io/badge/Java-21-orange.svg)](https://www.oracle.com/java/technologies/downloads/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3%2B-green.svg)](https://spring.io/projects/spring-boot)
[![Security](https://img.shields.io/badge/Security-API--Key--Authenticated-blue.svg)](#security-architecture)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An enterprise-grade, highly secure, and stateless cryptographic microservice built on **Spring Boot 3.3+ (Java 21)** and powered by **Bouncy Castle**. 

This engine is designed to serve as a hardened, high-performance cryptographic utility for modern CivicTech applications, decentralized identity platforms, secure document archiving systems, and official digital certificate validation.

---

## 1. Directory Structure

```
civictech-crypto-engine/
├── pom.xml
├── README.md
├── Dockerfile
└── src
    ├── main
    │   ├── java
    │   │   └── com
    │   │       └── civictech
    │   │           └── crypto
    │   │               └── engine
    │   │                   ├── CivicTechCryptoEngineApplication.java
    │   │                   ├── certificates
    │   │                   │   ├── CertificateController.java
    │   │                   │   ├── CertificateService.java
    │   │                   │   └── dto/
    │   │                   ├── config
    │   │                   │   ├── BouncyCastleConfig.java
    │   │                   │   ├── CryptographicKeysConfig.java
    │   │                   │   ├── SecurityConfig.java
    │   │                   │   └── WebConfig.java
    │   │                   ├── error
    │   │                   │   ├── CryptoException.java
    │   │                   │   ├── ErrorResponse.java
    │   │                   │   └── GlobalExceptionHandler.java
    │   │                   ├── health
    │   │                   │   └── HealthController.java
    │   │                   ├── identity
    │   │                   │   ├── ZkpController.java
    │   │                   │   ├── ZkpService.java
    │   │                   │   └── dto/
    │   │                   ├── security
    │   │                   │   ├── ApiKeyAuthFilter.java
    │   │                   │   ├── ApiKeyAuthentication.java
    │   │                   │   └── ApiKeyConfig.java
    │   │                   ├── signing
    │   │                   │   ├── SigningController.java
    │   │                   │   ├── SigningService.java
    │   │                   │   └── dto/
    │   │                   ├── tsa
    │   │                   │   ├── TsaController.java
    │   │                   │   ├── TsaService.java
    │   │                   │   └── dto/
    │   │                   └── vault
    │   │                       ├── VaultController.java
    │   │                       ├── VaultService.java
    │   │                       └── dto/
    │   └── resources
    │       └── application.yml
    └── test
        └── java
            └── com
                └── civictech
                    └── crypto
                        └── engine
                            └── CivicTechCryptoEngineApplicationTests.java
```

---

## 2. Architecture & Design Principles

```
                                      +---------------------------------------------+
                                      |                 HTTP Client                 |
                                      +----------------------+----------------------+
                                                             | (JSON over SSL/TLS with API Key)
                                                             v
                                      +----------------------+----------------------+
                                      |             Spring Security                 |
                                      |      (Stateless API Key Authentication)     |
                                      +----------------------+----------------------+
                                                             |
                                                             v
                                      +----------------------+----------------------+
                                      |        Global Exception Handler             |
                                      |    (Sanitizes output, hides stack traces)   |
                                      +----------------------+----------------------+
                                                             |
                      +--------------------------------------+---------------------------------------+
                      |                       |                       |                              |
                      v                       v                       v                              v
             +--------+--------+     +--------+--------+     +--------+--------+            +--------+--------+
             |  Signing Engine |     |   ZKP Age       |     |  Document Vault |            | X.509 Parser &  |
             |   Controller    |     |  Verifier       |     |   & Audit Log   |            | Validation      |
             +--------+--------+     +--------+--------+     +--------+--------+            +--------+--------+
                      |                       |                       |                              |
                      v                       v                       v                              v
             +--------+--------+     +--------+--------+     +--------+--------+            +--------+--------+
             |  SigningService |     |   ZkpService    |     |  VaultService   |            |CertificatesServ |
             +--------+--------+     +--------+--------+     +--------+--------+            +--------+--------+
                      |                       |                       | (Incremental Ledger)         |
                      |                       |                       | [Block Hash -> Merkle Root]  |
                      |                       |                       +--------------+               |
                      |                       |                                      |               |
                      +-----------------------+-----------+--------------------------+---------------+
                                                          |
                                                          v
                                       +------------------+--------------------------+
                                       |       Cryptographic Key Configuration       |
                                       |   (Supports Environment Variables, fallbacks |
                                       |     to random Ephemeral Keys on startup)    |
                                       +------------------+--------------------------+
                                                          |
                                                          v
                                       +------------------+--------------------------+
                                       |        Bouncy Castle Provider Engine        |
                                       +---------------------------------------------+
```

### Stateless & Horizontally Scalable
The engine does not maintain a persistent database. It performs all cryptographic operations in-memory and expects clients to provide the required states (ciphertext, signature, keys, or nonces) in request payloads. This design makes the engine exceptionally light, highly scalable, and perfect for containerized deployment in serverless container environments (e.g., Google Cloud Run, AWS Fargate).

### Hardened Error Handling
A global exception handler captures any system failures or formatting errors and converts them to standard RFC 7807-like error responses. Stack traces are suppressed at the REST layer to prevent information disclosure attacks.

---

## 3. Cryptographic Deep Dive

### 3.1 Digital Signatures: ECDSA secp256r1
* **Why ECDSA over RSA?**
  Digital signing in this engine is backed by the Elliptic Curve Digital Signature Algorithm (ECDSA). A 256-bit ECDSA key (specifically the `secp256r1` curve, also known as prime256v1 or NIST P-256) offers equivalent cryptographic strength to a 3072-bit RSA key. The smaller key size translates into significantly faster computation, drastically reduced memory usage, and much smaller network payloads.
* **Standards Compliance**
  The `secp256r1` curve is a standard curve recommended by NIST and approved under European eIDAS regulations for Advanced Electronic Signatures (AdES).
* **Deterministic vs. Randomized Signatures**
  The engine utilizes the standard DSA signing process over elliptic curves, which relies on a cryptographically strong random number generator (`SecureRandom`) to ensure that signing the same payload multiple times results in unique signatures, mitigating signature replay and structural analysis attacks.

### 3.2 Authenticated Encryption: AES-256-GCM
* **Why GCM over CBC?**
  For encrypting personal identifiable information (PII) or sensitive records, the Document Vault module uses Advanced Encryption Standard in Galois/Counter Mode (AES-GCM). AES-GCM is an **Authenticated Encryption with Associated Data (AEAD)** cipher. Unlike traditional modes like CBC (which only guarantee confidentiality and require an external MAC to ensure integrity), GCM natively produces an authentication tag. 
* **Padding Oracle Mitigation**
  Because GCM is a stream-based mode that does not require block padding, it is completely immune to padding oracle attacks (such as POODLE or Lucky Thirteen) which frequently plague CBC implementations.
* **Initialization Vectors (IV)**
  Each encryption request generates a cryptographically secure, unique 12-byte initialization vector (IV) using `SecureRandom`. Reusing an IV with the same key in GCM destroys its security properties; the engine strictly enforces unique IV generation per operation to ensure cipher integrity.

### 3.3 Zero-Knowledge Proofs (Schnorr NIZKP)
The Zero-Knowledge Age Verifier implements a non-interactive variant of the **Schnorr Proof of Knowledge** over the `secp256r1` elliptic curve group. This allows a citizen to prove they possess a private credential (e.g., matching a public identity key) without revealing any information about the private key itself.

#### Mathematical Steps of the Protocol:
1. **System Setup**:
   Let $G$ be the base generator point on the `secp256r1` curve, and $n$ be the prime order of the subgroup generated by $G$.
2. **Prover Keypair**:
   The citizen has a private key $x \in [1, n-1]$ and a public identity key $Y = x \cdot G$.
3. **Commitment (First Step)**:
   The prover generates a random ephemeral nonce $k \in [1, n-1]$ and computes a commitment point on the curve:
   $$R = k \cdot G$$
   The prover computes the SHA-256 hash of the compressed commitment point $R$ to bind it:
   $$\text{commitment\_hash} = \text{SHA-256}(R)$$
4. **Challenge (Second Step)**:
   The verifier issues a random scalar challenge $c \in [1, n-1]$. (In a non-interactive setup, this challenge is computed via the Fiat-Shamir heuristic, but in our API, the challenge is passed explicitly to support interactive protocols).
5. **Response (Third Step)**:
   The prover calculates the response scalar:
   $$s = k + c \cdot x \pmod n$$
   The proof bundle consisting of $(R, c, s, Y, \text{commitment\_hash})$ is sent to the verifier.
6. **Verification**:
   The verifier receives the proof and performs the following verification:
   * Re-computes the SHA-256 hash of the compressed point $R$ and checks if it matches the received `commitment_hash`.
   * Computes the Left-Hand Side (LHS) of the verification identity:
     $$\text{LHS} = s \cdot G$$
   * Computes the Right-Hand Side (RHS) of the verification identity:
     $$\text{RHS} = R + c \cdot Y$$
   * Checks if $\text{LHS} = \text{RHS}$.
   
   **Mathematical Proof of Correctness**:
   $$\text{LHS} = s \cdot G = (k + c \cdot x) \cdot G = k \cdot G + c \cdot (x \cdot G) = R + c \cdot Y = \text{RHS}$$

### 3.4 Cryptographic Audit Trail (Blockchain Ledger)
The Document Vault includes a thread-safe, in-memory incremental blockchain ledger.
* **Block Hashing**:
  Each log entry is bound into a block containing:
  $$\text{BlockHash}_i = \text{SHA-256}(i \mathbin{\Vert} \text{Timestamp}_i \mathbin{\Vert} \text{LogEntry}_i \mathbin{\Vert} \text{BlockHash}_{i-1})$$
* **Merkle Root Verification**:
  Whenever a new audit block is created, a Merkle Tree is dynamically computed across the entire chain of block hashes. The resulting Merkle Root represents the unified cryptographic state of the ledger. If any block in the past is modified, its hash changes, breaking the hash chain and generating a completely different Merkle Root, making unauthorized tampering immediately evident.

### 3.5 RFC 3161 TSA Timestamps
The Timestamping Authority (TSA) module creates digitally signed timestamp tokens according to the **RFC 3161** standard.
* It binds a SHA-256 hash of a document/transaction with a trusted system date and time.
* It signs the response token using an ECDSA key configured with the critical `id-kp-timeStamping` Extended Key Usage (EKU) extension.
* The output token is formatted as a DER-encoded Cryptographic Message Syntax (CMS) structure, ensuring complete interoperability with standard document signing software (like Adobe Acrobat or DocuSign).

---

## 4. API Specification & Testing Commands

To authenticate against the API, you must provide the API key in the `Authorization` header.
* **Header format**: `Authorization: Bearer <your_api_key>`
* If no key is set in your environment variables, check the console output on startup for the generated **ephemeral API key**.

---

### Module 1: Digital Signing & Hashing Engine

#### 1. Sign base64 payload
* **Endpoint**: `POST /api/v1/signing/sign`
* **Description**: Signs a Base64-encoded payload using the configured ECDSA private key.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/signing/sign \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"payload_base64": "SGVsbG8gQ2l2aWNUZWNo"}'
```
* **Expected Response**:
```json
{
  "signature": "MEQCIDU4M12...",
  "public_key_x": "7c98f828...",
  "public_key_y": "8f89e2c2...",
  "algorithm": "SHA256withECDSA"
}
```

#### 2. Verify signature
* **Endpoint**: `POST /api/v1/signing/verify`
* **Description**: Verifies a signature against the original payload and public key coordinates.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/signing/verify \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "original_payload": "SGVsbG8gQ2l2aWNUZWNo",
    "payload_is_hash": false,
    "signature": "MEQCIDU4M12...",
    "public_key_x": "7c98f828...",
    "public_key_y": "8f89e2c2..."
  }'
```
* **Expected Response**:
```json
{
  "valid": true,
  "issuer": "CivicTech Digital Signing Engine"
}
```

---

### Module 2: Zero-Knowledge Age Verifier

#### Verify Schnorr ZKP Age Proof
* **Endpoint**: `POST /api/v1/identity/zkp-verify`
* **Description**: Validates a non-interactive Schnorr proof of identity/age eligibility.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/identity/zkp-verify \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "commitment_hash": "252f4eb27b165243b8110b5f1f31f9d657512a8a8ebc8702b8d0d467a99f1c78",
    "commitment_x": "8b51d8db02c4df7a19bb81005bc1610281b8be671c3e13765a6b7c875602474b",
    "commitment_y": "5a42e2ca1c5cdb2100827598c4f130281d8b671f3e137765a6b7c875602474d",
    "challenge": "3",
    "response": "11",
    "public_key_x": "7c17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "public_key_y": "3fe342e2ca1c5cdb2100827598c4f130281d8b671f3e137765a6b7c875602474"
  }'
```
* **Expected Response**:
```json
{
  "verified": true,
  "proof_log": [
    "Initialized elliptic curve secp256r1 (NIST P-256).",
    "Using standard curve generator G.",
    "Reconstructed commitment point R.",
    "Commitment hash verified successfully.",
    "Reconstructed citizen's public identity key Y.",
    "Verification Success: s * G equals R + c * Y. Decentralized age proof is mathematically valid."
  ]
}
```

---

### Module 3: Secure Document Vault & Audit Trail

#### 1. Encrypt personal data
* **Endpoint**: `POST /api/v1/vault/encrypt`
* **Description**: Encrypts an arbitrary JSON payload using AES-256-GCM.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/vault/encrypt \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sensitive_data": {"citizen_id": "12345678Z", "full_name": "Juana de Arco", "birthdate": "1412-01-06"}}'
```
* **Expected Response**:
```json
{
  "ciphertext": "SGVsbG8...",
  "iv": "dGVzdElW...",
  "auth_tag": "dGFnQXV0a..."
}
```

#### 2. Decrypt personal data
* **Endpoint**: `POST /api/v1/vault/decrypt`
* **Description**: Decrypts and verifies the integrity of the ciphertext using AES-256-GCM.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/vault/decrypt \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "SGVsbG8...",
    "iv": "dGVzdElW...",
    "auth_tag": "dGFnQXV0a..."
  }'
```
* **Expected Response**:
```json
{
  "decrypted_data": {
    "citizen_id": "12345678Z",
    "full_name": "Juana de Arco",
    "birthdate": "1412-01-06"
  }
}
```

#### 3. Log event in incremental audit trail
* **Endpoint**: `POST /api/v1/vault/audit`
* **Description**: Records an action in the blockchain-like audit trail and returns the new Merkle Root.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/vault/audit \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"log_entry": "NOTARIAL_DEPOSIT_DOCUMENT_ID_987654"}'
```
* **Expected Response**:
```json
{
  "index": 1,
  "timestamp": "2026-06-06T09:45:00Z",
  "log_entry": "NOTARIAL_DEPOSIT_DOCUMENT_ID_987654",
  "previous_hash": "8e5587172a83e511fd31...",
  "block_hash": "2f458ab398ca8e3d...",
  "merkle_root": "d76fdc0576db8494aad430a..."
}
```

---

### Module 4: X.509 Certificate Parser & Validation Service

#### Parse certificate
* **Endpoint**: `POST /api/v1/certificates/parse`
* **Description**: Parses a Base64-encoded X.509 certificate, extracting extension constraints, validity, and checking the signature.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/certificates/parse \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"certificate_base64": "MIIB3jCCAYWgAwIBAgIGAXv..."}'
```
* **Expected Response**:
```json
{
  "subject_dn": "CN=Citizen Juana, O=CivicTech, C=ES",
  "issuer_dn": "CN=Citizen Juana, O=CivicTech, C=ES",
  "serial_number": "18FC1A9B",
  "valid_from": "2026-06-06T08:00:00Z",
  "valid_to": "2027-06-06T08:00:00Z",
  "key_usage": ["digitalSignature", "nonRepudiation"],
  "signature_valid": true,
  "is_expired": false
}
```

---

### Module 5: Cryptographic Timestamping Authority (TSA)

#### Generate RFC 3161 timestamp token
* **Endpoint**: `POST /api/v1/tsa/timestamp`
* **Description**: Generates an RFC 3161 compliant, digitally signed timestamp token for a document hash.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/tsa/timestamp \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"document_hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"}'
```
* **Expected Response**:
```json
{
  "token_base64": "MIIHCAYJKoZIhvcNAQcCoIIH8...",
  "serial_number": "2647ECF1D2F",
  "timestamp": "2026-06-06T09:45:30Z",
  "nonce": "7A2B3C4D",
  "hash_algorithm": "SHA-256",
  "document_hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
  "signature": "MEQCIDU4M12...",
  "public_key_x": "7c98f828...",
  "public_key_y": "8f89e2c2..."
}
```

---

## 5. Security Architecture & Hardening

### 5.1 Custom API Key Authentication
The application implements an API Key authentication mechanism intercepting requests using a stateless filter (`ApiKeyAuthFilter.java`).
* It checks the `Authorization` header for a `Bearer <key>` structure.
* The API key configuration is handled by `ApiKeyConfig.java`.
* **EPHEMERAL FALLBACK**: If no API key is specified via configuration or environment variables, a cryptographically secure 32-byte hexadecimal key is dynamically generated on startup. This ensures the service is **secure-by-default** and prevents anyone from interacting with the engine in test/dev environments without authentication.

### 5.2 Thread-Safe Cryptographic Keys
All cryptographic keys (EC KeyPairs and SecretKeys) are loaded and cached in-memory at startup by `CryptographicKeysConfig.java`. The services access these keys in a read-only, thread-safe manner, eliminating key-derivation bottlenecks during request processing.

---

## 6. Local Development & Testing

### Prerequisites
* **Java 21** (JDK 21) installed.
* **Maven 3.9+** installed.

### Compiling and Running Tests
To compile the project and execute all cryptographic unit/integration tests, run:
```bash
mvn clean test
```
The test suite in `CivicTechCryptoEngineApplicationTests.java` covers:
1. Elliptic Curve Digital Signatures generation and verification.
2. Complete Schnorr Zero-Knowledge proof verification arithmetic.
3. AES-256-GCM encryption/decryption validation and incremental blockchain-audit logic.
4. X.509 Base64 Parser verification.
5. RFC 3161 TSA token generation and signature verification.

### Running the Application Locally
Run the Spring Boot application using Maven:
```bash
mvn spring-boot:run
```
Upon startup, the application runs on port `8080` with a servlet context path `/api` (making root URL: `http://localhost:8080/api`).

---

## 7. Production Deployment & CI/CD

### 7.1 Docker Containerization
To package the application for production, a lightweight and secure two-stage Docker build is utilized:

```dockerfile
# Stage 1: Build the application jar
FROM maven:3.9.6-eclipse-temurin-21-alpine AS builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Distribute lightweight JRE runtime
FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache tzdata
WORKDIR /app
COPY --from=builder /app/target/civictech-crypto-engine-1.0.0.jar app.jar

# Run as non-root user for security compliance and container hardening
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 8080

# Configure G1 Garbage Collector and restrict JVM memory usage to container limits
ENTRYPOINT ["java", "-XX:+UseG1GC", "-XX:MaxRAMPercentage=75.0", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar"]
```

### 7.2 Production Environment Variables
In production, you should override the ephemeral keys by injecting external configurations through environment variables:

| Variable Name | Description | Example / Format |
|---|---|---|
| `PORT` | Container Port to bind to (Default: 8080). | `8080` |
| `CRYPTO_API_KEY` | Hex-encoded API Key to authenticate REST calls. | `a1b2c3d4e5f6...` |
| `CRYPTO_KEYS_SIGNING_PRIVATE_KEY_BASE64` | Base64-encoded PKCS8 private key for signing. | `MIGHAgEAMBMGByqGSM49AgEG...` |
| `CRYPTO_KEYS_TSA_PRIVATE_KEY_BASE64` | Base64-encoded PKCS8 private key for TSA. | `MIGHAgEAMBMGByqGSM49AgEG...` |
| `CRYPTO_KEYS_VAULT_KEY_HEX` | 32-byte Hex-encoded key for AES-256 encryption. | `8c1f92e039b8...` |

### 7.3 Production Security Checklist
1. **SSL/TLS Termination**: Always run this engine behind a TLS-terminating load balancer (e.g., Google Cloud HTTPS Load Balancer, AWS ALB) or reverse-proxy (NGINX) enforcing TLS 1.3.
2. **Key Rotation**: Rotate the vault and signing keys regularly. In case of signing key rotation, register the previous public key as a valid historical verifier key in client applications.
3. **Structured Logging**: Configure log output formats to JSON (such as Logstash Logback Encoder) to route metrics and logs directly to central log processors (e.g., Datadog, ELK, Google Cloud Logging).
