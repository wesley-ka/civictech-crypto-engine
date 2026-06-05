# civictech-crypto-engine

An enterprise-grade, highly secure cryptographic backend service built with **Spring Boot 3.3+ (Java 21)** and **Bouncy Castle**. This engine is designed as a modular utility for decentralized identity, secure document archiving, digital signatures, and official certificate validation in CivicTech applications.

---

## 1. Directory Structure

```
civictech-crypto-engine/
├── pom.xml
├── README.md
└── src
    └── main
        ├── java
        │   └── com
        │       └── civictech
        │           └── crypto
        │               └── engine
        │                   ├── CivicTechCryptoEngineApplication.java
        │                   ├── config
        │                   │   ├── BouncyCastleConfig.java
        │                   │   ├── CryptographicKeysConfig.java
        │                   │   ├── SecurityConfig.java
        │                   │   └── WebConfig.java
        │                   ├── error
        │                   │   ├── CryptoException.java
        │                   │   ├── ErrorResponse.java
        │                   │   └── GlobalExceptionHandler.java
        │                   ├── signing
        │                   │   ├── SigningController.java
        │                   │   ├── SigningService.java
        │                   │   └── dto
        │                   │       ├── SignRequest.java
        │                   │       ├── SignResponse.java
        │                   │       ├── VerifyRequest.java
        │                   │       └── VerifyResponse.java
        │                   ├── identity
        │                   │   ├── ZkpController.java
        │                   │   ├── ZkpService.java
        │                   │   └── dto
        │                   │       ├── ZkpVerifyRequest.java
        │                   │       └── ZkpVerifyResponse.java
        │                   ├── vault
        │                   │   ├── VaultController.java
        │                   │   ├── VaultService.java
        │                   │   └── dto
        │                   │       ├── AuditRequest.java
        │                   │       ├── AuditResponse.java
        │                   │       ├── DecryptRequest.java
        │                   │       ├── DecryptResponse.java
        │                   │       ├── EncryptRequest.java
        │                   │       └── EncryptResponse.java
        │                   ├── certificates
        │                   │   ├── CertificateController.java
        │                   │   ├── CertificateService.java
        │                   │   └── dto
        │                   │       ├── ParseCertificateRequest.java
        │                   │       └── ParseCertificateResponse.java
        │                   ├── tsa
        │                   │   ├── TsaController.java
        │                   │   ├── TsaService.java
        │                   │   └── dto
        │                   │       ├── TimestampRequest.java
        │                   │       └── TimestampResponse.java
        └── resources
            └── application.yml
```

---

## 2. Architecture Diagram

```
                                      +---------------------------------------------+
                                      |                 HTTP Client                 |
                                      +----------------------+----------------------+
                                                             | (JSON over SSL/TLS)
                                                             v
                                      +----------------------+----------------------+
                                      |             Spring Security                 |
                                      |         (Stateless, CSP Headers)            |
                                      +----------------------+----------------------+
                                                             |
                                                             v
                                      +----------------------+----------------------+
                                      |        Global Exception Handler             |
                                      |     (CryptoException -> JSON Error)         |
                                      +----------------------+----------------------+
                                                             |
                     +---------------------------------------+---------------------------------------+
                     |                       |                       |                       |
                     v                       v                       v                       v
            +--------+--------+     +--------+--------+     +--------+--------+     +--------+--------+
            |  Signing Engine |     |   ZKP Age       |     |  Document Vault |     | X.509 Parser &  |
            |   Controller    |     |  Verifier       |     |   & Audit Log   |     | Validation      |
            +--------+--------+     +--------+--------+     +--------+--------+     +--------+--------+
                     |                       |                       |                       |
                     v                       v                       v                       v
            +--------+--------+     +--------+--------+     +--------+--------+     +--------+--------+
            |  SigningService |     |   ZkpService    |     |  VaultService   |     |CertificatesServ |
            +--------+--------+     +--------+--------+     +--------+--------+     +--------+--------+
                     |                       |                       |                       |
                     +-----------------------+-----------+-----------+-----------------------+
                                                         |
                                                         v
                                      +------------------+--------------------------+
                                      |       Cryptographic Key Configuration       |
                                      |    (ECDSA secp256r1, AES-256 Thread-Safe)   |
                                      +------------------+--------------------------+
                                                         |
                                                         v
                                      +------------------+--------------------------+
                                      |        Bouncy Castle Provider Engine        |
                                      +---------------------------------------------+
```

---

## 3. Cryptographic Deep Dive

### Why ECDSA secp256r1?
* **High Efficiency & Speed**: Elliptic Curve Digital Signature Algorithm (ECDSA) keys are much smaller than RSA keys while offering equivalent or superior security. A 256-bit ECDSA key (such as `secp256r1`) provides approximately the same security level as a 3072-bit RSA key, resulting in faster signing operations, lower memory overhead, and smaller payload transmission sizes.
* **Standards Compliance (eIDAS & NIST)**: The `secp256r1` curve (also known as prime256v1 or NIST P-256) is universally supported by national authentication schemes, modern web clients, and major hardware security modules (HSMs). It complies with eIDAS standards for advanced electronic signatures.

### Why AES-256-GCM over AES-CBC?
* **AEAD (Authenticated Encryption with Associated Data)**: GCM (Galois/Counter Mode) is an AEAD mode. It provides both **confidentiality** and **integrity/authenticity** in a single operation. If a single bit of the ciphertext or the IV is tampered with, the GCM authentication tag validation fails on decryption.
* **Resistance to Padding Oracle Attacks**: Standard CBC (Cipher Block Chaining) requires padding (like PKCS#7), making it highly susceptible to padding oracle attacks (e.g., POODLE, Lucky Thirteen) unless implemented with an explicit Encrypt-then-MAC (HMAC) pattern. GCM requires no padding and is immune to padding oracle attacks.
* **Thread-Safety & IV Uniqueness**: Every encryption request uses a cryptographically secure, unique 12-byte initialization vector (IV) generated by `SecureRandom`, preventing replay attacks and cryptographic pattern recognition.

### Mathematical Verification of the ZKP Age Proof (Schnorr Protocol)
The Zero-Knowledge Age Verifier implements a Schnorr-like zero-knowledge proof of knowledge of a discrete logarithm over the `secp256r1` elliptic curve group. This simulates proving ownership of a credential (representing age eligibility) without revealing the age or credential private key.

1. **Parameters**: Let $G$ be the base generator point on the curve, and $n$ be the prime order of the curve.
2. **Prover Keys**: The Prover has a private credential key $x \in [1, n-1]$ and a public identity commitment $Y = x \cdot G$.
3. **Commitment**: The Prover chooses a random nonce $k \in [1, n-1]$ and computes the commitment point $R = k \cdot G$. The Prover commits to this by transmitting $R$ (and its SHA-256 hash `commitment_hash` to ensure binding).
4. **Challenge**: The Verifier issues a random scalar challenge $c \in [1, n-1]$.
5. **Response**: The Prover calculates the response scalar:
   $$s = k + c \cdot x \pmod n$$
6. **Verification**: The Verifier receives the proof $(R, c, s, Y)$ and performs point arithmetic:
   * **Left-Hand Side (LHS)**: computes $s \cdot G$
   * **Right-Hand Side (RHS)**: computes $R + c \cdot Y$
   * **Verification identity**:
     $$s \cdot G = (k + c \cdot x) \cdot G = k \cdot G + c \cdot (x \cdot G) = R + c \cdot Y$$
7. **Equivalence**: If $LHS = RHS$ and the hash of $R$ matches the original commitment hash, the proof is verified. The Verifier is mathematically certain the Prover knows $x$ without $x$ ever being transmitted or revealed.

---

## 4. REST Endpoints & Testing Commands

### Module 1: Digital Signing & Hashing Engine

#### 1. Sign base64 payload
* **Endpoint**: `POST /api/v1/signing/sign`
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/signing/sign \
  -H "Content-Type: application/json" \
  -d '{"payload_base64": "SGVsbG8gQ2l2aWNUZWNo"}'
```

#### 2. Verify signature
* **Endpoint**: `POST /api/v1/signing/verify`
* **Request**:
*(Replace coordinates and signature with values returned from the sign endpoint)*
```bash
curl -X POST http://localhost:8080/api/v1/signing/verify \
  -H "Content-Type: application/json" \
  -d '{
    "original_payload": "SGVsbG8gQ2l2aWNUZWNo",
    "payload_is_hash": false,
    "signature": "MEQCIFp5pY6...",
    "public_key_x": "7c98f828...",
    "public_key_y": "8f89e2c2..."
  }'
```

---

### Module 2: Zero-Knowledge Age Verifier

#### Verify Schnorr ZKP Age Proof
* **Endpoint**: `POST /api/v1/identity/zkp-verify`
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/identity/zkp-verify \
  -H "Content-Type: application/json" \
  -d '{
    "commitment_hash": "252f4eb27b165243b8110b5f1f31f9d657512a8a8ebc8702b8d0d467a99f1c78",
    "commitment_x": "8b51d8db02c4df7a19bb81005bc1610281b8be671c3e13765a6b7c875602474b",
    "commitment_y": "5a42e2ca1c5cdb2100827598c4f130281d8b671f3e137765a6b7c875602474d2",
    "challenge": "3",
    "response": "11",
    "public_key_x": "7c17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2965",
    "public_key_y": "3fe342e2ca1c5cdb2100827598c4f130281d8b671f3e137765a6b7c8756024741"
  }'
```

---

### Module 3: Secure Document Vault & Audit Trail

#### 1. Encrypt personal data
* **Endpoint**: `POST /api/v1/vault/encrypt`
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/vault/encrypt \
  -H "Content-Type: application/json" \
  -d '{"sensitive_data": {"citizen_id": "12345678Z", "full_name": "Juana de Arco", "birthdate": "1412-01-06"}}'
```

#### 2. Decrypt personal data
* **Endpoint**: `POST /api/v1/vault/decrypt`
* **Request**:
*(Replace ciphertext, iv, and auth_tag with response from encrypt endpoint)*
```bash
curl -X POST http://localhost:8080/api/v1/vault/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "abc...",
    "iv": "def...",
    "auth_tag": "ghi..."
  }'
```

#### 3. Log event in incremental audit trail (Merkle root update)
* **Endpoint**: `POST /api/v1/vault/audit`
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/vault/audit \
  -H "Content-Type: application/json" \
  -d '{"log_entry": "NOTARIAL_DEPOSIT_DOCUMENT_ID_987654"}'
```

---

### Module 4: X.509 Certificate Parser & Validation Service

#### Parse citizen digital certificate
* **Endpoint**: `POST /api/v1/certificates/parse`
* **Request**:
*(Accepts Base64 DER or standard PEM certificates)*
```bash
curl -X POST http://localhost:8080/api/v1/certificates/parse \
  -H "Content-Type: application/json" \
  -d '{"certificate_base64": "MIIB3jCCAYWgAwIBAgIGAXv..."}'
```

---

### Module 5: Cryptographic Timestamping Authority (TSA)

#### Generate sealed timestamp token (RFC 3161)
* **Endpoint**: `POST /api/v1/tsa/timestamp`
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/tsa/timestamp \
  -H "Content-Type: application/json" \
  -d '{"document_hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"}'
```

---


## 5. Production Deployment

### Docker Containerization

To run this in containerized production environments (such as Google Cloud Run, AWS Fargate, or Kubernetes), construct a two-stage build to minimize image size and attack surface:

Create a `Dockerfile` in the root:

```dockerfile
# Stage 1: Build the application
FROM maven:3.9.6-eclipse-temurin-21-alpine AS builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Distribute lightweight runtime
FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache tzdata
WORKDIR /app
COPY --from=builder /app/target/civictech-crypto-engine-1.0.0.jar app.jar

# Run as non-root user for security compliance
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 8080
ENTRYPOINT ["java", "-XX:+UseG1GC", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
```

### Production Security Best Practices:
1. **Disable Ephemeral Keys**: For production, override the ephemeral keys by mounting external keys or passing them as environment variables:
   * `CRYPTO_KEYS_SIGNING_PRIVATE_KEY_BASE64`
   * `CRYPTO_KEYS_TSA_PRIVATE_KEY_BASE64`
   * `CRYPTO_KEYS_VAULT_KEY_HEX`
2. **Enable SSL/TLS**: Configure Spring Boot to enforce HTTPS (`server.ssl.key-store` settings) or terminate TLS at your reverse proxy (NGINX/Cloud Load Balancer).
3. **Audit Logging**: Route logging outputs to standard structured JSON formats for consumption by cloud log routers (e.g. Stackdriver, CloudWatch, Datadog).
