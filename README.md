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
    │   │                   ├── cleanup
    │   │                   │   └── StorageCleanupService.java
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
    │   │                   │   ├── vc
    │   │                   │   │   ├── VcController.java
    │   │                   │   │   ├── VcService.java
    │   │                   │   │   └── dto/
    │   │                   │   └── dto/
    │   │                   ├── ledger
    │   │                   │   ├── LedgerController.java
    │   │                   │   ├── LedgerService.java
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
    │   │                   ├── vault
    │   │                   │   ├── VaultController.java
    │   │                   │   ├── VaultService.java
    │   │                   │   └── dto/
    │   │                   └── voting
    │   │                       ├── VotingController.java
    │   │                       ├── VotingService.java
    │   │                       ├── TelegramResultDeliveryService.java
    │   │                       ├── VotingResultDeliveryService.java
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
   $$\text{commitment hash} = \text{SHA-256}(R)$$
4. **Challenge (Second Step)**:
   The verifier issues a random scalar challenge $c \in [1, n-1]$. (In a non-interactive setup, this challenge is computed via the Fiat-Shamir heuristic, but in our API, the challenge is passed explicitly to support interactive protocols).
5. **Response (Third Step)**:
   The prover calculates the response scalar:
   $$s = k + c \cdot x \pmod n$$
   The proof bundle consisting of $(R, c, s, Y, \text{commitment hash})$ is sent to the verifier.
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

### 3.6 Ephemeral ZKP-Verified Voting Protocol & UOC Master's Thesis Implementation
This module provides a database-free, highly scalable, and privacy-preserving electronic voting protocol based on Zero-Knowledge Proofs (Schnorr Non-Interactive Zero-Knowledge Proofs).

> [!NOTE]
> **Academic Basis & Context**
> This voting implementation is a practical adaptation of the UOC (Universitat Oberta de Catalunya) Master's Thesis (**Trabajo Fin de Máster - TFM**):
> * **Title:** *Zero-Knowledge Technology in Blockchain*
> * **Objective:** Developed a privacy-preserving blockchain framework using Zero-Knowledge Proofs, with a prototype for secure, auditable electronic voting.
> * **Tutor:** Javier Rodríguez Fernández
> * **SRP (Second Reader):** Carlos Núñez Gómez

#### Protocol Mechanics:
1. **Creation**: An administrator creates a voting session with a custom expiration time and a Telegram reporting chat ID.
2. **Interactive Challenge**: To cast a vote, the voter generates a unique cryptographic nullifier (derived from a private passphrase and the `vote_id`) and registers it to receive a session-bound challenge.
3. **Ballot Casting (ZKP)**: The voter computes a non-interactive Schnorr proof of knowledge of the private key matching their registered public identity. The server verifies this ZKP, records the vote, and logs the nullifier to prevent double voting.
4. **Voter Anonymity (No-Link at Rest)**: The backend decouples voter identities (nullifiers) from their candidate selections by storing them in separate directories (`nullifiers/` and `ballots/`). Since ballots are written as randomized JSON objects with no timestamps or metadata linked back to the nullifiers, there is no cryptographic or physical linkage between the voter's identity and their selection.
5. **Double-Voting Prevention (No Database)**: To remain fully stateless and database-free, the engine writes nullifiers atomically to the local file system (simulating S3 conditional writes like `If-None-Match: *`). If a voter tries to vote twice, the second file write fails, and the ballot is rejected.
6. **Automatic Purging & Delivery**: Every 15 seconds, a scheduler checks for expired sessions. Upon expiration, it compiles the results, generates a **Unified JSON Audit Package** and a **Markdown Verification Guide**, uploads them to B2 Object Storage (or local storage), delivers the results directly to the creator's Telegram chat, and purges all voter-identifying nullifiers and ballot files, achieving zero persistent storage costs.

### 3.7 W3C-like Verifiable Credentials (VC) with Two-Device Flow
* **W3C Standard Alignment**:
  Verifiable Credentials (VC) provide a digitally signed cryptographic identity statement. The JSON structure conforms to the W3C Verifiable Credentials Data Model, containing a `@context`, `id` (as a URN UUID), standard types, issuer identity (`did:web:engine.civictech.org`), issuance date, expiration date, and a custom ECDSA-signed `proof` block.
* **Deterministic Hashing & Canonicalization**:
  To sign the VC securely, the engine extracts the credential data (excluding the signature proof block), marshals it into a sorted, deterministic JSON payload, and computes a SHA-256 hash. The hash is then signed using the engine's private ECDSA key.
* **Ephemeral Two-Device Mobile Verification Flow**:
  To support scanning a VC on desktop using a mobile phone without database storage:
  1. Desktop app calls `POST /api/v1/identity/vc/issue` to generate the VC. The signed VC JSON is written to ephemeral storage (such as Backblaze B2 under key `vc/{vcId}.json` or local `./local-storage/vc/{vcId}.json`).
  2. The endpoint returns the signed VC payload alongside a `shareUrl` (pointing to a shared read endpoint `/v1/identity/vc/share/{vcId}`).
  3. Desktop app displays a QR code containing a URL to a verification portal containing the `vcUrl` parameter.
  4. The user scans the QR code with their mobile phone. The mobile browser fetches the raw VC payload from `vcUrl` and calls the engine's `/api/v1/identity/vc/verify` endpoint to mathematically audit the signature.

### 3.8 Cryptographic Provenance Ledger with Chain Verification
* **Blockchain-like Transit Log**:
  Provides an immutable supply-chain or chain-of-custody audit trail for physical civic assets. Each event is recorded as a block linked to its predecessor.
* **Block Chaining**:
  Every block contains the hash of the preceding block (`previousBlockHash`). The hash of the block itself is calculated using:
  $$\text{BlockHash}_i = \text{SHA-256}(i \mathbin{\Vert} \text{Timestamp}_i \mathbin{\Vert} \text{AssetId}_i \mathbin{\Vert} \text{EventType}_i \mathbin{\Vert} \text{Custodian}_i \mathbin{\Vert} \text{Location}_i \mathbin{\Vert} \text{BlockHash}_{i-1} \mathbin{\Vert} \text{Meta}_i)$$
* **ECDSA Signature Integrity**:
  The computed block hash is signed by the engine using the configured ECDSA private key. Any modification to the data of any block (e.g. location or custodian) breaks the parent hash linkage and fails signature verification on all subsequent blocks, providing tamper evidence.
* **File/Cloud-backed Database-free Storage**:
  Blocks are written sequentially as individual JSON files in local disk (`./local-storage/ledger/{assetId}/block_{index}.json`) or Backblaze B2 prefixes (`ledger/{assetId}/block_{index}.json`). Chain audits parse the sequence to ensure order, linkage, and signature validity.

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

### Module 6: Ephemeral ZKP Voting Service

#### 1. Create a Voting Session
* **Endpoint**: `POST /api/v1/voting/create`
* **Description**: Initializes an ephemeral voting session.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/voting/create \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Decentralized Governance Election",
    "candidates": ["Alice", "Bob"],
    "duration_minutes": 5,
    "delivery_target": "-100123456789"
  }'
```
* **Expected Response**:
```json
{
  "vote_id": "18d3104c-7e33-4e42-8159-db0162db8af6",
  "expires_at": "2026-06-06T13:05:39.741518Z"
}
```

#### 2. Fetch Voting Session Info
* **Endpoint**: `GET /api/v1/voting/info/{voteId}`
* **Description**: Returns non-sensitive public configurations of the voting session (e.g., expiry date/time).
* **Request**:
```bash
curl -X GET http://localhost:8080/api/v1/voting/info/18d3104c-7e33-4e42-8159-db0162db8af6 \
  -H "Authorization: Bearer YOUR_API_KEY"
```
* **Expected Response**:
```json
{
  "vote_id": "18d3104c-7e33-4e42-8159-db0162db8af6",
  "title": "Decentralized Governance Election",
  "candidates": ["Alice", "Bob"],
  "expires_at": "2026-06-06T13:05:39.741518Z",
  "active": true
}
```

#### 3. Request Challenge (Interactive ZKP Flow)
* **Endpoint**: `POST /api/v1/voting/challenge`
* **Description**: Requests a unique session challenge bound to the voter's nullifier.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/voting/challenge \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vote_id": "18d3104c-7e33-4e42-8159-db0162db8af6",
    "nullifier": "528ed970719d58e0b1934f90789a8e1c34a20fca1251b0a3f22d649aac55d5ca",
    "public_key_x": "18e61b4c513dd59876f75722b6b26a8fc5f68bf45868e0dc301cd43a2ae745ad",
    "public_key_y": "9be1f472d9f6d37be61821cf2b887fb7bdbfc9a1fa6afa3a8413024f2f37b930"
  }'
```
* **Expected Response**:
```json
{
  "challenge": "7329d840754a514688283dc2fce126dec65caf80d72b9c5c2fdbf6472f5d55d0"
}
```

#### 4. Cast Ballot with ZKP Proof
* **Endpoint**: `POST /api/v1/voting/cast`
* **Description**: Verifies the Schnorr zero-knowledge proof of public key eligibility and casts the ballot.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/voting/cast \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "vote_id": "18d3104c-7e33-4e42-8159-db0162db8af6",
    "nullifier": "528ed970719d58e0b1934f90789a8e1c34a20fca1251b0a3f22d649aac55d5ca",
    "candidate_id": "Alice",
    "commitment_hash": "08a7f6ff03f65fbed2d158a265b4191c320895a571810f7795bcdf1da9600707",
    "commitment_x": "18e61b4c513dd59876f75722b6b26a8fc5f68bf45868e0dc301cd43a2ae745ad",
    "commitment_y": "9be1f472d9f6d37be61821cf2b887fb7bdbfc9a1fa6afa3a8413024f2f37b930",
    "challenge": "7329d840754a514688283dc2fce126dec65caf80d72b9c5c2fdbf6472f5d55d0",
    "response": "5eba4905cf500e687dc2f654c9df903e02ec44ab7532dc9818fecc09403955ef",
    "public_key_x": "18e61b4c513dd59876f75722b6b26a8fc5f68bf45868e0dc301cd43a2ae745ad",
    "public_key_y": "9be1f472d9f6d37be61821cf2b887fb7bdbfc9a1fa6afa3a8413024f2f37b930"
  }'
```
* **Expected Response**:
```json
{
  "status": "VOTE_CAST_SUCCESSFULLY"
}
```

#### 5. Fetch Final Results (Issues relative redirect to results)
* **Endpoint**: `GET /api/v1/voting/results/{voteId}`
* **Description**: Checks session expiration. If expired, compiles results to static file, triggers Telegram push, and redirects to static JSON (e.g. `/api/v1/voting/static/{voteId}/results.json`).
* **Request**:
```bash
curl -i -L -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8080/api/v1/voting/results/18d3104c-7e33-4e42-8159-db0162db8af6
```
* **Expected Response (Redirect followed)**:
Returns the final archived results JSON file containing the audit package, tallies, and verification guide.

---

### Module 7: Verifiable Credentials (VC) Wallet

#### 1. Issue Verifiable Credential
* **Endpoint**: `POST /api/v1/identity/vc/issue`
* **Description**: Generates and signs a W3C-like Verifiable Credential (VC) JSON object using the server's private key.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/identity/vc/issue \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "subjectId": "did:example:citizen123",
    "fullName": "Juana de Arco",
    "attributes": {
      "eligibleToVote": true,
      "jurisdiction": "Madrid"
    },
    "expirationDays": 30
  }'
```
* **Expected Response**:
```json
{
  "vcId": "8f2a17cb-de34-45b7-a3cf-b567b2d5a329",
  "shareUrl": "/v1/identity/vc/share/8f2a17cb-de34-45b7-a3cf-b567b2d5a329",
  "credential": {
    "@context": ["https://www.w3.org/2018/credentials/v1", "https://schema.org"],
    "id": "urn:uuid:8f2a17cb-de34-45b7-a3cf-b567b2d5a329",
    "type": ["VerifiableCredential", "CivicCitizenCredential"],
    "issuer": "did:web:engine.civictech.org",
    "issuanceDate": "2026-06-09T18:00:00Z",
    "expirationDate": "2026-07-09T18:00:00Z",
    "credentialSubject": {
      "id": "did:example:citizen123",
      "fullName": "Juana de Arco",
      "eligibleToVote": true,
      "jurisdiction": "Madrid"
    },
    "proof": {
      "type": "JsonWebSignature2020",
      "created": "2026-06-09T18:00:00Z",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "did:web:engine.civictech.org#key-1",
      "publicKeyX": "7c98f828...",
      "publicKeyY": "8f89e2c2...",
      "proofValue": "MEQCIDU4M12..."
    }
  }
}
```

#### 2. Get Shared Credential (QR Scan Endpoint)
* **Endpoint**: `GET /api/v1/identity/vc/share/{vcId}`
* **Description**: Returns the raw signed verifiable credential JSON stored in B2 or local disk.
* **Request**:
```bash
curl -X GET http://localhost:8080/api/v1/identity/vc/share/8f2a17cb-de34-45b7-a3cf-b567b2d5a329 \
  -H "Authorization: Bearer YOUR_API_KEY"
```
* **Expected Response**: Returns the raw `VerifiableCredential` JSON object containing the signature proof block.

#### 3. Verify Verifiable Credential
* **Endpoint**: `POST /api/v1/identity/vc/verify`
* **Description**: Mathematically checks the ECDSA signature, expiration, and payload integrity of a verifiable credential.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/identity/vc/verify \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "@context": ["https://www.w3.org/2018/credentials/v1", "https://schema.org"],
    "id": "urn:uuid:8f2a17cb-de34-45b7-a3cf-b567b2d5a329",
    "type": ["VerifiableCredential", "CivicCitizenCredential"],
    "issuer": "did:web:engine.civictech.org",
    "issuanceDate": "2026-06-09T18:00:00Z",
    "expirationDate": "2026-07-09T18:00:00Z",
    "credentialSubject": {
      "id": "did:example:citizen123",
      "fullName": "Juana de Arco",
      "eligibleToVote": true,
      "jurisdiction": "Madrid"
    },
    "proof": {
      "type": "JsonWebSignature2020",
      "created": "2026-06-09T18:00:00Z",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "did:web:engine.civictech.org#key-1",
      "publicKeyX": "7c98f828...",
      "publicKeyY": "8f89e2c2...",
      "proofValue": "MEQCIDU4M12..."
    }
  }'
```
* **Expected Response**:
```json
{
  "verified": true,
  "checks": {
    "signatureValid": true,
    "notExpired": true,
    "integrityIntact": true
  },
  "issuer": "did:web:engine.civictech.org",
  "subject": "did:example:citizen123",
  "verifiedAt": "2026-06-09T18:02:00Z"
}
```

---

### Module 8: Cryptographic Provenance Ledger

#### 1. Initialize Asset Ledger (Genesis Block)
* **Endpoint**: `POST /api/v1/ledger/create`
* **Description**: Starts an asset provenance history by writing block 0 (Genesis block) signed with ECDSA.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/ledger/create \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "assetId": "VM-9872",
    "assetType": "VOTING_MACHINE",
    "custodian": "Central Election Office",
    "meta": {
      "manufacturer": "Indra Systems"
    }
  }'
```
* **Expected Response**:
```json
{
  "index": 0,
  "timestamp": "2026-06-09T18:00:00Z",
  "assetId": "VM-9872",
  "eventType": "GENESIS",
  "custodian": "Central Election Office",
  "previousBlockHash": "0000000000000000000000000000000000000000000000000000000000000000",
  "blockHash": "4a7f3e1b...",
  "signature": "MEQCIE...",
  "meta": {
    "manufacturer": "Indra Systems"
  }
}
```

#### 2. Append Custody / Event Block
* **Endpoint**: `POST /api/v1/ledger/append`
* **Description**: Validates that `previousBlockHash` matches the current latest block, constructs and signs a new event block, and appends it to the chain.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/ledger/append \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "assetId": "VM-9872",
    "eventType": "CUSTODY_TRANSFER",
    "custodian": "Carrier Alpha",
    "location": "Warehouse Madrid-South",
    "previousBlockHash": "4a7f3e1b...",
    "meta": {
      "transportMode": "Truck-4"
    }
  }'
```
* **Expected Response**: Returns the appended block JSON with the computed hash and ECDSA signature.

#### 3. Fetch Asset History
* **Endpoint**: `GET /api/v1/ledger/{assetId}/history`
* **Description**: Returns all sequential ledger blocks sorted by index.
* **Request**:
```bash
curl -X GET http://localhost:8080/api/v1/ledger/VM-9872/history \
  -H "Authorization: Bearer YOUR_API_KEY"
```

#### 4. Audit Chain Verification
* **Endpoint**: `GET /api/v1/ledger/{assetId}/verify`
* **Description**: Audits the entire blockchain history for an asset, validating hash linkages and recalculating ECDSA signatures.
* **Request**:
```bash
curl -X GET http://localhost:8080/api/v1/ledger/VM-9872/verify \
  -H "Authorization: Bearer YOUR_API_KEY"
```
* **Expected Response**:
```json
{
  "assetId": "VM-9872",
  "validChain": true,
  "blockCount": 2,
  "auditReport": [
    {
      "index": 0,
      "hashMatches": true,
      "signatureValid": true,
      "blockHash": "4a7f3e1b..."
    },
    {
      "index": 1,
      "hashMatches": true,
      "signatureValid": true,
      "blockHash": "9b12e4f0..."
    }
  ]
}
```

#### 5. Reset Ledger Demo
* **Endpoint**: `DELETE /api/v1/ledger/{assetId}`
* **Description**: Completely deletes/purges the asset's transaction blocks from storage.
* **Request**:
```bash
curl -i -X DELETE http://localhost:8080/api/v1/ledger/VM-9872 \
  -H "Authorization: Bearer YOUR_API_KEY"
```
* **Expected Response**: `204 No Content`

#### 6. Database Tampering Simulator
* **Endpoint**: `POST /api/v1/ledger/{assetId}/tamper`
* **Description**: Bypasses signing logic to write a modified/tampered block to the database (modifying fields like `location` or `custodian` but leaving the original signature and hash untouched). Used to showcase audit verification catching unauthorized edits.
* **Request**:
```bash
curl -X POST http://localhost:8080/api/v1/ledger/VM-9872/tamper \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "index": 1,
    "location": "Unknown Warehouse"
  }'
```

---

### Module 9: Automated Storage Cleanup Service
* **Trigger**: Scheduled daily at 3:00 AM.
* **Description**: Scans the subfolders `voting/`, `ledger/`, and `vc/` (both on the local filesystem `./local-storage` and Backblaze B2 bucket prefixes) and purges all groups of objects or files whose files are older than 7 days, minimizing external storage overhead.

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
