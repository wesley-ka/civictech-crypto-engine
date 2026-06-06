package com.civictech.crypto.engine.quantum;

import com.civictech.crypto.engine.security.ApiKeyConfig;
import com.civictech.crypto.engine.quantum.dto.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class QuantumServiceTests {

    @Autowired
    private QuantumService quantumService;

    @Autowired
    private ApiKeyConfig apiKeyConfig;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testDirectServiceKeygenEncryptDecrypt() {
        // 1. Generate keypair
        KeyGenResponse keypair = quantumService.generateKeyPair();
        assertNotNull(keypair);
        assertEquals("ML-KEM-768", keypair.algorithm());
        assertEquals(1184, keypair.publicKeyLength());
        assertEquals(2400, keypair.privateKeyLength());

        // Validate base64url encoding
        byte[] decodedPub = Base64.getUrlDecoder().decode(keypair.publicKey());
        byte[] decodedPriv = Base64.getUrlDecoder().decode(keypair.privateKey());
        assertEquals(1184, decodedPub.length);
        assertEquals(2400, decodedPriv.length);

        // 2. Encrypt message
        String plaintext = "Secret civic technology vote payload";
        EncryptRequest encryptRequest = new EncryptRequest(keypair.publicKey(), plaintext);
        EncryptResponse encryptResponse = quantumService.encrypt(encryptRequest);

        assertNotNull(encryptResponse);
        assertEquals("ML-KEM-768 + AES-256-GCM", encryptResponse.algorithm());
        assertNotNull(encryptResponse.kemCiphertext());
        assertNotNull(encryptResponse.iv());
        assertNotNull(encryptResponse.encryptedMessage());
        assertNotNull(encryptResponse.sharedSecretHash());

        // Validate lengths of ciphertext and IV
        byte[] decodedKemCiphertext = Base64.getUrlDecoder().decode(encryptResponse.kemCiphertext());
        byte[] decodedIv = Base64.getUrlDecoder().decode(encryptResponse.iv());
        byte[] decodedEncryptedMessage = Base64.getUrlDecoder().decode(encryptResponse.encryptedMessage());

        assertEquals(1088, decodedKemCiphertext.length);
        assertEquals(12, decodedIv.length);
        // Ciphertext with 16-byte tag should be plaintext length + 16
        assertEquals(plaintext.getBytes().length + 16, decodedEncryptedMessage.length);

        // 3. Decrypt message
        DecryptRequest decryptRequest = new DecryptRequest(
                keypair.privateKey(),
                encryptResponse.kemCiphertext(),
                encryptResponse.iv(),
                encryptResponse.encryptedMessage()
        );
        DecryptResponse decryptResponse = quantumService.decrypt(decryptRequest);

        assertNotNull(decryptResponse);
        assertEquals("ML-KEM-768 + AES-256-GCM", decryptResponse.algorithm());
        assertEquals(plaintext, decryptResponse.decryptedText());
        assertEquals(encryptResponse.sharedSecretHash(), decryptResponse.sharedSecretHash());
    }

    @Test
    void testDecryptionWithTamperedCiphertextFails() {
        KeyGenResponse keypair = quantumService.generateKeyPair();
        String plaintext = "Important civic registration data";
        EncryptRequest encryptRequest = new EncryptRequest(keypair.publicKey(), plaintext);
        EncryptResponse encryptResponse = quantumService.encrypt(encryptRequest);

        // Tamper with the encrypted message bytes
        byte[] encryptedBytes = Base64.getUrlDecoder().decode(encryptResponse.encryptedMessage());
        encryptedBytes[0] ^= 0xFF; // Flip first byte
        String tamperedMessage = Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedBytes);

        DecryptRequest decryptRequest = new DecryptRequest(
                keypair.privateKey(),
                encryptResponse.kemCiphertext(),
                encryptResponse.iv(),
                tamperedMessage
        );

        assertThrows(RuntimeException.class, () -> quantumService.decrypt(decryptRequest));
    }

    @Test
    void testDecryptionWithTamperedIvFails() {
        KeyGenResponse keypair = quantumService.generateKeyPair();
        String plaintext = "Important civic registration data";
        EncryptRequest encryptRequest = new EncryptRequest(keypair.publicKey(), plaintext);
        EncryptResponse encryptResponse = quantumService.encrypt(encryptRequest);

        // Tamper with the IV
        byte[] ivBytes = Base64.getUrlDecoder().decode(encryptResponse.iv());
        ivBytes[0] ^= 0xFF; // Flip first byte
        String tamperedIv = Base64.getUrlEncoder().withoutPadding().encodeToString(ivBytes);

        DecryptRequest decryptRequest = new DecryptRequest(
                keypair.privateKey(),
                encryptResponse.kemCiphertext(),
                tamperedIv,
                encryptResponse.encryptedMessage()
        );

        assertThrows(RuntimeException.class, () -> quantumService.decrypt(decryptRequest));
    }

    @Test
    void testDecryptionWithTamperedKemCiphertextFails() {
        KeyGenResponse keypair = quantumService.generateKeyPair();
        String plaintext = "Important civic registration data";
        EncryptRequest encryptRequest = new EncryptRequest(keypair.publicKey(), plaintext);
        EncryptResponse encryptResponse = quantumService.encrypt(encryptRequest);

        // Tamper with the KEM ciphertext
        byte[] kemBytes = Base64.getUrlDecoder().decode(encryptResponse.kemCiphertext());
        kemBytes[0] ^= 0xFF; // Flip first byte
        String tamperedKem = Base64.getUrlEncoder().withoutPadding().encodeToString(kemBytes);

        DecryptRequest decryptRequest = new DecryptRequest(
                keypair.privateKey(),
                tamperedKem,
                encryptResponse.iv(),
                encryptResponse.encryptedMessage()
        );

        // Decapsulation of tampered KEM ciphertext in Kyber can result either in failure
        // or a different derived shared secret (due to active security/IND-CCA2 properties).
        // If it returns a different secret, the AES key will be different, making AES-GCM tag verification fail.
        // In either case, the decrypt operation must throw an exception.
        assertThrows(RuntimeException.class, () -> quantumService.decrypt(decryptRequest));
    }

    @Test
    void testControllerEndpointsWithAuth() throws Exception {
        String authHeader = "Bearer " + apiKeyConfig.getApiKey();

        // 1. Keygen Endpoint
        String keygenResultJson = mockMvc.perform(post("/v1/quantum/keygen")
                        .header("Authorization", authHeader))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey").exists())
                .andExpect(jsonPath("$.privateKey").exists())
                .andExpect(jsonPath("$.algorithm").value("ML-KEM-768"))
                .andExpect(jsonPath("$.publicKeyLength").value(1184))
                .andExpect(jsonPath("$.privateKeyLength").value(2400))
                .andReturn().getResponse().getContentAsString();

        KeyGenResponse keygenResponse = objectMapper.readValue(keygenResultJson, KeyGenResponse.class);

        // 2. Encrypt Endpoint
        EncryptRequest encryptRequest = new EncryptRequest(keygenResponse.publicKey(), "Hello Quantum World");
        String encryptResultJson = mockMvc.perform(post("/v1/quantum/encrypt")
                        .header("Authorization", authHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(encryptRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kem_ciphertext").exists())
                .andExpect(jsonPath("$.iv").exists())
                .andExpect(jsonPath("$.encrypted_message").exists())
                .andExpect(jsonPath("$.algorithm").value("ML-KEM-768 + AES-256-GCM"))
                .andExpect(jsonPath("$.shared_secret_hash").exists())
                .andReturn().getResponse().getContentAsString();

        EncryptResponse encryptResponse = objectMapper.readValue(encryptResultJson, EncryptResponse.class);

        // 3. Decrypt Endpoint
        DecryptRequest decryptRequest = new DecryptRequest(
                keygenResponse.privateKey(),
                encryptResponse.kemCiphertext(),
                encryptResponse.iv(),
                encryptResponse.encryptedMessage()
        );

        mockMvc.perform(post("/v1/quantum/decrypt")
                        .header("Authorization", authHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(decryptRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decrypted_text").value("Hello Quantum World"))
                .andExpect(jsonPath("$.algorithm").value("ML-KEM-768 + AES-256-GCM"))
                .andExpect(jsonPath("$.shared_secret_hash").value(encryptResponse.sharedSecretHash()));
    }

    @Test
    void testControllerEndpointsUnauthenticatedFails() throws Exception {
        mockMvc.perform(post("/v1/quantum/keygen"))
                .andExpect(status().isUnauthorized());

        EncryptRequest encryptRequest = new EncryptRequest("fakePubKey", "Hello");
        mockMvc.perform(post("/v1/quantum/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(encryptRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testControllerValidationFails() throws Exception {
        String authHeader = "Bearer " + apiKeyConfig.getApiKey();

        // Missing fields in EncryptRequest
        EncryptRequest invalidRequest = new EncryptRequest("", "");
        mockMvc.perform(post("/v1/quantum/encrypt")
                        .header("Authorization", authHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("Validation failed for fields")));
    }
}
