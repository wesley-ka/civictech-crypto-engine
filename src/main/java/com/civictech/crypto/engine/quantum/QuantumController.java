package com.civictech.crypto.engine.quantum;

import com.civictech.crypto.engine.quantum.dto.*;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/quantum")
public class QuantumController {

    private final QuantumService quantumService;

    public QuantumController(QuantumService quantumService) {
        this.quantumService = quantumService;
    }

    @PostMapping("/keygen")
    public ResponseEntity<KeyGenResponse> generateKeyPair() {
        return ResponseEntity.ok(quantumService.generateKeyPair());
    }

    @PostMapping("/encrypt")
    public ResponseEntity<EncryptResponse> encrypt(@Valid @RequestBody EncryptRequest request) {
        return ResponseEntity.ok(quantumService.encrypt(request));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<DecryptResponse> decrypt(@Valid @RequestBody DecryptRequest request) {
        return ResponseEntity.ok(quantumService.decrypt(request));
    }
}
