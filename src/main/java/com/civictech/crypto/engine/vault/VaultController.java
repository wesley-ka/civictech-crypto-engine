package com.civictech.crypto.engine.vault;

import com.civictech.crypto.engine.vault.dto.*;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/vault")
public class VaultController {

    private final VaultService vaultService;

    public VaultController(VaultService vaultService) {
        this.vaultService = vaultService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<EncryptResponse> encrypt(@Valid @RequestBody EncryptRequest request) {
        return ResponseEntity.ok(vaultService.encrypt(request));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<DecryptResponse> decrypt(@Valid @RequestBody DecryptRequest request) {
        return ResponseEntity.ok(vaultService.decrypt(request));
    }

    @PostMapping("/audit")
    public ResponseEntity<AuditResponse> audit(@Valid @RequestBody AuditRequest request) {
        return ResponseEntity.ok(vaultService.audit(request));
    }
}
