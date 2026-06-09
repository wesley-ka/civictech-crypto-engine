package com.civictech.crypto.engine.identity.vc;

import com.civictech.crypto.engine.identity.vc.dto.*;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/identity/vc")
public class VcController {

    private final VcService vcService;

    public VcController(VcService vcService) {
        this.vcService = vcService;
    }

    @PostMapping("/issue")
    public ResponseEntity<IssueVcResponse> issueCredential(@Valid @RequestBody IssueVcRequest request) {
        IssueVcResponse response = vcService.issueCredential(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/share/{vcId}")
    public ResponseEntity<VerifiableCredential> getSharedCredential(@PathVariable String vcId) {
        VerifiableCredential credential = vcService.getSharedCredential(vcId);
        return ResponseEntity.ok(credential);
    }

    @PostMapping("/verify")
    public ResponseEntity<VerifyVcResponse> verifyCredential(@Valid @RequestBody VerifiableCredential credential) {
        VerifyVcResponse response = vcService.verifyCredential(credential);
        return ResponseEntity.ok(response);
    }
}
