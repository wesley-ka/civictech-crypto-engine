package com.civictech.crypto.engine.signing;

import com.civictech.crypto.engine.signing.dto.SignRequest;
import com.civictech.crypto.engine.signing.dto.SignResponse;
import com.civictech.crypto.engine.signing.dto.VerifyRequest;
import com.civictech.crypto.engine.signing.dto.VerifyResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/signing")
public class SigningController {

    private final SigningService signingService;

    public SigningController(SigningService signingService) {
        this.signingService = signingService;
    }

    @PostMapping("/sign")
    public ResponseEntity<SignResponse> sign(@Valid @RequestBody SignRequest request) {
        return ResponseEntity.ok(signingService.sign(request));
    }

    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verify(@Valid @RequestBody VerifyRequest request) {
        return ResponseEntity.ok(signingService.verify(request));
    }
}
