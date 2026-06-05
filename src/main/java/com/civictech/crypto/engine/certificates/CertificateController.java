package com.civictech.crypto.engine.certificates;

import com.civictech.crypto.engine.certificates.dto.ParseCertificateRequest;
import com.civictech.crypto.engine.certificates.dto.ParseCertificateResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/certificates")
public class CertificateController {

    private final CertificateService certificateService;

    public CertificateController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @PostMapping("/parse")
    public ResponseEntity<ParseCertificateResponse> parseCertificate(@Valid @RequestBody ParseCertificateRequest request) {
        return ResponseEntity.ok(certificateService.parseCertificate(request));
    }
}
