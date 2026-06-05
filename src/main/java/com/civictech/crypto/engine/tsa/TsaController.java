package com.civictech.crypto.engine.tsa;

import com.civictech.crypto.engine.tsa.dto.TimestampRequest;
import com.civictech.crypto.engine.tsa.dto.TimestampResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/tsa")
public class TsaController {

    private final TsaService tsaService;

    public TsaController(TsaService tsaService) {
        this.tsaService = tsaService;
    }

    @PostMapping("/timestamp")
    public ResponseEntity<TimestampResponse> generateTimestamp(@Valid @RequestBody TimestampRequest request) {
        return ResponseEntity.ok(tsaService.generateTimestamp(request));
    }
}
