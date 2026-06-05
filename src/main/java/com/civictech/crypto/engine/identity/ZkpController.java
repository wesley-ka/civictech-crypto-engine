package com.civictech.crypto.engine.identity;

import com.civictech.crypto.engine.identity.dto.ZkpVerifyRequest;
import com.civictech.crypto.engine.identity.dto.ZkpVerifyResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/identity")
public class ZkpController {

    private final ZkpService zkpService;

    public ZkpController(ZkpService zkpService) {
        this.zkpService = zkpService;
    }

    @PostMapping("/zkp-verify")
    public ResponseEntity<ZkpVerifyResponse> verifyZkp(@Valid @RequestBody ZkpVerifyRequest request) {
        return ResponseEntity.ok(zkpService.verifyZkp(request));
    }
}
