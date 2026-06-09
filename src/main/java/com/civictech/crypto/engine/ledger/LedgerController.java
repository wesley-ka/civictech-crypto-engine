package com.civictech.crypto.engine.ledger;

import com.civictech.crypto.engine.ledger.dto.*;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/ledger")
public class LedgerController {

    private final LedgerService ledgerService;

    public LedgerController(LedgerService ledgerService) {
        this.ledgerService = ledgerService;
    }

    @PostMapping("/create")
    public ResponseEntity<LedgerBlock> createGenesisAsset(@Valid @RequestBody CreateAssetRequest request) {
        LedgerBlock block = ledgerService.createGenesisAsset(request);
        return ResponseEntity.ok(block);
    }

    @PostMapping("/append")
    public ResponseEntity<LedgerBlock> appendEvent(@Valid @RequestBody AppendEventRequest request) {
        LedgerBlock block = ledgerService.appendEvent(request);
        return ResponseEntity.ok(block);
    }

    @GetMapping("/{assetId}/history")
    public ResponseEntity<LedgerHistoryResponse> getAssetHistory(@PathVariable String assetId) {
        LedgerHistoryResponse history = ledgerService.getAssetHistory(assetId);
        return ResponseEntity.ok(history);
    }

    @GetMapping("/{assetId}/latest")
    public ResponseEntity<LedgerBlock> getLatestBlock(@PathVariable String assetId) {
        LedgerBlock block = ledgerService.getLatestBlock(assetId);
        return ResponseEntity.ok(block);
    }

    @GetMapping("/{assetId}/verify")
    public ResponseEntity<LedgerVerificationResponse> verifyLedger(@PathVariable String assetId) {
        LedgerVerificationResponse verification = ledgerService.verifyLedger(assetId);
        return ResponseEntity.ok(verification);
    }

    @DeleteMapping("/{assetId}")
    public ResponseEntity<Void> resetLedger(@PathVariable String assetId) {
        ledgerService.resetLedger(assetId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{assetId}/tamper")
    public ResponseEntity<LedgerBlock> tamperLedger(
            @PathVariable String assetId,
            @Valid @RequestBody TamperRequest request) {
        LedgerBlock block = ledgerService.tamperLedger(assetId, request);
        return ResponseEntity.ok(block);
    }
}
