package com.civictech.crypto.engine.voting;

import com.civictech.crypto.engine.voting.dto.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/v1/voting")
public class VotingController {

    private final VotingService votingService;

    public VotingController(VotingService votingService) {
        this.votingService = votingService;
    }

    @PostMapping("/create")
    public ResponseEntity<CreateVotingSessionResponse> createSession(@Valid @RequestBody CreateVotingSessionRequest request) {
        return ResponseEntity.ok(votingService.createSession(request));
    }

    @GetMapping("/info/{voteId}")
    public ResponseEntity<VotingSessionInfo> getSessionInfo(@PathVariable String voteId) {
        return ResponseEntity.ok(votingService.getSessionInfo(voteId));
    }

    @PostMapping("/challenge")
    public ResponseEntity<ChallengeResponse> generateChallenge(@Valid @RequestBody ChallengeRequest request) {
        return ResponseEntity.ok(votingService.generateChallenge(request));
    }

    @PostMapping("/cast")
    public ResponseEntity<Map<String, String>> castVote(@Valid @RequestBody CastVoteRequest request) {
        votingService.castVote(request);
        return ResponseEntity.ok(Map.of("status", "VOTE_CAST_SUCCESSFULLY"));
    }

    @GetMapping("/results/{voteId}")
    public ResponseEntity<?> getResults(@PathVariable String voteId, HttpServletRequest request) {
        try {
            String redirectUrl = votingService.getResultsUrl(
                    voteId,
                    request.getScheme(),
                    request.getServerName(),
                    request.getServerPort(),
                    request.getContextPath()
            );
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, redirectUrl)
                    .build();
        } catch (IllegalArgumentException e) {
            if (e.getMessage().contains("still active")) {
                String expiresAt = null;
                try {
                    expiresAt = votingService.getSessionInfo(voteId).expiresAt();
                } catch (Exception ignored) {}
                
                if (expiresAt != null) {
                    return ResponseEntity.badRequest().body(Map.of(
                            "status", "VOTING_IN_PROGRESS",
                            "message", e.getMessage(),
                            "expires_at", expiresAt
                    ));
                } else {
                    return ResponseEntity.badRequest().body(Map.of(
                            "status", "VOTING_IN_PROGRESS",
                            "message", e.getMessage()
                    ));
                }
            }
            throw e;
        }
    }

    @GetMapping(value = "/static/{voteId}/results.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> getStaticResults(@PathVariable String voteId) {
        return ResponseEntity.ok(votingService.getStaticResultsFile(voteId));
    }
}

