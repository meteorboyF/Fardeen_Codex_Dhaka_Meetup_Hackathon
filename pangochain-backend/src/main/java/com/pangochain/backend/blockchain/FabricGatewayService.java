package com.pangochain.backend.blockchain;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hyperledger.fabric.client.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.*;

/**
 * Single entry-point for all Hyperledger Fabric interactions.
 *
 * - submitTransaction  → fabric Invoke  (state-changing, goes through orderer)
 * - evaluateTransaction → fabric Query   (read-only, hits local peer)
 *
 * Chaincode event listener is started on construction and publishes
 * {@link FabricChaincodEvent} to Spring's event bus so other beans can react.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(name = "fabric.enabled", havingValue = "true")
public class FabricGatewayService {

    private final Network fabricNetwork;
    private final ApplicationEventPublisher eventPublisher;
    private final ObjectMapper objectMapper;

    @Value("${fabric.chaincode-name}")
    private String chaincodeName;

    private Contract contract;
    private CloseableIterator<ChaincodeEvent> eventIterator;
    private ExecutorService eventListenerExecutor;

    @PostConstruct
    public void init() {
        contract = fabricNetwork.getContract(chaincodeName);
        startEventListener();
        log.info("FabricGatewayService initialised for chaincode '{}'", chaincodeName);
    }

    @PreDestroy
    public void shutdown() {
        if (eventIterator != null) {
            try { eventIterator.close(); } catch (Exception ignored) {}
        }
        if (eventListenerExecutor != null) {
            eventListenerExecutor.shutdownNow();
        }
    }

    // ─── Submit (invoke) ──────────────────────────────────────────────────────

    /**
     * Submits a state-changing transaction synchronously.
     * Returns the Fabric transaction ID (not the chaincode response payload),
     * so callers can store it as an immutable ledger reference.
     * Uses the two-step endorse/submit API to capture getTransactionId().
     */
    @CircuitBreaker(name = "fabric", fallbackMethod = "submitFallback")
    @Retry(name = "fabric")
    public String submitTransaction(String functionName, String... args) throws FabricException {
        try {
            Transaction tx = contract.newProposal(functionName)
                    .addArguments(args)
                    .build()
                    .endorse();
            tx.submit();
            String txId = tx.getTransactionId();
            log.info("Fabric tx committed: fn={} txId={}", functionName, txId);
            return txId;
        } catch (EndorseException e) {
            // Peers evaluated the proposal and refused it — a deterministic policy answer
            // (e.g. an S3 recipient-key mismatch), not an outage. The chaincode's own error
            // string travels in the gRPC status details rather than getMessage(), so surface
            // both and mark the failure non-retryable so callers do not queue it.
            String detail = endorseDetail(e);
            log.error("Endorsement rejected for '{}': {}", functionName, detail);
            throw new FabricException("Chaincode rejected " + functionName + ": " + detail, e, true);
        } catch (SubmitException | CommitStatusException | CommitException e) {
            log.error("Submit transaction '{}' failed: {}", functionName, e.getMessage());
            throw new FabricException("Blockchain submit failed: " + e.getMessage(), e);
        }
    }

    /**
     * Circuit-breaker fallback for {@link #submitTransaction}. Fires immediately when the
     * breaker is OPEN (Fabric outage) instead of waiting for each call to time out. Always
     * throws FabricException so protected document-material callers can deny fail-closed.
     */
    @SuppressWarnings("unused")
    private String submitFallback(String functionName, String[] args, Throwable t) throws FabricException {
        log.warn("Fabric submit circuit fallback for '{}': {}", functionName, t.getMessage());
        if (t instanceof FabricException fe) throw fe;
        throw new FabricException("Blockchain unavailable (circuit open): " + t.getMessage(), t);
    }

    /**
     * Extracts the chaincode's own error string from an EndorseException. Fabric carries it
     * in the per-endorser {@code ErrorDetail} list rather than in getMessage(), so a plain
     * message reads only "failed to endorse transaction". Returns the first endorser detail
     * message, falling back to getMessage() when none is present.
     */
    private static String endorseDetail(org.hyperledger.fabric.client.EndorseException e) {
        try {
            for (var d : e.getDetails()) {
                if (d.getMessage() != null && !d.getMessage().isBlank()) {
                    return d.getMessage();
                }
            }
        } catch (Throwable ignore) {
            // fall through to the plain message
        }
        return e.getMessage() == null ? "endorsement rejected" : e.getMessage();
    }

    /**
     * Async variant — fire and forget, used for non-critical audit logging.
     */
    @Async
    public CompletableFuture<String> submitTransactionAsync(String functionName, String... args) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return submitTransaction(functionName, args);
            } catch (FabricException e) {
                log.warn("Async submit '{}' failed: {}", functionName, e.getMessage());
                return "";
            }
        });
    }

    // ─── Evaluate (query) ─────────────────────────────────────────────────────

    /**
     * Evaluates a read-only transaction and returns the JSON string payload.
     */
    @CircuitBreaker(name = "fabric", fallbackMethod = "evaluateFallback")
    @Retry(name = "fabric")
    public String evaluateTransaction(String functionName, String... args) throws FabricException {
        try {
            byte[] result = contract.evaluateTransaction(functionName, args);
            return new String(result, StandardCharsets.UTF_8);
        } catch (GatewayException e) {
            log.error("Evaluate transaction '{}' failed: {}", functionName, e.getMessage());
            throw new FabricException("Blockchain query failed: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unused")
    private String evaluateFallback(String functionName, String[] args, Throwable t) throws FabricException {
        log.warn("Fabric evaluate circuit fallback for '{}': {}", functionName, t.getMessage());
        if (t instanceof FabricException fe) throw fe;
        throw new FabricException("Blockchain unavailable (circuit open): " + t.getMessage(), t);
    }

    /**
     * Convenience wrapper that parses the JSON result into a typed object.
     */
    public <T> T evaluateAndParse(String functionName, Class<T> type, String... args)
            throws FabricException {
        String json = evaluateTransaction(functionName, args);
        try {
            return objectMapper.readValue(json, type);
        } catch (Exception e) {
            throw new FabricException("Failed to parse chaincode response: " + e.getMessage(), e);
        }
    }

    // ─── Chaincode-specific helpers ───────────────────────────────────────────

    public String registerDocument(String docId, String caseId, String docHash,
            String ipfsCid, String ownerId, String ownerOrg, String timestamp) throws FabricException {
        return submitTransaction("RegisterDocument", docId, caseId, docHash, ipfsCid, ownerId, ownerOrg, timestamp);
    }

    public String grantAccess(String docId, String targetSubject, String subjectOrg,
            String capability, String expiresAt, String wrappedKeyRef, String grantorId,
            String recipientKeyHash) throws FabricException {
        return submitTransaction("GrantAccess", docId, targetSubject, subjectOrg, capability,
                expiresAt, wrappedKeyRef, grantorId, recipientKeyHash);
    }

    /**
     * Anchors the hash of a user's public wrapping key at enrollment (S3 closure).
     * Immutable on-chain: a later substitution in the operational identity table can
     * no longer be re-anchored, and GrantAccess verifies against this binding.
     */
    public String registerUserKey(String userId, String keyHash) throws FabricException {
        return submitTransaction("RegisterUserKey", userId, keyHash);
    }

    /** Returns the anchored user-key binding JSON, or an empty string when unbound. */
    public String getUserKeyBinding(String userId) throws FabricException {
        return evaluateTransaction("GetUserKeyBinding", userId);
    }

    public String revokeAccess(String docId, String targetSubject, String revokerId) throws FabricException {
        return submitTransaction("RevokeAccess", docId, targetSubject, revokerId);
    }

    public boolean checkAccess(String docId, String userId, String userOrg) throws FabricException {
        String result = evaluateTransaction("CheckAccess", docId, userId, userOrg);
        return "true".equalsIgnoreCase(result.trim().replace("\"", ""));
    }

    public String registerCase(String caseId, String firmId, String title,
            String creatorId, String timestamp) throws FabricException {
        return submitTransaction("RegisterCase", caseId, firmId, title, creatorId, timestamp);
    }

    public String getDocumentHistory(String docId) throws FabricException {
        return evaluateTransaction("GetDocumentHistory", docId);
    }

    public String updateDocument(String docId, String newCid, String newHash, String updaterId)
            throws FabricException {
        return submitTransaction("UpdateDocument", docId, newCid, newHash, updaterId);
    }

    // ─── Chaincode event listener ─────────────────────────────────────────────

    private void startEventListener() {
        eventListenerExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "fabric-event-listener");
            t.setDaemon(true);
            return t;
        });

        eventListenerExecutor.submit(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    eventIterator = fabricNetwork.getChaincodeEvents(chaincodeName);
                    log.info("Chaincode event listener started for '{}'", chaincodeName);
                    eventIterator.forEachRemaining(event -> {
                        try {
                            String payload = event.getPayload() != null
                                    ? new String(event.getPayload(), StandardCharsets.UTF_8) : "{}";
                            log.debug("Chaincode event '{}': {}", event.getEventName(), payload);
                            eventPublisher.publishEvent(new FabricChaincodEvent(
                                    this, event.getEventName(), event.getTransactionId(), payload));
                        } catch (Exception e) {
                            log.warn("Error processing chaincode event: {}", e.getMessage());
                        }
                    });
                } catch (Exception e) {
                    if (!Thread.currentThread().isInterrupted()) {
                        log.warn("Chaincode event listener disconnected, reconnecting in 5s: {}", e.getMessage());
                        try { TimeUnit.SECONDS.sleep(5); } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }
            }
        });
    }
}
