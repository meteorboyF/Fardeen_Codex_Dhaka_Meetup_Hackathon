package com.pangochain.backend.access;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pangochain.backend.audit.AuditService;
import com.pangochain.backend.blockchain.FabricException;
import com.pangochain.backend.crypto.KeyHashing;
import com.pangochain.backend.blockchain.FabricGatewayService;
import org.springframework.beans.factory.annotation.Autowired;
import com.pangochain.backend.document.Document;
import com.pangochain.backend.document.DocumentAccess;
import com.pangochain.backend.document.DocumentAccessRepository;
import com.pangochain.backend.document.DocumentRepository;
import com.pangochain.backend.notification.NotificationService;
import com.pangochain.backend.user.User;
import com.pangochain.backend.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AccessControlService {

    private final DocumentAccessRepository accessRepository;
    private final DocumentRepository documentRepository;
    private final UserRepository userRepository;
    private final NotificationService notificationService;
    @Autowired(required = false)
    private FabricGatewayService fabricGatewayService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;
    private final PendingAnchorRepository pendingAnchorRepository;
    private final OutboxSigner outboxSigner;

    /**
     * When true, a grant to a recipient with no ledger-anchored key binding is refused
     * (strict migration posture); the shipped default accepts unbound recipients and
     * records the grant as unbound.
     */
    @org.springframework.beans.factory.annotation.Value("${access.require-key-binding:false}")
    private boolean requireKeyBinding;

    /** Result of {@link #revoke}: whether the ledger anchor committed inline or was queued. */
    public record RevokeResult(boolean ledgerCommitted, String fabricTxId, UUID pendingAnchorId) {}

    /**
     * Phase 4: Grant access — wrapped key arrives from the browser.
     * 1. Verify granter has owner/write capability
     * 2. Call GrantAccess chaincode (records on ledger)
     * 3. Persist DocumentAccess row
     * 4. Notify grantee
     *
     * The ledger write is durable, mirroring {@link #revoke}: attempted inline for the
     * common case, and on failure (e.g. an ordering outage) a PENDING {@link PendingAnchor}
     * row carrying the full replay payload is committed in the same DB transaction. Before
     * this change grant() was fire-and-forget — a grant issued during an outage updated the
     * operational ACL and was never anchored, the mirror-image of the revocation defect
     * fixed in 027. The response carries "pending" rather than unqualified success while
     * the anchor is outstanding.
     */
    @Transactional
    public AccessDto grant(GrantAccessRequest req, User granter) {
        UUID docId = UUID.fromString(req.getDocId());
        UUID granteeId = UUID.fromString(req.getGranteeId());

        // Verify granter has owner capability
        DocumentAccess granterAccess = accessRepository.findActiveEntry(docId, granter.getId())
                .orElseThrow(() -> new IllegalStateException("You do not have access to this document"));
        if (granterAccess.getCapability() == DocumentAccess.Capability.read) {
            throw new IllegalStateException("Read-only users cannot grant access");
        }

        // Capability-capped delegation: a granter may never grant a capability higher than
        // their own (owner > write > read). This bounds the per-case delegation chain — e.g.
        // a 'write' delegate can pass on read/write but never owner.
        DocumentAccess.Capability requested = DocumentAccess.Capability.valueOf(req.getCapability().toLowerCase());
        if (rank(requested) > rank(granterAccess.getCapability())) {
            throw new IllegalStateException(
                    "Cannot grant '" + requested + "' — it exceeds your own '" + granterAccess.getCapability() + "' capability");
        }

        User grantee = userRepository.findById(granteeId)
                .orElseThrow(() -> new IllegalArgumentException("Grantee not found: " + req.getGranteeId()));

        // Determine expiry
        Instant expiresAt = req.getExpiresAtEpochMs() != null
                ? Instant.ofEpochMilli(req.getExpiresAtEpochMs()) : null;

        // Fabric GrantAccess — durable: failure leaves a PENDING outbox row, not a log line.
        // The recipient-key attestation (S3 closure) hashes the stored JWK this service
        // would serve to the granter's browser; the chaincode compares it against the
        // binding anchored at enrollment and refuses a substituted key.
        String granteeMsp = grantee.getFirm() != null ? grantee.getFirm().getMspId() : "FirmAMSP";
        String expiryStr = expiresAt != null ? expiresAt.toString() : "";
        // Prefer the client's attestation of the key it actually wrapped under (S4);
        // fall back to hashing the stored key for clients that predate the field.
        boolean clientAttested = req.getRecipientKeyHash() != null && !req.getRecipientKeyHash().isBlank();
        String recipientKeyHash = clientAttested
                ? req.getRecipientKeyHash()
                : (grantee.getPublicKeyEcies() != null ? KeyHashing.sha256Hex(grantee.getPublicKeyEcies()) : "");

        if (requireKeyBinding && fabricGatewayService != null) {
            try {
                String binding = fabricGatewayService.getUserKeyBinding(grantee.getId().toString());
                if (binding == null || binding.isBlank()) {
                    throw new org.springframework.web.server.ResponseStatusException(
                            org.springframework.http.HttpStatus.FORBIDDEN,
                            "Recipient has no ledger-anchored key binding and strict binding mode is enabled.");
                }
            } catch (FabricException e) {
                throw new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE,
                        "Strict binding mode requires the ledger, which is unreachable.");
            }
        }
        PendingAnchor anchor = PendingAnchor.builder()
                .chaincodeFunction("GrantAccess")
                .docId(docId)
                .targetUserId(granteeId)
                .revokerId(granter.getId())
                .status(PendingAnchor.Status.PENDING)
                .attempts(0)
                .nextAttemptAt(Instant.now())
                .payload(toJson(Map.of(
                        "granteeMsp", granteeMsp,
                        "capability", req.getCapability().toLowerCase(),
                        "expiresAt", expiryStr,
                        "wrappedKeyRef", req.getWrappedKeyToken(),
                        "recipientKeyHash", recipientKeyHash,
                        "keyHashSource", clientAttested ? "client" : "gateway-db")))
                .build();
        anchor.setSignature(outboxSigner.sign(anchor));

        String fabricTxId = null;
        boolean ledgerCommitted = false;
        try {
            if (fabricGatewayService == null) throw new FabricException("Fabric not enabled");
            // Intent-order guard for the inline path (audit finding S6): if an older
            // mutation for this (document, user) is still pending, submitting inline
            // would jump the queue, so this mutation is queued behind it instead.
            if (pendingAnchorRepository.existsByStatusAndDocIdAndTargetUserIdAndCreatedAtBefore(
                    PendingAnchor.Status.PENDING, docId, granteeId, Instant.now())) {
                throw new FabricException("older pending anchors exist for this document and user; queued to preserve intent order");
            }
            fabricTxId = fabricGatewayService.grantAccess(
                    docId.toString(),
                    grantee.getId().toString(),
                    granteeMsp,
                    req.getCapability().toLowerCase(),
                    expiryStr,
                    req.getWrappedKeyToken(),
                    granter.getId().toString(),
                    recipientKeyHash
            );
            ledgerCommitted = true;
        } catch (FabricException e) {
            // A deterministic endorsement rejection (e.g. an S3 recipient-key mismatch) must
            // not be queued: replaying it can never succeed and would mask the refusal. Only
            // transport/ordering failures are durable. The chaincode's own reason travels in
            // the endorsement detail, which FabricException surfaces in its message.
            if (e.isDeterministicRejection()) {
                auditService.log("ACCESS_GRANT_REJECTED_KEY_MISMATCH", granter.getId(), "DOCUMENT",
                        docId.toString(), null,
                        toJson(Map.of("grantee", grantee.getEmail(),
                                "attestedKeyHash", recipientKeyHash,
                                "reason", String.valueOf(e.getMessage()))));
                throw new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.FORBIDDEN,
                        "Grant refused by the ledger: the recipient's current public key does not match "
                        + "the binding anchored at enrollment (possible key substitution).");
            }
            log.warn("Fabric GrantAccess failed, queuing durable retry: {}", e.getMessage());
            anchor.setLastError(e.getMessage());
        }

        if (ledgerCommitted) {
            anchor.setStatus(PendingAnchor.Status.COMMITTED);
            anchor.setFabricTxId(fabricTxId);
            anchor.setCommittedAt(Instant.now());
        }
        anchor = pendingAnchorRepository.save(anchor);

        DocumentAccess.Capability cap = DocumentAccess.Capability.valueOf(req.getCapability().toLowerCase());
        DocumentAccess access = accessRepository.findActiveEntry(docId, granteeId)
                .orElseGet(() -> DocumentAccess.builder()
                        .docId(docId)
                        .userId(granteeId)
                        .build());
        access.setCapability(cap);
        access.setGrantedBy(granter.getId());
        access.setExpiresAt(expiresAt);
        access.setWrappedKeyToken(req.getWrappedKeyToken());
        access.setTokenObsolete(false);
        access = accessRepository.save(access);

        // Notify grantee (real-time push + persisted)
        notificationService.push(granteeId, "ACCESS_GRANTED",
                String.format("%s granted you %s access to a document",
                        granter.getFullName(), req.getCapability()));

        auditService.log("ACCESS_GRANTED", granter.getId(), "DOCUMENT",
                docId.toString(), fabricTxId,
                toJson(Map.of(
                        "grantee", grantee.getEmail(),
                        "capability", req.getCapability(),
                        "ledgerSyncStatus", ledgerCommitted ? "committed" : "pending",
                        "pendingAnchorId", anchor.getId().toString())));

        AccessDto dto = toDto(access, grantee.getEmail(), grantee.getFullName(), granter.getEmail());
        dto.setLedgerSyncStatus(ledgerCommitted ? "committed" : "pending");
        dto.setPendingAnchorId(ledgerCommitted ? null : anchor.getId());
        return dto;
    }

    /**
     * Phase 4: Revoke access. Also triggers key rotation notification.
     *
     * The ledger write is durable: it is attempted inline for the common case (returns
     * committed immediately), but a failure — e.g. an orderer outage — leaves a PENDING
     * {@link PendingAnchor} row in the same DB transaction instead of being dropped. See
     * {@link AnchorReconciliationWorker}. Fixes bcra_peer_review.md M1 / Experiment 16, where
     * a failed Fabric submit was only logged and the revoke still returned success, leaving
     * the on-chain grant ACTIVE forever with no reconciliation.
     */
    @Transactional
    public RevokeResult revoke(String docIdStr, String targetUserIdStr, User revoker) {
        UUID docId = UUID.fromString(docIdStr);
        UUID targetUserId = UUID.fromString(targetUserIdStr);

        DocumentAccess access = accessRepository.findActiveEntry(docId, targetUserId)
                .orElseThrow(() -> new IllegalArgumentException("No active access entry found"));

        access.setRevokedAt(Instant.now());
        access.setRevokedBy(revoker.getId());
        accessRepository.save(access);

        PendingAnchor anchor = PendingAnchor.builder()
                .chaincodeFunction("RevokeAccess")
                .docId(docId)
                .targetUserId(targetUserId)
                .revokerId(revoker.getId())
                .status(PendingAnchor.Status.PENDING)
                .attempts(0)
                .nextAttemptAt(Instant.now())
                .build();
        anchor.setSignature(outboxSigner.sign(anchor));

        String fabricTxId = null;
        boolean ledgerCommitted = false;
        try {
            if (fabricGatewayService == null) throw new FabricException("Fabric not enabled");
            // Intent-order guard for the inline path (audit finding S6); see grant().
            if (pendingAnchorRepository.existsByStatusAndDocIdAndTargetUserIdAndCreatedAtBefore(
                    PendingAnchor.Status.PENDING, docId, targetUserId, Instant.now())) {
                throw new FabricException("older pending anchors exist for this document and user; queued to preserve intent order");
            }
            fabricTxId = fabricGatewayService.revokeAccess(docIdStr, targetUserIdStr, revoker.getId().toString());
            ledgerCommitted = true;
        } catch (FabricException e) {
            log.warn("Fabric RevokeAccess failed, queuing durable retry: {}", e.getMessage());
            anchor.setLastError(e.getMessage());
        }

        if (ledgerCommitted) {
            anchor.setStatus(PendingAnchor.Status.COMMITTED);
            anchor.setFabricTxId(fabricTxId);
            anchor.setCommittedAt(Instant.now());
        }
        anchor = pendingAnchorRepository.save(anchor);

        // Mark all non-owner tokens on this document as OBSOLETE — they may have been
        // exposed to the revoked user and must not be trusted after key rotation.
        List<DocumentAccess> nonOwnerTokens = accessRepository.findActiveNonOwnerByDoc(docId, DocumentAccess.Capability.owner);
        for (DocumentAccess token : nonOwnerTokens) {
            token.setTokenObsolete(true);
            accessRepository.save(token);
        }

        // Flag the document so the owner's browser is prompted to rotate keys.
        Document doc = documentRepository.findById(docId).orElse(null);
        if (doc != null) {
            doc.setKeyRotationPending(true);
            documentRepository.save(doc);
        }

        // Notify revoked user
        notificationService.push(targetUserId, "ACCESS_REVOKED",
                "Your access to a document has been revoked by " + revoker.getFullName());

        // Notify document owner that key rotation is required
        if (doc != null) {
            notificationService.push(doc.getOwner().getId(), "KEY_ROTATION_REQUIRED",
                    "Key rotation required for document '" + doc.getFileName()
                            + "' — a user's access was revoked. Please re-encrypt and redistribute the document key.");
        }

        auditService.log("ACCESS_REVOKED", revoker.getId(), "DOCUMENT",
                docIdStr, fabricTxId,
                toJson(Map.of(
                        "targetUser", targetUserIdStr,
                        "tokensMarkedObsolete", nonOwnerTokens.size(),
                        "ledgerSyncStatus", ledgerCommitted ? "committed" : "pending",
                        "pendingAnchorId", anchor.getId().toString())));

        log.info("KEY_ROTATION_REQUIRED: doc={} revokedUser={} obsoleteTokens={}", docIdStr, targetUserIdStr, nonOwnerTokens.size());

        return new RevokeResult(ledgerCommitted, fabricTxId, anchor.getId());
    }

    public List<AccessDto> listForDoc(UUID docId, User requester) {
        return accessRepository.findActiveByDoc(docId)
                .stream()
                .map(a -> {
                    User grantee = userRepository.findById(a.getUserId()).orElse(null);
                    String granteeEmail = grantee != null ? grantee.getEmail() : "unknown";
                    String granteeName = grantee != null ? grantee.getFullName() : "Unknown user";
                    String granterEmail = a.getGrantedBy() != null
                            ? userRepository.findById(a.getGrantedBy()).map(User::getEmail).orElse("system")
                            : "system";
                    return toDto(a, granteeEmail, granteeName, granterEmail);
                })
                .toList();
    }

    private AccessDto toDto(DocumentAccess a, String granteeEmail, String granteeName, String granterEmail) {
        return AccessDto.builder()
                .id(a.getId())
                .docId(a.getDocId())
                .userId(a.getUserId())
                .userEmail(granteeEmail)
                .userFullName(granteeName)
                .grantedByEmail(granterEmail)
                .capability(a.getCapability().name())
                .expiresAt(a.getExpiresAt())
                .grantedAt(a.getGrantedAt())
                .build();
    }

    private String toJson(Object obj) {
        try { return objectMapper.writeValueAsString(obj); } catch (Exception e) { return "{}"; }
    }

    /** Capability ranking for delegation checks: owner(3) > write(2) > read(1). */
    private static int rank(DocumentAccess.Capability cap) {
        return switch (cap) {
            case owner -> 3;
            case write -> 2;
            case read -> 1;
        };
    }
}
