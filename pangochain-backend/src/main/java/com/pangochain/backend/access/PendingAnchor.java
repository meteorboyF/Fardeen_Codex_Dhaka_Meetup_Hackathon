package com.pangochain.backend.access;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Durable outbox row for a chaincode submit that must eventually reach the ledger.
 *
 * Written in the same PostgreSQL transaction as the operational write it backs (e.g. the
 * {@code document_access.revoked_at} update in {@link AccessControlService#revoke}), so a
 * Fabric/orderer outage can never silently drop the ledger side the way it did in
 * bcra_peer_review.md M1 / Experiment 16 (revoke returned 204 while the on-chain grant stayed
 * ACTIVE forever, with no reconciliation). {@link AnchorReconciliationWorker} drains PENDING
 * rows on a schedule and retries with backoff until the anchor commits.
 */
@Entity
@Table(name = "pending_anchor")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PendingAnchor {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** Chaincode function this anchor submits, e.g. "RevokeAccess". */
    @Column(name = "chaincode_function", nullable = false)
    private String chaincodeFunction;

    @Column(name = "doc_id", nullable = false)
    private UUID docId;

    @Column(name = "target_user_id", nullable = false)
    private UUID targetUserId;

    @Column(name = "revoker_id", nullable = false)
    private UUID revokerId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;

    @Column(nullable = false)
    @Builder.Default
    private int attempts = 0;

    @Column(name = "next_attempt_at")
    private Instant nextAttemptAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "committed_at")
    private Instant committedAt;

    @Column(name = "fabric_tx_id")
    private String fabricTxId;

    @Column(name = "last_error", columnDefinition = "TEXT")
    private String lastError;

    /**
     * JSON arguments needed to replay the chaincode call at drain time, for functions whose
     * argument set exceeds the fixed columns (GrantAccess: grantee MSP, capability, expiry,
     * wrapped-key reference). Null for RevokeAccess rows, whose three arguments are covered
     * by {@code docId}/{@code targetUserId}/{@code revokerId}.
     */
    @Column(columnDefinition = "TEXT")
    private String payload;

    /**
     * Gateway HMAC over the replay-relevant fields (audit finding S2). Rows whose
     * signature does not verify are refused by the reconciliation worker, so a database
     * writer cannot mint ledger mutations by inserting or altering outbox rows.
     */
    @Column(columnDefinition = "TEXT")
    private String signature;

    @PrePersist
    void prePersist() {
        if (createdAt == null) createdAt = Instant.now();
    }

    public enum Status { PENDING, COMMITTED, FAILED }
}
