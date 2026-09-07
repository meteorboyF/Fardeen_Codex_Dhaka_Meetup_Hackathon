package com.pangochain.backend.audit;

import com.pangochain.backend.blockchain.FabricException;
import com.pangochain.backend.blockchain.FabricGatewayService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entityManager;

    // Allocate audit IDs in commit order so a concurrent insert cannot fall below
    // an already checkpointed watermark. The lock ends with REQUIRES_NEW commit.
    private void lockAppendOrder() {
        entityManager.unwrap(org.hibernate.Session.class).doWork(connection -> {
            try (var statement = connection.prepareStatement("SELECT pg_advisory_xact_lock(728194051)")) {
                statement.execute();
            }
        });
    }

    @Autowired(required = false)
    private FabricGatewayService fabricGatewayService;

    /**
     * Persist an audit entry in its own synchronous transaction before returning.
     * A persistence failure propagates: callers must not acknowledge an unrecorded action.
     * Ledger anchoring is exclusively handled by AuditAnchorBackfillWorker; no
     * network submit or asynchronous in-memory queue precedes this durable append.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String eventType, UUID actorId, String resourceType,
                    String resourceId, String fabricTxId, String metadataJson) {
        lockAppendOrder();
        String auditFabricTxId = fabricTxId;
        try {
            AuditLog entry = AuditLog.builder()
                    .eventType(eventType)
                    .actorId(actorId)
                    .resourceType(resourceType)
                    .resourceId(resourceId)
                    .fabricTxId(auditFabricTxId)
                    .metadataJson(metadataJson)
                    .build();
            auditLogRepository.saveAndFlush(entry);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot durably record audit event " + eventType, e);
        }
    }

    /** Overload for system-generated events (no UUID actor — uses string identity). */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String eventType, String actorIdStr, String actorOrg,
                    String resourceType, String resourceId, String fabricTxId,
                    String metadataJson, String ipAddress) {
        lockAppendOrder();
        String auditFabricTxId = fabricTxId;
        try {
            AuditLog entry = AuditLog.builder()
                    .eventType(eventType)
                    .actorId(null)
                    .resourceType(resourceType)
                    .resourceId(resourceId)
                    .fabricTxId(auditFabricTxId)
                    .metadataJson(metadataJson != null ? metadataJson
                            : String.format("{\"actor\":\"%s\",\"org\":\"%s\"}", actorIdStr, actorOrg))
                    .build();
            auditLogRepository.saveAndFlush(entry);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot durably record audit event " + eventType, e);
        }
    }
}
