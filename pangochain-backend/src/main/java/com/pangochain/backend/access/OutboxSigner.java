package com.pangochain.backend.access;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * Authenticates outbox rows against database tampering (audit finding S2).
 *
 * The reconciliation worker acts on whatever {@code pending_anchor} contains and submits
 * with the gateway's Fabric credentials, so an unauthenticated outbox hands a database
 * writer a path to ledger mutations. Each row is therefore signed with HMAC-SHA256 over
 * its replay-relevant fields, keyed by a secret that lives only in gateway configuration.
 * A database writer cannot produce a valid signature, so forged or altered rows fail
 * verification and are refused rather than replayed.
 *
 * With no secret configured, signing degrades to disabled with a startup warning; the
 * measured deployment sets one. Key rotation invalidates pending rows and is deliberately
 * out of scope for the prototype.
 */
@Component
@Slf4j
public class OutboxSigner {

    private final byte[] secret;

    public OutboxSigner(@Value("${access.outbox-hmac-secret:}") String secret) {
        this.secret = secret == null || secret.isBlank()
                ? null : secret.getBytes(StandardCharsets.UTF_8);
        if (this.secret == null) {
            log.warn("access.outbox-hmac-secret is not set: outbox rows are UNSIGNED and a "
                    + "database writer can forge pending ledger mutations (audit finding S2)");
        }
    }

    public boolean enabled() {
        return secret != null;
    }

    /** Canonical signing input: every field the worker will replay, unambiguously joined. */
    private static String canonical(PendingAnchor a) {
        return String.join("\n",
                String.valueOf(a.getChaincodeFunction()),
                String.valueOf(a.getDocId()),
                String.valueOf(a.getTargetUserId()),
                String.valueOf(a.getRevokerId()),
                a.getPayload() == null ? "" : a.getPayload());
    }

    public String sign(PendingAnchor a) {
        if (secret == null) return null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return HexFormat.of().formatHex(
                    mac.doFinal(canonical(a).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /** True when the row's stored signature matches its contents (or signing is disabled). */
    public boolean verify(PendingAnchor a) {
        if (secret == null) return true;
        String expected = sign(a);
        String actual = a.getSignature();
        if (actual == null || expected == null) return false;
        // Constant-time comparison; both are fixed-length hex of the same MAC.
        return java.security.MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }
}
