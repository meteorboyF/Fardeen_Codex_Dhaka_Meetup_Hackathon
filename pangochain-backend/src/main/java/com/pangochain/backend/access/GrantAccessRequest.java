package com.pangochain.backend.access;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class GrantAccessRequest {
    @NotBlank private String docId;
    @NotBlank private String granteeId;
    /** "read" | "write" | "owner" */
    @NotBlank private String capability;
    /** ECIES-wrapped AES doc key, encrypted with grantee's public key — done in browser */
    @NotBlank private String wrappedKeyToken;
    /** Optional expiry epoch milliseconds */
    private Long expiresAtEpochMs;
    /**
     * SHA-256 hex over the exact public-key JWK string the client fetched and wrapped
     * under (audit finding S4). When present, this attestation rather than a gateway
     * hash of the current database key is what the chaincode compares against the
     * enrollment anchor, so a key substituted after the client fetched it, or restored
     * before submission, still fails verification.
     */
    private String recipientKeyHash;
}
