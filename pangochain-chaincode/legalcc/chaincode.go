package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// LegalContract implements all chaincode functions for PangoChain.
type LegalContract struct {
	contractapi.Contract
}

// ─── RegisterDocument ────────────────────────────────────────────────────────

// RegisterDocument anchors a document's hash and IPFS CID to the ledger and
// initialises its ACL with the owner's full capability.
func (c *LegalContract) RegisterDocument(
	ctx contractapi.TransactionContextInterface,
	docID, caseID, documentHash, ipfsCID, ownerID, ownerOrg, timestamp string,
) error {
	key := docKey(docID)
	if exists, _ := assetExists(ctx, key); exists {
		return fmt.Errorf("document %s already registered", docID)
	}

	ownerGrant := &Grant{
		Capability:    CapOwner,
		SubjectOrg:    ownerOrg,
		GrantedBy:     ownerID,
		GrantedAt:     timestamp,
		WrappedKeyRef: "",
		Status:        StatusActive,
	}

	doc := &DocumentAsset{
		DocID:        docID,
		CaseID:       caseID,
		DocumentHash: documentHash,
		IpfsCID:      ipfsCID,
		OwnerID:      ownerID,
		OwnerOrg:     ownerOrg,
		Timestamp:    timestamp,
		Status:       StatusActive,
		Version:      1,
		ACL:          map[string]*Grant{ownerID: ownerGrant},
	}

	if err := putAsset(ctx, key, doc); err != nil {
		return err
	}

	ctx.GetStub().SetEvent("DOC_REGISTERED", mustJSON(map[string]string{
		"docId": docID, "caseId": caseID, "ownerId": ownerID, "ownerOrg": ownerOrg,
	}))

	return c.logAuditInternal(ctx, "DOC_REGISTERED", ownerID, ownerOrg, docID,
		fmt.Sprintf(`{"caseId":"%s","hash":"%s","cid":"%s"}`, caseID, documentHash, ipfsCID))
}

// ─── GrantAccess ─────────────────────────────────────────────────────────────

// GrantAccess adds or updates an access capability for a target subject.
// Stores the ECIES-wrapped document key reference for that subject.
// RegisterUserKey anchors the hash of a user's public wrapping key at enrollment
// (threat-model Scenario S3: public-key substitution). Immutable — a second
// registration for the same user is refused, so an adversary who later replaces
// the key in the operational identity table cannot re-anchor the substitute.
func (c *LegalContract) RegisterUserKey(
	ctx contractapi.TransactionContextInterface,
	userID, keyHash string,
) error {
	if userID == "" || keyHash == "" {
		return fmt.Errorf("userID and keyHash are required")
	}
	key := fmt.Sprintf("%s:%s", UserKeyPrefix, userID)
	exists, err := assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("key binding for user %s already anchored; bindings are immutable", userID)
	}
	mspID, err := callerMSP(ctx)
	if err != nil {
		return err
	}
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %w", err)
	}
	binding := UserKeyBinding{
		UserID:       userID,
		KeyHash:      keyHash,
		RegisteredAt: time.Unix(txTimestamp.Seconds, 0).UTC().Format(time.RFC3339),
		RegisteredBy: mspID,
	}
	if err := putAsset(ctx, key, binding); err != nil {
		return err
	}
	return c.logAuditInternal(ctx, "USER_KEY_ANCHORED", userID, mspID, userID,
		fmt.Sprintf(`{"keyHash":"%s"}`, keyHash))
}

// GetUserKeyBinding returns the anchored binding for a user, or an empty string
// if none has been anchored.
func (c *LegalContract) GetUserKeyBinding(
	ctx contractapi.TransactionContextInterface,
	userID string,
) (string, error) {
	data, err := ctx.GetStub().GetState(fmt.Sprintf("%s:%s", UserKeyPrefix, userID))
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", nil
	}
	return string(data), nil
}

func (c *LegalContract) GrantAccess(
	ctx contractapi.TransactionContextInterface,
	docID, targetSubject, subjectOrg, capability, expiresAt, wrappedKeyRef, grantorID,
	recipientKeyHash string,
) error {
	doc, err := getDocument(ctx, docID)
	if err != nil {
		return err
	}

	// S3 closure: when a key binding is anchored for the recipient, the caller must
	// attest the hash of the public key the wrap was produced under, and it must
	// match the enrollment-time anchor. A substituted key in the operational
	// identity table then fails here, in consortium-visible state, instead of
	// silently yielding a grant wrapped for the attacker. Absent a binding the
	// grant proceeds (migration posture for users enrolled before anchoring;
	// recorded in the audit payload).
	bindingRaw, err := ctx.GetStub().GetState(fmt.Sprintf("%s:%s", UserKeyPrefix, targetSubject))
	if err != nil {
		return fmt.Errorf("failed to read key binding for %s: %w", targetSubject, err)
	}
	bindingChecked := "absent"
	if bindingRaw != nil {
		var binding UserKeyBinding
		if err := json.Unmarshal(bindingRaw, &binding); err != nil {
			return fmt.Errorf("unreadable key binding for %s: %w", targetSubject, err)
		}
		if recipientKeyHash == "" {
			return fmt.Errorf("recipient %s has an anchored key binding; recipientKeyHash attestation is required", targetSubject)
		}
		if recipientKeyHash != binding.KeyHash {
			return fmt.Errorf("recipient key mismatch for %s: attested %s, anchored %s — possible key substitution",
				targetSubject, recipientKeyHash, binding.KeyHash)
		}
		bindingChecked = "verified"
	}

	mspID, err := callerMSP(ctx)
	if err != nil {
		return err
	}

	// Only owner or owner-org admin may grant
	ownerGrant, ownerOK := doc.ACL[doc.OwnerID]
	if !ownerOK || (grantorID != doc.OwnerID && mspID != doc.OwnerOrg) {
		return fmt.Errorf("only the document owner may grant access")
	}
	_ = ownerGrant

	if capability != CapOwner && capability != CapWrite && capability != CapRead {
		return fmt.Errorf("invalid capability %q: must be owner|write|read", capability)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %w", err)
	}
	now := time.Unix(txTimestamp.Seconds, 0).UTC().Format(time.RFC3339)
	doc.ACL[targetSubject] = &Grant{
		Capability:    capability,
		SubjectOrg:    subjectOrg,
		GrantedBy:     grantorID,
		GrantedAt:     now,
		ExpiresAt:     expiresAt,
		WrappedKeyRef: wrappedKeyRef,
		Status:        StatusActive,
	}

	if err := putAsset(ctx, docKey(docID), doc); err != nil {
		return err
	}

	ctx.GetStub().SetEvent("ACCESS_GRANTED", mustJSON(map[string]string{
		"docId": docID, "subject": targetSubject, "capability": capability,
	}))

	return c.logAuditInternal(ctx, "ACCESS_GRANTED", grantorID, mspID, docID,
		fmt.Sprintf(`{"subject":"%s","capability":"%s","expiresAt":"%s","keyBinding":"%s"}`,
			targetSubject, capability, expiresAt, bindingChecked))
}

// ─── RevokeAccess ────────────────────────────────────────────────────────────

// RevokeAccess marks a subject's capability as REVOKED and emits a
// KEY_ROTATION_REQUIRED event so the backend can trigger re-encryption.
func (c *LegalContract) RevokeAccess(
	ctx contractapi.TransactionContextInterface,
	docID, targetSubject, revokerID string,
) error {
	doc, err := getDocument(ctx, docID)
	if err != nil {
		return err
	}

	mspID, err := callerMSP(ctx)
	if err != nil {
		return err
	}

	if revokerID != doc.OwnerID && mspID != doc.OwnerOrg {
		return fmt.Errorf("only the document owner may revoke access")
	}

	grant, ok := doc.ACL[targetSubject]
	if !ok {
		return fmt.Errorf("no access grant found for subject %s", targetSubject)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %w", err)
	}
	now := time.Unix(txTimestamp.Seconds, 0).UTC().Format(time.RFC3339)
	grant.Status = StatusRevoked
	grant.RevokedAt = now

	if err := putAsset(ctx, docKey(docID), doc); err != nil {
		return err
	}

	// Signal key rotation required (Spring Boot listens for this)
	ctx.GetStub().SetEvent("KEY_ROTATION_REQUIRED", mustJSON(map[string]string{
		"docId": docID, "revokedSubject": targetSubject, "revokerOrg": mspID,
	}))
	ctx.GetStub().SetEvent("ACCESS_REVOKED", mustJSON(map[string]string{
		"docId": docID, "subject": targetSubject,
	}))

	return c.logAuditInternal(ctx, "ACCESS_REVOKED", revokerID, mspID, docID,
		fmt.Sprintf(`{"revokedSubject":"%s","revokedAt":"%s"}`, targetSubject, now))
}

// ─── TimeAnchor ──────────────────────────────────────────────────────────────

// UpdateTimeAnchor advances the ledger's wall-clock reference point. It is a SUBMIT, so
// every endorsing peer sees the proposal and independently validates its timestamp against
// its own clock before endorsing; a backdated heartbeat therefore cannot be committed
// without collecting endorsements from peers whose clocks disagree with it.
//
// Determinism note: the local clock is used only to accept or reject. The value written to
// world state is the proposal timestamp, which is identical across endorsers, so the
// read-write set stays deterministic and endorsement still matches. Comparing local clocks
// would be fine here in a way that writing time.Now() would not.
func (c *LegalContract) UpdateTimeAnchor(ctx contractapi.TransactionContextInterface) error {
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %w", err)
	}
	proposed := time.Unix(txTimestamp.Seconds, 0).UTC()

	// Endorser-local plausibility check (accept/reject only - never written to state).
	skew := time.Since(proposed)
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxHeartbeatSkewSeconds*time.Second {
		return fmt.Errorf(
			"heartbeat timestamp %s is %.0fs from this endorser's clock, exceeding the %ds tolerance",
			proposed.Format(time.RFC3339), skew.Seconds(), MaxHeartbeatSkewSeconds)
	}

	mspID, err := callerMSP(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve caller MSP: %w", err)
	}

	current, err := getTimeAnchor(ctx)
	if err != nil {
		return err
	}

	// Refuse to move the anchor backwards: a stale or replayed heartbeat must not widen the
	// backdating window that CheckAccess derives from it.
	if current != nil {
		prev, parseErr := time.Parse(time.RFC3339, current.Timestamp)
		if parseErr == nil && !proposed.After(prev) {
			return fmt.Errorf(
				"heartbeat timestamp %s does not advance the current anchor %s",
				proposed.Format(time.RFC3339), current.Timestamp)
		}
	}

	next := &TimeAnchor{
		Timestamp: proposed.Format(time.RFC3339),
		UpdatedBy: mspID,
		Sequence:  1,
	}
	if current != nil {
		next.Sequence = current.Sequence + 1
	}
	return putAsset(ctx, TimeAnchorKey, next)
}

// GetTimeAnchor returns the current anchor as JSON, for operators and experiments.
func (c *LegalContract) GetTimeAnchor(ctx contractapi.TransactionContextInterface) (string, error) {
	anchor, err := getTimeAnchor(ctx)
	if err != nil {
		return "", err
	}
	if anchor == nil {
		return "", fmt.Errorf("no time anchor has been established")
	}
	return string(mustJSON(anchor)), nil
}

// ─── CheckAccess ─────────────────────────────────────────────────────────────

// CheckAccess evaluates whether a user has an active, non-expired capability
// on a document. Called on EVERY document request (Layer 2 ACL check).
// Returns "true" or "false" as a string (evaluate transaction).
func (c *LegalContract) CheckAccess(
	ctx contractapi.TransactionContextInterface,
	docID, userID, userOrg string,
) (string, error) {
	doc, err := getDocument(ctx, docID)
	if err != nil {
		return "false", err
	}

	if doc.Status != StatusActive {
		return "false", nil
	}

	// Derive current time from the Fabric transaction timestamp so the access decision is
	// deterministic across all endorsing peers (time.Now() would diverge and break endorsement).
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "false", fmt.Errorf("failed to get tx timestamp: %w", err)
	}
	now := time.Unix(txTimestamp.Seconds, 0).UTC()

	// On an evaluate this timestamp originates in the caller's proposal, and the caller is
	// the custodial gateway. Refuse to decide from a clock that sits implausibly far behind
	// the last endorsed TimeAnchor, which is what a gateway backdating its way past an
	// expired grant would have to do. See the TimeAnchor type for the full argument.
	if !disableFreshnessCheckForMeasurement {
		if err := assertProposalTimeIsFresh(ctx, now); err != nil {
			return "false", err
		}
	}

	// Check user-level grant first
	if grant, ok := doc.ACL[userID]; ok && grant.Status == StatusActive {
		if grant.ExpiresAt == "" {
			return "true", nil
		}
		exp, err := time.Parse(time.RFC3339, grant.ExpiresAt)
		if err == nil && now.Before(exp) {
			return "true", nil
		}
		// Expired. Deliberately no write here: CheckAccess is only ever called as an
		// evaluate, and writes in an evaluate are discarded rather than ordered, so a
		// PutState would silently never persist. Marking the grant EXPIRED on the ledger
		// requires a submit and is handled outside the release path.
		return "false", nil
	}

	// Deliberately no implicit ownership fallback.
	//
	// This previously read `if doc.OwnerOrg == userOrg { return "true" }`, which let any
	// member of the owning organization retrieve any of that organization's documents given
	// only a document ID, with no grant issued by anyone. Experiment 18 measured it end to
	// end. In legal practice that is not a minor over-permission: ethical walls and
	// matter-level screening are the primary intra-firm access requirement, conflict
	// screening depends on them, and privileged material carries a confidentiality horizon
	// measured in decades, so "bounded to ciphertext" is a weak consolation against
	// harvest-now-decrypt-later. Every principal now needs an explicit grant; the uploader
	// receives one from RegisterDocument, so upload-then-download still works.

	// Check if any org-level grant exists for userOrg
	orgKey := "ORG:" + userOrg
	if grant, ok := doc.ACL[orgKey]; ok && grant.Status == StatusActive {
		if grant.ExpiresAt == "" {
			return "true", nil
		}
		exp, err := time.Parse(time.RFC3339, grant.ExpiresAt)
		if err == nil && now.Before(exp) {
			return "true", nil
		}
	}

	return "false", nil
}

// ─── GetAccessList ───────────────────────────────────────────────────────────

// GetAccessList returns the full ACL for a document (evaluate transaction).
func (c *LegalContract) GetAccessList(
	ctx contractapi.TransactionContextInterface,
	docID string,
) (*DocumentAsset, error) {
	return getDocument(ctx, docID)
}

// ─── GetHistoryForKey ────────────────────────────────────────────────────────

// GetDocumentHistory returns the full transaction history for a document key.
func (c *LegalContract) GetDocumentHistory(
	ctx contractapi.TransactionContextInterface,
	docID string,
) ([]map[string]interface{}, error) {
	iter, err := ctx.GetStub().GetHistoryForKey(docKey(docID))
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var records []map[string]interface{}
	for iter.HasNext() {
		mod, err := iter.Next()
		if err != nil {
			return nil, err
		}
		record := map[string]interface{}{
			"txId":      mod.TxId,
			"timestamp": mod.Timestamp.String(),
			"isDelete":  mod.IsDelete,
			"value":     string(mod.Value),
		}
		records = append(records, record)
	}
	return records, nil
}

// ─── UpdateDocument ──────────────────────────────────────────────────────────

// UpdateDocument records a new IPFS CID and hash after re-encryption / versioning.
func (c *LegalContract) UpdateDocument(
	ctx contractapi.TransactionContextInterface,
	docID, newIpfsCID, newDocumentHash, updaterID string,
) error {
	doc, err := getDocument(ctx, docID)
	if err != nil {
		return err
	}

	mspID, err := callerMSP(ctx)
	if err != nil {
		return err
	}

	// Must be owner or have write access
	if ok, _ := c.CheckAccess(ctx, docID, updaterID, mspID); ok != "true" {
		return fmt.Errorf("updater %s does not have write access to document %s", updaterID, docID)
	}

	doc.IpfsCID = newIpfsCID
	doc.DocumentHash = newDocumentHash
	doc.Version++

	if err := putAsset(ctx, docKey(docID), doc); err != nil {
		return err
	}

	return c.logAuditInternal(ctx, "DOC_UPDATED", updaterID, mspID, docID,
		fmt.Sprintf(`{"newCid":"%s","version":%d}`, newIpfsCID, doc.Version))
}

// ─── RegisterCase ────────────────────────────────────────────────────────────

// RegisterCase anchors a new legal case to the ledger.
func (c *LegalContract) RegisterCase(
	ctx contractapi.TransactionContextInterface,
	caseID, firmID, title, creatorID, timestamp string,
) error {
	key := fmt.Sprintf("%s:%s", CasePrefix, caseID)
	if exists, _ := assetExists(ctx, key); exists {
		return fmt.Errorf("case %s already registered", caseID)
	}

	cas := &CaseAsset{
		CaseID:    caseID,
		FirmID:    firmID,
		Title:     title,
		CreatorID: creatorID,
		Timestamp: timestamp,
		Status:    StatusActive,
	}

	mspID, _ := callerMSP(ctx)
	if err := putAsset(ctx, key, cas); err != nil {
		return err
	}

	return c.logAuditInternal(ctx, "CASE_REGISTERED", creatorID, mspID, caseID,
		fmt.Sprintf(`{"firmId":"%s","title":"%s"}`, firmID, title))
}

// ─── LogAuditEvent ───────────────────────────────────────────────────────────

// LogAuditEvent records an application-layer audit event with SHA-256 chaining.
// prevAuditHash is the SHA-256 hash of the previous audit event payload.
func (c *LegalContract) LogAuditEvent(
	ctx contractapi.TransactionContextInterface,
	eventType, actorID, actorOrg, resourceID, contextJSON, prevAuditHash string,
) error {
	return c.logAuditInternal(ctx, eventType, actorID, actorOrg, resourceID, contextJSON)
}

func (c *LegalContract) logAuditInternal(
	ctx contractapi.TransactionContextInterface,
	eventType, actorID, actorOrg, resourceID, contextJSON string,
) error {
	txID := ctx.GetStub().GetTxID()
	ts, _ := ctx.GetStub().GetTxTimestamp()
	timestamp := time.Unix(ts.Seconds, 0).UTC().Format(time.RFC3339)

	payload := fmt.Sprintf(`{"eventType":"%s","actorId":"%s","resourceId":"%s","txId":"%s","timestamp":"%s"}`,
		eventType, actorID, resourceID, txID, timestamp)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))

	event := &AuditEvent{
		EventID:     txID + ":" + eventType,
		EventType:   eventType,
		ActorID:     actorID,
		ActorOrg:    actorOrg,
		ResourceID:  resourceID,
		ContextJSON: contextJSON,
		Timestamp:   timestamp,
	}

	key := fmt.Sprintf("%s:%s:%s", AuditPrefix, resourceID, txID)
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(key, data); err != nil {
		return err
	}

	// Emit audit event for off-chain indexing
	ctx.GetStub().SetEvent("AUDIT_EVENT", mustJSON(map[string]string{
		"eventType":  eventType,
		"actorId":    actorID,
		"resourceId": resourceID,
		"hash":       hash,
		"timestamp":  timestamp,
	}))

	return nil
}

// ─── RevokeUserCertificate ───────────────────────────────────────────────────

// RevokeUserCertificate records an MSP-level revocation on the ledger.
func (c *LegalContract) RevokeUserCertificate(
	ctx contractapi.TransactionContextInterface,
	userID, revokerOrg string,
) error {
	mspID, err := callerMSP(ctx)
	if err != nil {
		return err
	}

	return c.logAuditInternal(ctx, "USER_CERT_REVOKED", userID, mspID, userID,
		fmt.Sprintf(`{"revokerOrg":"%s"}`, revokerOrg))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func docKey(docID string) string {
	return fmt.Sprintf("%s:%s", DocPrefix, docID)
}

func assetExists(ctx contractapi.TransactionContextInterface, key string) (bool, error) {
	data, err := ctx.GetStub().GetState(key)
	return data != nil, err
}

func getDocument(ctx contractapi.TransactionContextInterface, docID string) (*DocumentAsset, error) {
	data, err := ctx.GetStub().GetState(docKey(docID))
	if err != nil {
		return nil, fmt.Errorf("failed to read document %s: %w", docID, err)
	}
	if data == nil {
		return nil, fmt.Errorf("document %s not found", docID)
	}
	var doc DocumentAsset
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func putAsset(ctx contractapi.TransactionContextInterface, key string, obj interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, data)
}

// getTimeAnchor returns the committed anchor, or (nil, nil) when none has been established.
func getTimeAnchor(ctx contractapi.TransactionContextInterface) (*TimeAnchor, error) {
	data, err := ctx.GetStub().GetState(TimeAnchorKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read time anchor: %w", err)
	}
	if data == nil {
		return nil, nil
	}
	var anchor TimeAnchor
	if err := json.Unmarshal(data, &anchor); err != nil {
		return nil, fmt.Errorf("failed to decode time anchor: %w", err)
	}
	return &anchor, nil
}

// assertProposalTimeIsFresh refuses a proposal timestamp that sits more than
// MaxClockSkewSeconds behind the committed anchor, and - when MaxAnchorStalenessSeconds is
// enabled - refuses decisions taken against an anchor that has stopped advancing.
//
// Backdating is the attack: a timestamp *ahead* of the anchor is expected during normal
// operation, since the anchor only moves on a heartbeat, and post-dating cannot revive an
// expired grant - it can only expire a live one early, which is fail-safe.
//
// When no anchor exists the check is skipped rather than failing closed, so that a
// deployment which has not enabled the heartbeat keeps its previous behaviour instead of
// having every access decision denied by an upgrade. That fallback is deliberate but it is
// also the mechanism's floor: with no anchor there is no bound.
func assertProposalTimeIsFresh(ctx contractapi.TransactionContextInterface, proposed time.Time) error {
	anchor, err := getTimeAnchor(ctx)
	if err != nil {
		return err
	}
	if anchor == nil {
		return nil
	}
	anchored, err := time.Parse(time.RFC3339, anchor.Timestamp)
	if err != nil {
		return fmt.Errorf("time anchor holds an unparseable timestamp %q: %w", anchor.Timestamp, err)
	}
	if behind := anchored.Sub(proposed); behind > MaxClockSkewSeconds*time.Second {
		return fmt.Errorf(
			"proposal timestamp %s is %.0fs behind the endorsed time anchor %s, exceeding the %ds tolerance",
			proposed.Format(time.RFC3339), behind.Seconds(), anchor.Timestamp, MaxClockSkewSeconds)
	}
	// Anchor staleness is measured with the answering peer's own wall clock, never
	// with the caller-supplied proposal timestamp. Measuring it against the proposal
	// is circular: a caller that backdates the proposal to the anchor's own instant
	// (P = A) makes an arbitrarily old anchor look fresh, and the ceiling then bounds
	// nothing (pre-submission audit, finding S1). CheckAccess runs only as an
	// evaluate answered by a single peer, so consulting that peer's clock introduces
	// no endorsement nondeterminism and extends an assumption the design already
	// makes, namely that the answering peer returns honest state. With this check the
	// composed bound holds against a malicious proposal clock: the anchor is at most
	// the ceiling old by the peer's clock, and the proposal is at most the skew
	// tolerance behind the anchor, so a proposal timestamp cannot sit more than
	// ceiling+skew behind the peer's present.
	if MaxAnchorStalenessSeconds > 0 {
		if stale := time.Now().UTC().Sub(anchored); stale > time.Duration(MaxAnchorStalenessSeconds)*time.Second {
			return fmt.Errorf(
				"time anchor %s is %.0fs stale by the answering peer's clock, exceeding the %ds ceiling; "+
					"refusing to decide from state whose freshness cannot be established",
				anchor.Timestamp, stale.Seconds(), MaxAnchorStalenessSeconds)
		}
	}
	return nil
}

func callerMSP(ctx contractapi.TransactionContextInterface) (string, error) {
	id, err := ctx.GetClientIdentity().GetMSPID()
	return id, err
}

func mustJSON(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}
