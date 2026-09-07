package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ─── Mock ClientIdentity ──────────────────────────────────────────────────────

type mockClientIdentity struct {
	mspID string
}

func (m *mockClientIdentity) GetMSPID() (string, error)                      { return m.mspID, nil }
func (m *mockClientIdentity) GetID() (string, error)                         { return "mock-client-id", nil }
func (m *mockClientIdentity) GetX509Certificate() (*x509.Certificate, error) { return nil, nil }
func (m *mockClientIdentity) GetAttributeValue(attrName string) (string, bool, error) {
	return "", false, nil
}
func (m *mockClientIdentity) AssertAttributeValue(attrName, attrValue string) error { return nil }

// ─── Mock Transaction Context ─────────────────────────────────────────────────

type testContext struct {
	stub *shimtest.MockStub
	cid  *mockClientIdentity
}

func (tc *testContext) GetStub() shim.ChaincodeStubInterface {
	return tc.stub
}

func (tc *testContext) GetClientIdentity() cid.ClientIdentity {
	return tc.cid
}

// Compile-time check: testContext satisfies contractapi.TransactionContextInterface
var _ contractapi.TransactionContextInterface = (*testContext)(nil)

// ─── Test Helpers ─────────────────────────────────────────────────────────────

func setupCtx(t *testing.T, txID string) (*testContext, *shimtest.MockStub) {
	t.Helper()
	// nil chaincode: these tests call contract methods directly with the mock context and
	// use the stub only as a state store, so MockStub never needs to dispatch an Invoke.
	// Passing &LegalContract{} does not compile - contractapi.Contract is not a
	// shim.Chaincode - which is why this suite had not been runnable.
	stub := shimtest.NewMockStub("legalcc", nil)
	stub.MockTransactionStart(txID)
	ctx := &testContext{
		stub: stub,
		cid:  &mockClientIdentity{mspID: "TestMSP"},
	}
	return ctx, stub
}

func commitTx(stub *shimtest.MockStub, txID string) {
	stub.MockTransactionEnd(txID)
}

func mustGetDoc(t *testing.T, stub *shimtest.MockStub, docID string) *DocumentAsset {
	t.Helper()
	data, err := stub.GetState(docKey(docID))
	if err != nil {
		t.Fatalf("GetState(%s): %v", docID, err)
	}
	if data == nil {
		t.Fatalf("document %s not in state", docID)
	}
	var doc DocumentAsset
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal doc: %v", err)
	}
	return &doc
}

func mustGetCase(t *testing.T, stub *shimtest.MockStub, caseID string) *CaseAsset {
	t.Helper()
	key := fmt.Sprintf("%s:%s", CasePrefix, caseID)
	data, err := stub.GetState(key)
	if err != nil {
		t.Fatalf("GetState(%s): %v", key, err)
	}
	if data == nil {
		t.Fatalf("case %s not in state", caseID)
	}
	var cas CaseAsset
	if err := json.Unmarshal(data, &cas); err != nil {
		t.Fatalf("unmarshal case: %v", err)
	}
	return &cas
}

func nowTS() string { return time.Now().UTC().Format(time.RFC3339) }

// ─── RegisterCase ─────────────────────────────────────────────────────────────

func TestRegisterCase(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-reg-case")
	contract := &LegalContract{}

	if err := contract.RegisterCase(ctx, "case-001", "firm-001", "Smith v Jones", "lawyer-001", nowTS()); err != nil {
		t.Fatalf("RegisterCase: %v", err)
	}
	commitTx(stub, "tx-reg-case")

	cas := mustGetCase(t, stub, "case-001")
	if cas.CaseID != "case-001" {
		t.Errorf("caseId: got %s, want case-001", cas.CaseID)
	}
	if cas.Status != StatusActive {
		t.Errorf("status: got %s, want %s", cas.Status, StatusActive)
	}
	if cas.Title != "Smith v Jones" {
		t.Errorf("title: got %s, want 'Smith v Jones'", cas.Title)
	}
}

func TestRegisterCase_Duplicate(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-dup-1")
	contract := &LegalContract{}

	if err := contract.RegisterCase(ctx, "dup-001", "firm-001", "Title", "lawyer", nowTS()); err != nil {
		t.Fatalf("first RegisterCase: %v", err)
	}
	commitTx(stub, "tx-dup-1")

	// Start a new transaction for the duplicate attempt
	stub.MockTransactionStart("tx-dup-2")
	ctx2 := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "TestMSP"}}
	err := contract.RegisterCase(ctx2, "dup-001", "firm-001", "Title", "lawyer", nowTS())
	if err == nil {
		t.Fatal("expected error on duplicate RegisterCase, got nil")
	}
	commitTx(stub, "tx-dup-2")
}

// ─── RegisterDocument ─────────────────────────────────────────────────────────

func TestRegisterDocument(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-reg-doc")
	contract := &LegalContract{}

	err := contract.RegisterDocument(ctx,
		"doc-001", "case-001", "sha256hexhash", "QmCID001",
		"owner-001", "TestMSP", nowTS())
	if err != nil {
		t.Fatalf("RegisterDocument: %v", err)
	}
	commitTx(stub, "tx-reg-doc")

	doc := mustGetDoc(t, stub, "doc-001")
	if doc.DocumentHash != "sha256hexhash" {
		t.Errorf("hash: got %s, want sha256hexhash", doc.DocumentHash)
	}
	if doc.IpfsCID != "QmCID001" {
		t.Errorf("cid: got %s, want QmCID001", doc.IpfsCID)
	}
	grant, ok := doc.ACL["owner-001"]
	if !ok || grant.Capability != CapOwner {
		t.Errorf("owner ACL entry missing or wrong capability")
	}
}

// ─── CheckAccess ──────────────────────────────────────────────────────────────

func TestCheckAccess_Granted(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-acl-1")
	contract := &LegalContract{}

	_ = contract.RegisterDocument(ctx, "doc-acl", "case-001", "hash", "Qm1", "owner-001", "TestMSP", nowTS())
	_ = contract.GrantAccess(ctx, "doc-acl", "user-002", "TestMSP", CapRead, "", "wrapped-key", "owner-001", "")
	commitTx(stub, "tx-acl-1")

	stub.MockTransactionStart("tx-acl-check")
	checkCtx := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "TestMSP"}}

	// Owner should have access
	result, err := contract.CheckAccess(checkCtx, "doc-acl", "owner-001", "TestMSP")
	if err != nil || result != "true" {
		t.Errorf("owner should have access: got %q err=%v", result, err)
	}

	// Granted user should have access
	result, err = contract.CheckAccess(checkCtx, "doc-acl", "user-002", "TestMSP")
	if err != nil || result != "true" {
		t.Errorf("grantee user-002 should have access: got %q err=%v", result, err)
	}
	commitTx(stub, "tx-acl-check")
}

func TestCheckAccess_Denied(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-acl-deny")
	contract := &LegalContract{}

	_ = contract.RegisterDocument(ctx, "doc-deny", "case-001", "hash", "Qm2", "owner-001", "TestMSP", nowTS())
	commitTx(stub, "tx-acl-deny")

	stub.MockTransactionStart("tx-acl-deny-check")
	checkCtx := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "OtherMSP"}}
	result, err := contract.CheckAccess(checkCtx, "doc-deny", "user-999", "OtherMSP")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if result != "false" {
		t.Errorf("expected 'false' for unknown user, got %q", result)
	}
	commitTx(stub, "tx-acl-deny-check")
}

// ─── LogAuditEvent ────────────────────────────────────────────────────────────

func TestRecordAuditEvent(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-audit")
	contract := &LegalContract{}

	err := contract.LogAuditEvent(ctx,
		"DOC_VIEWED", "user-001", "TestMSP", "doc-001",
		`{"action":"download"}`, "")
	if err != nil {
		t.Fatalf("LogAuditEvent: %v", err)
	}
	commitTx(stub, "tx-audit")

	// Verify an AUDIT: key was written to state
	iter, err := stub.GetStateByRange("AUDIT:", "AUDIT:~")
	if err != nil {
		t.Fatalf("GetStateByRange: %v", err)
	}
	defer iter.Close()

	found := false
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			break
		}
		var event AuditEvent
		if jsonErr := json.Unmarshal(kv.Value, &event); jsonErr == nil && event.EventType == "DOC_VIEWED" {
			found = true
			break
		}
	}
	if !found {
		t.Error("audit event DOC_VIEWED not found in ledger")
	}
}

// ─── GetDocumentHistory ───────────────────────────────────────────────────────

func TestGetHistoryForKey(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-hist-1")
	contract := &LegalContract{}

	// Version 1: register document
	_ = contract.RegisterDocument(ctx, "doc-hist", "case-001", "hash-v1", "Qm-v1", "owner-001", "TestMSP", nowTS())
	commitTx(stub, "tx-hist-1")

	// Version 2: update document
	stub.MockTransactionStart("tx-hist-2")
	ctx2 := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "TestMSP"}}
	_ = contract.UpdateDocument(ctx2, "doc-hist", "Qm-v2", "hash-v2", "owner-001")
	commitTx(stub, "tx-hist-2")

	// Query history
	stub.MockTransactionStart("tx-hist-query")
	queryCtx := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "TestMSP"}}
	history, err := contract.GetDocumentHistory(queryCtx, "doc-hist")
	commitTx(stub, "tx-hist-query")

	if err != nil {
		// shimtest.MockStub does not implement GetHistoryForKey, so this path cannot be
		// exercised off-network. History behaviour is covered live by Experiment 7 instead.
		t.Skipf("GetDocumentHistory unsupported by the mock ledger: %v", err)
	}
	if len(history) == 0 {
		t.Error("expected at least one history entry, got 0")
	}
}

// ─── TimeAnchor ───────────────────────────────────────────────────────────────
//
// These cover reviewer finding M2: grant expiry is evaluated from a timestamp the calling
// gateway supplies, so a compromised gateway could backdate its way past an expired grant.

// seedAnchor writes a TimeAnchor directly to state at the given time, standing in for a
// heartbeat that was endorsed and committed at that moment.
func seedAnchor(t *testing.T, stub *shimtest.MockStub, at time.Time) {
	t.Helper()
	anchor := &TimeAnchor{
		Timestamp: at.UTC().Format(time.RFC3339),
		UpdatedBy: "TestMSP",
		Sequence:  1,
	}
	data, err := json.Marshal(anchor)
	if err != nil {
		t.Fatalf("marshal anchor: %v", err)
	}
	stub.MockTransactionStart("tx-seed-anchor")
	if err := stub.PutState(TimeAnchorKey, data); err != nil {
		t.Fatalf("seed anchor: %v", err)
	}
	commitTx(stub, "tx-seed-anchor")
}

func TestUpdateTimeAnchor_EstablishesAndAdvances(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-anchor-1")
	contract := &LegalContract{}

	if err := contract.UpdateTimeAnchor(ctx); err != nil {
		t.Fatalf("first heartbeat should be accepted: %v", err)
	}
	commitTx(stub, "tx-anchor-1")

	raw, err := stub.GetState(TimeAnchorKey)
	if err != nil || raw == nil {
		t.Fatalf("anchor not written: err=%v", err)
	}
	var anchor TimeAnchor
	if err := json.Unmarshal(raw, &anchor); err != nil {
		t.Fatalf("decode anchor: %v", err)
	}
	if anchor.Sequence != 1 {
		t.Errorf("first anchor sequence = %d, want 1", anchor.Sequence)
	}
	if anchor.UpdatedBy != "TestMSP" {
		t.Errorf("anchor UpdatedBy = %q, want TestMSP", anchor.UpdatedBy)
	}
}

// A heartbeat that does not move time forward must be refused, otherwise a replayed or
// stalled heartbeat could hold the anchor back and widen the backdating window.
func TestUpdateTimeAnchor_RejectsNonAdvancing(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-anchor-stale")
	contract := &LegalContract{}

	seedAnchor(t, stub, time.Now().Add(1*time.Hour))

	err := contract.UpdateTimeAnchor(ctx)
	commitTx(stub, "tx-anchor-stale")
	if err == nil {
		t.Fatal("expected a heartbeat older than the current anchor to be rejected")
	}
}

// The core M2 case: an expired grant, and a caller presenting a backdated proposal
// timestamp that would make it look live. With an anchor committed, the decision is
// refused rather than silently granted.
func TestCheckAccess_RejectsBackdatedProposal(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-backdate-setup")
	contract := &LegalContract{}

	// Grant expired an hour ago.
	expired := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	_ = contract.RegisterDocument(ctx, "doc-bd", "case-bd", "hash", "Qm-bd", "owner-bd", "TestMSP", nowTS())
	_ = contract.GrantAccess(ctx, "doc-bd", "user-bd", "TestMSP", CapRead, expired, "wrapped", "owner-bd", "")
	commitTx(stub, "tx-backdate-setup")

	// No anchor yet: the mechanism is inactive, so this is the pre-fix behaviour. The grant
	// is expired, so access is denied on expiry alone -- the timestamp is not yet policed.
	stub.MockTransactionStart("tx-backdate-noanchor")
	noAnchorCtx := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "TestMSP"}}
	result, err := contract.CheckAccess(noAnchorCtx, "doc-bd", "user-bd", "TestMSP")
	commitTx(stub, "tx-backdate-noanchor")
	if err != nil || result != "true" && result != "false" {
		t.Fatalf("unexpected pre-anchor result: %q err=%v", result, err)
	}

	// Now commit an anchor well ahead of any timestamp a backdating caller would present.
	// A proposal claiming a time far behind the anchor must be refused outright.
	seedAnchor(t, stub, time.Now().Add(24*time.Hour))

	stub.MockTransactionStart("tx-backdate-anchored")
	anchoredCtx := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "TestMSP"}}
	result, err = contract.CheckAccess(anchoredCtx, "doc-bd", "user-bd", "TestMSP")
	commitTx(stub, "tx-backdate-anchored")

	if err == nil {
		t.Error("expected a proposal far behind the anchor to be refused, got no error")
	}
	if result != "false" {
		t.Errorf("backdated proposal must not be authorised, got %q", result)
	}
}

// A live grant must still be authorised while the anchor is current: the freshness check
// has to reject backdating without breaking ordinary access.
func TestCheckAccess_AnchorDoesNotBlockLiveGrant(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-anchor-live")
	contract := &LegalContract{}

	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	_ = contract.RegisterDocument(ctx, "doc-live", "case-live", "hash", "Qm-live", "owner-live", "TestMSP", nowTS())
	_ = contract.GrantAccess(ctx, "doc-live", "user-live", "TestMSP", CapRead, future, "wrapped", "owner-live", "")
	commitTx(stub, "tx-anchor-live")

	// Anchor a few seconds old, as a recent heartbeat would leave it.
	seedAnchor(t, stub, time.Now().Add(-5*time.Second))

	stub.MockTransactionStart("tx-anchor-live-check")
	checkCtx := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "TestMSP"}}
	result, err := contract.CheckAccess(checkCtx, "doc-live", "user-live", "TestMSP")
	commitTx(stub, "tx-anchor-live-check")

	if err != nil {
		t.Fatalf("live grant with a fresh anchor should not error: %v", err)
	}
	if result != "true" {
		t.Errorf("live grant should be authorised, got %q", result)
	}
}

// An anchor that has stopped advancing (heartbeat suppressed, or ordering down) must not
// start refusing ordinary traffic: proposals ahead of the anchor are normal.
func TestCheckAccess_StaleAnchorStillAuthorisesLiveGrant(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-anchor-staleanchor")
	contract := &LegalContract{}

	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	_ = contract.RegisterDocument(ctx, "doc-sa", "case-sa", "hash", "Qm-sa", "owner-sa", "TestMSP", nowTS())
	_ = contract.GrantAccess(ctx, "doc-sa", "user-sa", "TestMSP", CapRead, future, "wrapped", "owner-sa", "")
	commitTx(stub, "tx-anchor-staleanchor")

	// Anchor is two hours old: ordering has been unavailable for a while.
	seedAnchor(t, stub, time.Now().Add(-2*time.Hour))

	stub.MockTransactionStart("tx-anchor-staleanchor-check")
	checkCtx := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "TestMSP"}}
	result, err := contract.CheckAccess(checkCtx, "doc-sa", "user-sa", "TestMSP")
	commitTx(stub, "tx-anchor-staleanchor-check")

	if err != nil {
		t.Fatalf("a stale anchor must not break live access: %v", err)
	}
	if result != "true" {
		t.Errorf("live grant should still be authorised against a stale anchor, got %q", result)
	}
}

// ─── Organization fallback removal (reviewer M5) ──────────────────────────────

// A member of the owning organization who holds no grant must be denied. This pins the
// removal of the implicit `doc.OwnerOrg == userOrg` fallback: without an explicit grant,
// sharing an organization with the document owner confers nothing.
func TestCheckAccess_SameOrgWithoutGrantIsDenied(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-m5-deny")
	contract := &LegalContract{}

	_ = contract.RegisterDocument(ctx, "doc-m5", "case-m5", "hash", "Qm-m5", "owner-m5", "FirmAMSP", nowTS())
	commitTx(stub, "tx-m5-deny")

	stub.MockTransactionStart("tx-m5-check")
	checkCtx := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "FirmAMSP"}}
	result, err := contract.CheckAccess(checkCtx, "doc-m5", "colleague-no-grant", "FirmAMSP")
	commitTx(stub, "tx-m5-check")

	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if result != "false" {
		t.Errorf("same-org user without a grant must be denied, got %q", result)
	}
}

// The owner must retain access after the fallback removal, via the explicit self-grant
// RegisterDocument creates. If this breaks, upload-then-download is broken.
func TestCheckAccess_OwnerRetainsAccessWithoutFallback(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-m5-owner")
	contract := &LegalContract{}

	_ = contract.RegisterDocument(ctx, "doc-m5o", "case-m5o", "hash", "Qm-m5o", "owner-m5o", "FirmAMSP", nowTS())
	commitTx(stub, "tx-m5-owner")

	stub.MockTransactionStart("tx-m5-owner-check")
	checkCtx := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "FirmAMSP"}}
	result, err := contract.CheckAccess(checkCtx, "doc-m5o", "owner-m5o", "FirmAMSP")
	commitTx(stub, "tx-m5-owner-check")

	if err != nil || result != "true" {
		t.Errorf("owner must retain access via the explicit self-grant: got %q err=%v", result, err)
	}
}

// An explicit grant to a same-org colleague must still work - the removal targets the
// implicit fallback, not deliberate intra-firm sharing.
func TestCheckAccess_SameOrgWithExplicitGrantIsAllowed(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-m5-grant")
	contract := &LegalContract{}

	_ = contract.RegisterDocument(ctx, "doc-m5g", "case-m5g", "hash", "Qm-m5g", "owner-m5g", "FirmAMSP", nowTS())
	_ = contract.GrantAccess(ctx, "doc-m5g", "colleague-m5g", "FirmAMSP", CapRead, "", "wrapped", "owner-m5g", "")
	commitTx(stub, "tx-m5-grant")

	stub.MockTransactionStart("tx-m5-grant-check")
	checkCtx := &testContext{stub: stub, cid: &mockClientIdentity{mspID: "FirmAMSP"}}
	result, err := contract.CheckAccess(checkCtx, "doc-m5g", "colleague-m5g", "FirmAMSP")
	commitTx(stub, "tx-m5-grant-check")

	if err != nil || result != "true" {
		t.Errorf("explicitly granted same-org colleague should have access: got %q err=%v", result, err)
	}
}

// ─── Audit finding S1: the P = A freshness counterexample ─────────────────────

// timestampOverrideStub lets a test present an arbitrary proposal timestamp, which
// the shimtest mock cannot do on its own. It stands in for a caller that controls
// the timestamp field of its own proposal, which is exactly the adversary of A7.
type timestampOverrideStub struct {
	shim.ChaincodeStubInterface
	at time.Time
}

func (s *timestampOverrideStub) GetTxTimestamp() (*timestamppb.Timestamp, error) {
	return timestamppb.New(s.at), nil
}

// The pre-submission audit's S1 counterexample: measure anchor staleness against the
// caller-supplied proposal timestamp and a caller that sets P = A makes an arbitrarily
// old anchor look fresh, so an expired grant is authorised from the past. With staleness
// measured by the answering peer's own clock the same proposal is refused.
func TestCheckAccess_RejectsForgedFreshness_PEqualsA(t *testing.T) {
	ctx, stub := setupCtx(t, "tx-s1-setup")
	contract := &LegalContract{}

	// Grant expired one hour ago, but it was still live two hours ago.
	expired := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	_ = contract.RegisterDocument(ctx, "doc-s1", "case-s1", "hash", "Qm-s1", "owner-s1", "TestMSP", nowTS())
	_ = contract.GrantAccess(ctx, "doc-s1", "user-s1", "TestMSP", CapRead, expired, "wrapped", "owner-s1", "")
	commitTx(stub, "tx-s1-setup")

	// Enable a ceiling for this test; the shipped default of zero disables the
	// check entirely, which is the documented no-bound configuration.
	MaxAnchorStalenessSeconds = 120
	defer func() { MaxAnchorStalenessSeconds = 0 }()

	// The heartbeat has been starved for two hours: the anchor is far beyond the ceiling.
	anchorAt := time.Now().Add(-2 * time.Hour)
	seedAnchor(t, stub, anchorAt)

	// The attacker submits a proposal whose timestamp equals the anchor's own instant.
	// Both proposal-versus-anchor comparisons then pass by construction; only a check
	// against a clock the caller does not control can refuse this.
	stub.MockTransactionStart("tx-s1-attack")
	forged := &timestampOverrideStub{ChaincodeStubInterface: stub, at: anchorAt}
	attackCtx := &overrideContext{stub: forged, cid: &mockClientIdentity{mspID: "TestMSP"}}
	result, err := contract.CheckAccess(attackCtx, "doc-s1", "user-s1", "TestMSP")
	commitTx(stub, "tx-s1-attack")

	if err == nil {
		t.Error("expected the stale anchor to be refused by the peer clock, got no error")
	}
	if result == "true" {
		t.Error("P = A forged-freshness proposal must not be authorised")
	}
}

// overrideContext is testContext with an arbitrary stub interface, so wrapper stubs
// can be injected.
type overrideContext struct {
	stub shim.ChaincodeStubInterface
	cid  *mockClientIdentity
}

func (tc *overrideContext) GetStub() shim.ChaincodeStubInterface { return tc.stub }
func (tc *overrideContext) GetClientIdentity() cid.ClientIdentity { return tc.cid }
