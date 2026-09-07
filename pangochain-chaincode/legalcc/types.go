package main

// DocumentAsset is the on-chain representation of a registered document.
type DocumentAsset struct {
	DocID         string            `json:"docId"`
	CaseID        string            `json:"caseId"`
	DocumentHash  string            `json:"documentHash"`  // SHA-256 of plaintext
	IpfsCID       string            `json:"ipfsCid"`
	OwnerID       string            `json:"ownerId"`
	OwnerOrg      string            `json:"ownerOrg"`
	Timestamp     string            `json:"timestamp"`
	Status        string            `json:"status"`        // ACTIVE | DELETED | SUPERSEDED
	PrevVersionID string            `json:"prevVersionId"` // empty if first version
	Version       int               `json:"version"`
	ACL           map[string]*Grant `json:"acl"`           // subject -> Grant
}

// Grant represents an access capability for one subject on a document.
type Grant struct {
	Capability      string `json:"capability"`      // owner | write | read
	SubjectOrg      string `json:"subjectOrg"`
	GrantedBy       string `json:"grantedBy"`
	GrantedAt       string `json:"grantedAt"`
	ExpiresAt       string `json:"expiresAt"`       // RFC3339, empty = no expiry
	WrappedKeyRef   string `json:"wrappedKeyRef"`   // base64 ECIES-wrapped doc key
	Status          string `json:"status"`          // ACTIVE | REVOKED | EXPIRED
	RevokedAt       string `json:"revokedAt"`
}

// AuditEvent is a SHA-256 chained audit record stored on the ledger.
type AuditEvent struct {
	EventID       string `json:"eventId"`
	EventType     string `json:"eventType"`
	ActorID       string `json:"actorId"`
	ActorOrg      string `json:"actorOrg"`
	ResourceID    string `json:"resourceId"`
	ContextJSON   string `json:"contextJson"`
	PrevAuditHash string `json:"prevAuditHash"` // SHA-256 of previous event payload
	Timestamp     string `json:"timestamp"`
}

// TimeAnchor is a periodically refreshed reference point for wall-clock time.
//
// Grant expiry is evaluated inside CheckAccess, which runs as a Fabric *evaluate*.
// GetTxTimestamp() on an evaluate returns the timestamp the client put in its proposal,
// and in a custodial deployment the client is the application gateway - the component the
// architecture claims to remove from the authorization TCB. A compromised gateway could
// therefore backdate a proposal to satisfy an already-expired ExpiresAt.
//
// UpdateTimeAnchor is a *submit*, so its proposal is seen by every endorsing peer before it
// commits, and each peer independently refuses to endorse a proposal whose timestamp is
// implausible against that peer's own clock. A backdated anchor therefore cannot reach the
// ledger without collusion satisfying the endorsement policy. CheckAccess then rejects any
// proposal timestamp that sits more than MaxClockSkewSeconds behind the committed anchor,
// which bounds undetected backdating to roughly the heartbeat interval plus that tolerance
// instead of leaving it unbounded.
type TimeAnchor struct {
	// Timestamp is the endorsed proposal time of the heartbeat, RFC3339.
	Timestamp string `json:"timestamp"`
	// UpdatedBy is the MSP ID that submitted the heartbeat.
	UpdatedBy string `json:"updatedBy"`
	// Sequence increments on every accepted heartbeat, so a replayed or stalled anchor is visible.
	Sequence int64 `json:"sequence"`
}

// CaseAsset is the on-chain record of a legal case/matter.
type CaseAsset struct {
	CaseID    string `json:"caseId"`
	FirmID    string `json:"firmId"`
	Title     string `json:"title"`
	CreatorID string `json:"creatorId"`
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"` // ACTIVE | CLOSED | ARCHIVED
}

// UserKeyBinding anchors the hash of a user's public wrapping key at enrollment,
// making key substitution in the operational identity table detectable at grant
// time (threat-model Scenario S3). The binding is immutable: first write wins,
// and key rotation requires an explicit consortium-governed re-registration,
// which is deliberately not implemented here.
type UserKeyBinding struct {
	UserID       string `json:"userId"`
	KeyHash      string `json:"keyHash"` // SHA-256 (hex) over the stored public-key JWK string
	RegisteredAt string `json:"registeredAt"`
	RegisteredBy string `json:"registeredBy"` // MSP that submitted the binding
}

// Composite key prefixes
const (
	DocPrefix     = "DOC"
	CasePrefix    = "CASE"
	AuditPrefix   = "AUDIT"
	UserKeyPrefix = "USERKEY"

	// TimeAnchorKey is the single world-state key holding the current TimeAnchor.
	TimeAnchorKey = "TIMEANCHOR"

	// MaxHeartbeatSkewSeconds is how far an UpdateTimeAnchor proposal's timestamp may sit
	// from an endorsing peer's own clock and still be endorsed. It must comfortably exceed
	// real NTP drift and endorsement latency between peers, or honest heartbeats will fail
	// to collect endorsements; it must stay small enough that it does not itself become the
	// backdating window.
	MaxHeartbeatSkewSeconds = 120

	// MaxClockSkewSeconds is how far behind the committed anchor a CheckAccess proposal
	// timestamp may sit before the decision is refused. Undetected backdating is bounded by
	// roughly the anchor's staleness plus this value.
	MaxClockSkewSeconds = 120

	// disableFreshnessCheckForMeasurement removes the TimeAnchor read from CheckAccess so
	// Experiment 17 can measure that read's cost by paired comparison against an otherwise
	// identical chaincode. It exists purely as a measurement control and MUST stay false in
	// any deployed build: flipping it restores the unbounded-backdating behaviour of
	// reviewer finding M2.
	disableFreshnessCheckForMeasurement = false

	// MaxAnchorStalenessSeconds refuses access decisions once the anchor has stopped
	// advancing for this long, measured against the answering peer's own wall clock
	// (pre-submission audit S1: measuring it against the caller's proposal timestamp
	// is circular, since a caller choosing P = A defeats any ceiling).
	//
	// This exists because the backdating bound is only as good as the anchor's freshness,
	// and the party submitting heartbeats is the same custodial gateway the mechanism is
	// meant to constrain. That gateway cannot rewind the anchor, but it can stop feeding it;
	// the anchor then freezes and the reachable backdating window grows with the suppression
	// interval. Enforcing a staleness ceiling caps that window at this value regardless of
	// how long heartbeats have been withheld.
	//
	// The cost is availability: once ordering is unavailable for longer than this, honest
	// access decisions are refused too, because a stalled anchor and a suppressed one are
	// indistinguishable from inside CheckAccess. Zero disables the ceiling, which keeps
	// reads available during an outage and accepts the weaker bound - that is the trade-off
	// swept in Experiment 17, and the reason this is a knob rather than a fixed policy.
	//
	// Deliberately a compile-time constant rather than a value settable by a chaincode
	// function. A runtime-settable security ceiling would be a privileged knob reachable by
	// exactly the compromised gateway this mechanism exists to constrain - setting it to
	// zero would disable the ceiling silently. As a constant, weakening it requires
	// redeploying the chaincode, which Fabric's lifecycle already gates behind multi-org
	// approval. The cost is that Experiment 17 must redeploy to sweep it.
	// (Declared as a package variable below purely so unit tests can exercise
	// nonzero ceilings; nothing in the chaincode mutates it at runtime.)

	StatusActive    = "ACTIVE"
	StatusRevoked   = "REVOKED"
	StatusExpired   = "EXPIRED"
	StatusDeleted   = "DELETED"
	StatusSuperseded = "SUPERSEDED"

	CapOwner = "owner"
	CapWrite = "write"
	CapRead  = "read"
)

// See the commentary in the constant block above: sweep-settable at build time,
// test-settable in unit tests, never mutated at runtime.
var (
	MaxAnchorStalenessSeconds = 0
)
