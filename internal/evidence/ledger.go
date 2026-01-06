package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// DecisionLog represents a single immutable entry in the audit chain.
type DecisionLog struct {
	Timestamp time.Time
	Subject   string
	Decision  string // "Allow" or "Deny"
	PrevHash  string // The hash of the previous record (Merkle link)
	SelfHash  string // SHA256(Timestamp + Subject + Decision + PrevHash)
}

// Ledger acts as a tamper-evident log store.
type Ledger struct {
	mu       sync.Mutex
	chain    []DecisionLog
	lastHash string
}

// NewLedger initializes the hash chain with a genesis block.
func NewLedger() *Ledger {
	// Genesis hash (arbitrary seed)
	genesisHash := "0000000000000000000000000000000000000000000000000000000000000000"
	return &Ledger{
		chain:    make([]DecisionLog, 0),
		lastHash: genesisHash,
	}
}

// LogDecision appends a new decision to the immutable chain.
// It calculates the hash based on the previous entry to ensure integrity.
func (l *Ledger) LogDecision(subject, decision string) string {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().UTC()
	prev := l.lastHash

	// Construct the payload to be hashed.
	// Format: <ISO8601>|<Subject>|<Decision>|<PrevHash>
	payload := fmt.Sprintf("%s|%s|%s|%s", ts.Format(time.RFC3339Nano), subject, decision, prev)

	// Compute SHA-256
	hasher := sha256.New()
	hasher.Write([]byte(payload))
	currentHash := hex.EncodeToString(hasher.Sum(nil))

	entry := DecisionLog{
		Timestamp: ts,
		Subject:   subject,
		Decision:  decision,
		PrevHash:  prev,
		SelfHash:  currentHash,
	}

	l.chain = append(l.chain, entry)
	l.lastHash = currentHash

	// In a real system, you would asynchronously flush 'entry' to persistent storage (e.g., DB, File)
	// while keeping the hash chain logic in memory or consistent storage.
	
	return currentHash
}

// VerifyIntegrity re-calculates the entire chain to detect tampering.
func (l *Ledger) VerifyIntegrity() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	expectedPrev := "0000000000000000000000000000000000000000000000000000000000000000"

	for i, entry := range l.chain {
		if entry.PrevHash != expectedPrev {
			return false, fmt.Errorf("chain broken at index %d: prevHash mismatch", i)
		}

		payload := fmt.Sprintf("%s|%s|%s|%s", entry.Timestamp.Format(time.RFC3339Nano), entry.Subject, entry.Decision, entry.PrevHash)
		hasher := sha256.New()
		hasher.Write([]byte(payload))
		recalcHash := hex.EncodeToString(hasher.Sum(nil))

		if recalcHash != entry.SelfHash {
			return false, fmt.Errorf("data corrupted at index %d: hash mismatch", i)
		}

		expectedPrev = entry.SelfHash
	}

	return true, nil
}
