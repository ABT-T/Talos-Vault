package sidecar

import (
	"sync"
)

// RevocationList handles instant blocking of compromised identities.
// It bypasses policy checks and certificate TTLs.
type RevocationList struct {
	// blockedIdentities uses sync.Map for concurrent read-optimized access.
	// Key: SPIFFE ID or Subject string, Value: struct{}{} (empty)
	blockedIdentities sync.Map
}

// NewRevocationList creates an empty revocation list.
func NewRevocationList() *RevocationList {
	return &RevocationList{}
}

// Revoke immediately adds a subject to the blocklist.
// This operation takes effect instantly across all goroutines.
func (r *RevocationList) Revoke(subject string) {
	r.blockedIdentities.Store(subject, struct{}{})
}

// Restore removes a subject from the blocklist.
func (r *RevocationList) Restore(subject string) {
	r.blockedIdentities.Delete(subject)
}

// IsRevoked checks if the subject is currently blocked.
// This is an O(1) operation designed to be called on every request.
func (r *RevocationList) IsRevoked(subject string) bool {
	_, found := r.blockedIdentities.Load(subject)
	return found
}
