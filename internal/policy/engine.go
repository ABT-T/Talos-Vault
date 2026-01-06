package policy

import (
	"context"
	"sync/atomic"
)

// Policy represents a simple access control rule.
type Policy struct {
	Resource string
	Action   string
	Effect   string // "allow" or "deny"
}

// Engine implements a lock-free policy evaluation engine using atomic.Value.
// This ensures that reads (CheckAccess) are never blocked by writes (LoadPolicies).
type Engine struct {
	// policies holds a map[string][]Policy
	// We use atomic.Value to swap the entire map pointer during updates.
	policies atomic.Value
}

// NewEngine initializes the policy engine with an empty policy set.
func NewEngine() *Engine {
	e := &Engine{}
	// Initialize with an empty map to avoid nil pointer dereference on first read.
	e.policies.Store(make(map[string][]Policy))
	return e
}

// LoadPolicies updates the policy set atomically.
// This operation is thread-safe and does not block readers.
func (e *Engine) LoadPolicies(newPolicies map[string][]Policy) {
	// atomic.Store is extremely fast and acts as a memory barrier.
	e.policies.Store(newPolicies)
}

// CheckAccess evaluates if a subject can perform an action on a resource.
// Target Performance: < 1ms p99.
func (e *Engine) CheckAccess(ctx context.Context, subject, resource, action string) (bool, error) {
	// Load the current snapshot of policies.
	// This is a wait-free operation (no locks).
	policyMap := e.policies.Load().(map[string][]Policy)

	rules, exists := policyMap[subject]
	if !exists {
		// Default deny if no policies found for subject.
		return false, nil
	}

	// iterate over rules (linear scan is fine for small N, use O(1) lookup for large sets)
	for _, rule := range rules {
		if rule.Resource == resource && rule.Action == action {
			if rule.Effect == "allow" {
				return true, nil
			}
			// Explicit deny takes precedence in this simple model,
			// though here we return immediately on first match for speed.
			// Ideally, you'd collect all matching rules and resolve conflicts.
			return false, nil
		}
	}

	return false, nil
}
