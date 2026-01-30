package policy

import (
	"encoding/json"
	"fmt"
	"log/slog" // We need logging here now
	"os"
	"strings"
	"sync"
	"time"
)

// Policy defines what a workload is allowed to do.
type Policy struct {
	AllowedExecs   []string `json:"allowed_execs"`
	AllowedDomains []string `json:"allowed_domains"`
	AllowedMethods []string `json:"allowed_methods"`
}

// Engine manages policies and evaluates requests.
type Engine struct {
	mu       sync.RWMutex
	policies map[string]Policy
}

func NewEngine() *Engine {
	return &Engine{
		policies: make(map[string]Policy),
	}
}

// LoadPoliciesFromFile reads the JSON config and updates the engine.
func (e *Engine) LoadPoliciesFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	var newPolicies map[string]Policy
	if err := json.Unmarshal(data, &newPolicies); err != nil {
		return fmt.Errorf("failed to parse policy json: %w", err)
	}

	e.mu.Lock()
	e.policies = newPolicies
	e.mu.Unlock()

	return nil
}

// Watch starts a background worker to reload policies on change.
// NOTE: In production, use fsnotify/fsnotify instead of polling.
func (e *Engine) Watch(path string, logger *slog.Logger) {
	var lastMod time.Time

	for {
		info, err := os.Stat(path)
		if err != nil {
			logger.Error("Policy Watcher Error", "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// If file is modified more recently than last load
		if info.ModTime().After(lastMod) {
			logger.Info("Policy file changed, reloading...", "path", path)
			
			if err := e.LoadPoliciesFromFile(path); err != nil {
				logger.Error("Failed to reload policies", "error", err)
			} else {
				lastMod = info.ModTime()
				logger.Info("Policies successfully hot-reloaded!")
			}
		}

		time.Sleep(2 * time.Second) // Poll every 2 seconds
	}
}

func (e *Engine) Evaluate(spiffeID, action, target string) (bool, string) {
	e.mu.RLock()
	policy, exists := e.policies[spiffeID]
	e.mu.RUnlock()

	if !exists {
		return false, fmt.Sprintf("no policy found for identity: %s", spiffeID)
	}

	switch action {
	case "exec":
		for _, allowed := range policy.AllowedExecs {
			if allowed == target {
				return true, "exec allowed by policy"
			}
		}
	case "net-outbound":
		for _, allowed := range policy.AllowedDomains {
			if strings.HasSuffix(target, allowed) {
				return true, "network access allowed by policy"
			}
		}
	default:
		return false, "unknown action type"
	}

	return false, "action denied: target not in allow-list"
}
