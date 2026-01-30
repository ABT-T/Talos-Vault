package storage

import (
    "database/sql"
    "encoding/json"
    "log"
    "sync"
    "time"

    _ "github.com/mattn/go-sqlite3"
)

// Policy represents the security rule structure
type Policy struct {
    Subject string `json:"subject"`
    Action  string `json:"action"`
    Effect  string `json:"effect"` // allow/deny
}

// AuditEntry represents an immutable log entry
type AuditEntry struct {
    Timestamp time.Time `json:"timestamp"`
    Principal string    `json:"principal"`
    Action    string    `json:"action"`
    Decision  string    `json:"decision"`
}

// Store defines the interface for persistence
type Store interface {
    SavePolicy(subject string, policy Policy) error
    GetPolicies(subject string) ([]Policy, error)
    GetAllPolicies() (map[string][]Policy, error)
    AppendAuditLog(entry AuditEntry) error
    Close() error
}

// SQLiteStore implements Store with In-Memory fallback
type SQLiteStore struct {
    db          *sql.DB
    mu          sync.RWMutex
    useInMemory bool
    // In-memory storage
    memPolicies map[string][]Policy
    memAudits   []AuditEntry
}

// NewSQLiteStore initializes the DB or falls back to memory
func NewSQLiteStore(path string) (*SQLiteStore, error) {
    db, err := sql.Open("sqlite3", path)
    if err != nil {
        log.Printf("[storage] sqlite open failed (%v); using in-memory store", err)
        return newInMemoryStore(), nil
    }

    // Try initializing schema
    schema := `
    CREATE TABLE IF NOT EXISTS policies (
        subject TEXT,
        data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (subject)
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        principal TEXT,
        action TEXT,
        decision TEXT,
        timestamp DATETIME
    );`

    if _, err := db.Exec(schema); err != nil {
        log.Printf("[storage] sqlite schema init failed (%v); using in-memory store", err)
        db.Close()
        return newInMemoryStore(), nil
    }

    return &SQLiteStore{db: db, useInMemory: false}, nil
}

func newInMemoryStore() *SQLiteStore {
    return &SQLiteStore{
        db:          nil,
        useInMemory: true,
        memPolicies: make(map[string][]Policy),
        memAudits:   make([]AuditEntry, 0),
    }
}

// SavePolicy upserts a policy
func (s *SQLiteStore) SavePolicy(subject string, policy Policy) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    // 1. In-Memory Path
    if s.useInMemory {
        s.memPolicies[subject] = []Policy{policy}
        return nil
    }

    // 2. SQLite Path
    data, err := json.Marshal(policy)
    if err != nil {
        return err
    }
    query := `INSERT INTO policies (subject, data) VALUES (?, ?) 
              ON CONFLICT(subject) DO UPDATE SET data=excluded.data`
    _, err = s.db.Exec(query, subject, string(data))
    return err
}

// GetPolicies retrieves policies for a subject
func (s *SQLiteStore) GetPolicies(subject string) ([]Policy, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    // 1. In-Memory Path
    if s.useInMemory {
        if policies, ok := s.memPolicies[subject]; ok {
            return policies, nil
        }
        return nil, nil
    }

    // 2. SQLite Path
    var data string
    err := s.db.QueryRow("SELECT data FROM policies WHERE subject = ?", subject).Scan(&data)
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }

    var p Policy
    if err := json.Unmarshal([]byte(data), &p); err != nil {
        return nil, err
    }
    return []Policy{p}, nil
}

// GetAllPolicies retrieves all policies
func (s *SQLiteStore) GetAllPolicies() (map[string][]Policy, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    // 1. In-Memory Path
    if s.useInMemory {
        // Return a copy to be safe
        copyMap := make(map[string][]Policy)
        for k, v := range s.memPolicies {
            copyMap[k] = v
        }
        return copyMap, nil
    }

    // 2. SQLite Path
    rows, err := s.db.Query("SELECT subject, data FROM policies")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    result := make(map[string][]Policy)
    for rows.Next() {
        var subject, data string
        if err := rows.Scan(&subject, &data); err != nil {
            return nil, err
        }
        var p Policy
        _ = json.Unmarshal([]byte(data), &p)
        result[subject] = []Policy{p}
    }
    return result, nil
}

// AppendAuditLog inserts a new log entry
func (s *SQLiteStore) AppendAuditLog(entry AuditEntry) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    // 1. In-Memory Path
    if s.useInMemory {
        s.memAudits = append(s.memAudits, entry)
        if len(s.memAudits) > 1000 {
            s.memAudits = s.memAudits[1:]
        }
        return nil
    }

    // 2. SQLite Path
    _, err := s.db.Exec("INSERT INTO audit_logs (principal, action, decision, timestamp) VALUES (?, ?, ?, ?)",
        entry.Principal, entry.Action, entry.Decision, entry.Timestamp)
    return err
}

func (s *SQLiteStore) Close() error {
    if s.useInMemory {
        return nil
    }
    return s.db.Close()
}