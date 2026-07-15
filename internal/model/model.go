// Package model mirrors the Egret ingest contract (schema_version 1) as plain
// Go structs. It is a deliberate *copy* of the wire shape — the dashboard does
// NOT import the agent's Go packages, so the only coupling is the versioned
// JSON contract documented in Egret/docs/ingest-contract.md.
package model

import "time"

// SchemaVersion is the ingest contract version this dashboard understands.
const SchemaVersion = 1

// Envelope is the top-level payload POSTed to /ingest.
type Envelope struct {
	SchemaVersion   int       `json:"schema_version"`
	Producer        string    `json:"producer"`
	ProducerVersion string    `json:"producer_version,omitempty"`
	GeneratedAt     time.Time `json:"generated_at"`
	Run             RunMeta   `json:"run"`
	Session         *Session  `json:"session"`
}

// RunMeta identifies where a run happened (from the CI provider).
type RunMeta struct {
	Provider   string `json:"provider,omitempty"`
	Repository string `json:"repository,omitempty"`
	SHA        string `json:"sha,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	RunAttempt string `json:"run_attempt,omitempty"`
	Actor      string `json:"actor,omitempty"`
}

// Session is the observed run — identical shape to the agent's report.json.
type Session struct {
	StartedAt   time.Time    `json:"started_at"`
	FinishedAt  time.Time    `json:"finished_at"`
	Command     []string     `json:"command"`
	Mode        string       `json:"mode"`
	ExitCode    int          `json:"exit_code"`
	Connections []Connection `json:"connections"`
	Processes   []Process    `json:"processes"`
	FileWrites  []FileWrite  `json:"file_writes"`
	Violations  []Violation  `json:"violations"`
}

type Connection struct {
	Time   time.Time `json:"time"`
	PID    uint32    `json:"pid"`
	Comm   string    `json:"comm"`
	Daddr  string    `json:"daddr"`
	Dport  uint16    `json:"dport"`
	Proto  string    `json:"proto"`
	Domain string    `json:"domain,omitempty"`
}

// Endpoint is the domain if known, else the raw IP — the identity used for
// allowlist drift.
func (c Connection) Endpoint() string {
	if c.Domain != "" {
		return c.Domain
	}
	return c.Daddr
}

type Process struct {
	Time     time.Time `json:"time"`
	PID      uint32    `json:"pid"`
	PPID     uint32    `json:"ppid"`
	Comm     string    `json:"comm"`
	Filename string    `json:"filename"`
}

type FileWrite struct {
	Time time.Time `json:"time"`
	PID  uint32    `json:"pid"`
	Comm string    `json:"comm"`
	Path string    `json:"path"`
	Op   string    `json:"op"`
}

type Violation struct {
	Kind    string `json:"kind"`
	Reason  string `json:"reason"`
	Detail  string `json:"detail"`
	Blocked bool   `json:"blocked"`
}
