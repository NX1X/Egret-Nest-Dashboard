package model

import (
	"encoding/json"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	// A representative payload matching the ingest contract wire format.
	raw := `{
	  "schema_version": 1,
	  "producer": "egret",
	  "producer_version": "v0.1.0",
	  "generated_at": "2026-07-02T10:00:00Z",
	  "run": {"provider":"github-actions","repository":"NX1X/Egret","sha":"deadbeef","run_id":"42"},
	  "session": {
	    "mode": "block",
	    "exit_code": 0,
	    "connections": [
	      {"pid":1,"comm":"git","daddr":"140.82.121.4","dport":443,"proto":"tcp","domain":"github.com"},
	      {"pid":2,"comm":"curl","daddr":"8.8.8.8","dport":53,"proto":"udp"}
	    ],
	    "violations": [
	      {"kind":"connection","reason":"raw-ip egress","detail":"8.8.8.8","blocked":true}
	    ]
	  }
	}`

	var env Envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %d", env.SchemaVersion)
	}
	if env.Run.Repository != "NX1X/Egret" {
		t.Errorf("repository = %q", env.Run.Repository)
	}
	if env.Session == nil || len(env.Session.Connections) != 2 {
		t.Fatalf("session not parsed: %+v", env.Session)
	}
	if len(env.Session.Violations) != 1 || !env.Session.Violations[0].Blocked {
		t.Errorf("violations = %+v", env.Session.Violations)
	}

	// Re-marshal keeps the wire keys.
	b, _ := json.Marshal(env)
	var back map[string]any
	json.Unmarshal(b, &back)
	if _, ok := back["schema_version"]; !ok {
		t.Errorf("schema_version key lost: %s", b)
	}
}

func TestEndpoint(t *testing.T) {
	if got := (Connection{Domain: "github.com", Daddr: "1.1.1.1"}).Endpoint(); got != "github.com" {
		t.Errorf("Endpoint with domain = %q, want github.com", got)
	}
	if got := (Connection{Daddr: "8.8.8.8"}).Endpoint(); got != "8.8.8.8" {
		t.Errorf("Endpoint without domain = %q, want 8.8.8.8", got)
	}
}
