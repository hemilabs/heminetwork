// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build continuum_debug

package main

import (
	"context"
	"strings"
	"testing"
)

func TestRequireInt(t *testing.T) {
	tests := []struct {
		name    string
		args    map[string]string
		key     string
		want    int
		wantErr string
	}{
		{"valid", map[string]string{"n": "3"}, "n", 3, ""},
		{"zero", map[string]string{"n": "0"}, "n", 0, ""},
		{"negative", map[string]string{"n": "-1"}, "n", -1, ""},
		{"missing", map[string]string{}, "n", 0, "n required"},
		{"empty", map[string]string{"n": ""}, "n", 0, "n required"},
		{"not a number", map[string]string{"n": "abc"}, "n", 0, "invalid n"},
		{"float", map[string]string{"n": "1.5"}, "n", 0, "invalid n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := requireInt(tt.args, tt.key)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRequireHex(t *testing.T) {
	tests := []struct {
		name    string
		args    map[string]string
		key     string
		wantLen int
		wantErr string
	}{
		{"valid 32 bytes", map[string]string{"h": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}, "h", 32, ""},
		{"valid 1 byte", map[string]string{"h": "ff"}, "h", 1, ""},
		{"empty value", map[string]string{"h": ""}, "h", 0, "h required"},
		{"missing key", map[string]string{}, "h", 0, "h required"},
		{"odd length", map[string]string{"h": "abc"}, "h", 0, "invalid h hex"},
		{"not hex", map[string]string{"h": "zzzz"}, "h", 0, "invalid h hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := requireHex(tt.args, tt.key)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Fatalf("got %d bytes, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestParseMembers(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantN   int
		wantErr string
	}{
		// Valid: 3 compressed secp256k1 pubkeys (33 bytes each).
		// These are syntactically valid identities (correct prefix
		// and length) but not real curve points.
		{
			"single member",
			"0000000000000000000000000000000000000001",
			1, "",
		},
		{
			"two members",
			"0000000000000000000000000000000000000001," +
				"0000000000000000000000000000000000000002",
			2, "",
		},
		{
			"trailing comma ignored",
			"0000000000000000000000000000000000000001,",
			1, "",
		},
		{
			"spaces trimmed",
			" 0000000000000000000000000000000000000001 , 0000000000000000000000000000000000000002 ",
			2, "",
		},
		{"empty string", "", 0, "empty members list"},
		{"just commas", ",,,", 0, "empty members list"},
		{"invalid hex", "zzzz", 0, "invalid identity"},
		{"too short", "02abcd", 0, "invalid identity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMembers(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantN {
				t.Fatalf("got %d identities, want %d", len(got), tt.wantN)
			}
		})
	}
}

func TestResolveCommitteePrefixExclusiveOr(t *testing.T) {
	// Both set → error.
	_, err := resolveCommitteePrefix(context.TODO(), nil, nil,
		map[string]string{"members": "x", "auto": "3"}, "")
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("expected 'not both' error, got: %v", err)
	}

	// Neither set → error.
	_, err = resolveCommitteePrefix(context.TODO(), nil, nil,
		map[string]string{}, "")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected 'required' error, got: %v", err)
	}

	// Prefixed: both set → error.
	_, err = resolveCommitteePrefix(context.TODO(), nil, nil,
		map[string]string{"old_members": "x", "old_auto": "3"}, "old_")
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("expected 'not both' error, got: %v", err)
	}

	// Prefixed: neither set → error.
	_, err = resolveCommitteePrefix(context.TODO(), nil, nil,
		map[string]string{}, "old_")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected 'required' error, got: %v", err)
	}

	// auto=0 → error.
	_, err = resolveCommitteePrefix(context.TODO(), nil, nil,
		map[string]string{"auto": "0"}, "")
	if err == nil || !strings.Contains(err.Error(), ">= 1") {
		t.Fatalf("expected '>= 1' error, got: %v", err)
	}

	// auto=abc → error.
	_, err = resolveCommitteePrefix(context.TODO(), nil, nil,
		map[string]string{"auto": "abc"}, "")
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected 'invalid' error, got: %v", err)
	}
}
