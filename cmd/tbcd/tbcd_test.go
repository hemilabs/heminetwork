// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"testing"
	"time"
)

func TestParseRequestTimeout(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{
			name:  "duration with seconds",
			input: "120s",
			want:  120 * time.Second,
		},
		{
			name:  "duration with minutes",
			input: "2m",
			want:  2 * time.Minute,
		},
		{
			name:  "duration mixed",
			input: "1m30s",
			want:  90 * time.Second,
		},
		{
			name:  "bare integer backward compat",
			input: "120",
			want:  120 * time.Second,
		},
		{
			name:  "bare integer one",
			input: "1",
			want:  1 * time.Second,
		},
		{
			name:    "zero duration",
			input:   "0s",
			wantErr: true,
		},
		{
			name:    "negative duration",
			input:   "-5s",
			wantErr: true,
		},
		{
			name:    "zero bare integer",
			input:   "0",
			wantErr: true,
		},
		{
			name:    "negative bare integer",
			input:   "-10",
			wantErr: true,
		},
		{
			name:    "garbage",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "bare integer overflow",
			input:   "18446744074",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRequestTimeout(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseRequestTimeout(%q) = %v, want error",
						tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRequestTimeout(%q) error: %v",
					tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parseRequestTimeout(%q) = %v, want %v",
					tt.input, got, tt.want)
			}
		})
	}
}
