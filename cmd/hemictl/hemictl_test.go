// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"reflect"
	"testing"
)

type fakeAPICmd struct {
	ID     int    `json:"id"`
	Name   string `json:"name,omitempty"`
	Hidden string `json:"-"`
	NoTag  bool
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantAction string
		wantParsed map[string]string
		wantErr    bool
	}{
		{
			name:       "action only",
			args:       []string{"list"},
			wantAction: "list",
			wantParsed: map[string]string{},
		},
		{
			name:       "action with args",
			args:       []string{"add", "hvm=localhost:1234", "hproxy=localhost:9999"},
			wantAction: "add",
			wantParsed: map[string]string{"hvm": "localhost:1234", "hproxy": "localhost:9999"},
		},
		{
			name:    "no args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "missing equals",
			args:    []string{"list", "hvm"},
			wantErr: true,
		},
		{
			name:    "empty key",
			args:    []string{"list", "=value"},
			wantErr: true,
		},
		{
			name:    "empty value",
			args:    []string{"list", "key="},
			wantErr: true,
		},
		{
			name:    "multiple equals",
			args:    []string{"list", "key=a=b"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, parsed, err := parseArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if action != tt.wantAction {
				t.Errorf("got action %q, wanted %q", action, tt.wantAction)
			}
			if !reflect.DeepEqual(parsed, tt.wantParsed) {
				t.Errorf("got parsed %v, want %v", parsed, tt.wantParsed)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	spec := map[string]argument{
		"required":    {required: true},
		"withDefault": {defaultValue: "fallback"},
		"plain":       {},
	}

	tests := []struct {
		name     string
		provided map[string]string
		want     map[string]string
	}{
		{
			name:     "fills missing default",
			provided: map[string]string{},
			want:     map[string]string{"withDefault": "fallback"},
		},
		{
			name:     "does not override provided value",
			provided: map[string]string{"withDefault": "explicit"},
			want:     map[string]string{"withDefault": "explicit"},
		},
		{
			name:     "leaves args without defaults untouched",
			provided: map[string]string{"required": "set"},
			want:     map[string]string{"required": "set", "withDefault": "fallback"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyDefaults(spec, tt.provided)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateArgs(t *testing.T) {
	tests := []struct {
		name      string
		spec      map[string]argument
		effective map[string]string
		wantErr   bool
	}{
		{
			name: "ungrouped required present",
			spec: map[string]argument{
				"hash": {required: true},
			},
			effective: map[string]string{"hash": "abc"},
		},
		{
			name: "ungrouped required missing",
			spec: map[string]argument{
				"hash": {required: true},
			},
			effective: map[string]string{},
			wantErr:   true,
		},
		{
			name: "ungrouped optional missing",
			spec: map[string]argument{
				"count": {},
			},
			effective: map[string]string{},
		},
		{
			name: "required group with exactly one set",
			spec: map[string]argument{
				"hash":    {required: true, order: 1},
				"address": {required: true, order: 1},
			},
			effective: map[string]string{"hash": "abc"},
		},
		{
			name: "required group with none set",
			spec: map[string]argument{
				"hash":    {required: true, order: 1},
				"address": {required: true, order: 1},
			},
			effective: map[string]string{},
			wantErr:   true,
		},
		{
			name: "required group with both set",
			spec: map[string]argument{
				"hash":    {required: true, order: 1},
				"address": {required: true, order: 1},
			},
			effective: map[string]string{"hash": "abc", "address": "1Addr"},
			wantErr:   true,
		},
		{
			name: "optional group with none set",
			spec: map[string]argument{
				"foo": {order: 1},
				"bar": {order: 1},
			},
			effective: map[string]string{},
		},
		{
			name: "optional group with both set",
			spec: map[string]argument{
				"foo": {order: 1},
				"bar": {order: 1},
			},
			effective: map[string]string{"foo": "1", "bar": "2"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateArgs(tt.spec, tt.effective)
			if tt.wantErr && err == nil {
				t.Fatal("wanted error")
			}
			if !tt.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestArgsFromType(t *testing.T) {
	got := argsFromType(reflect.TypeFor[fakeAPICmd]())

	want := map[string]argument{
		"id":    {help: "int"},
		"name":  {help: "string"},
		"notag": {help: "bool"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, wanted %v", got, want)
	}
}

func TestPayloadFromMap(t *testing.T) {
	cmdType := reflect.TypeFor[fakeAPICmd]()

	t.Run("builds typed payload", func(t *testing.T) {
		args := map[string]string{
			"id":   "42",
			"name": `"hello"`,
		}
		got, err := payloadFromMap(cmdType, args)
		if err != nil {
			t.Fatal(err)
		}
		want := &fakeAPICmd{ID: 42, Name: "hello"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, wanted %v", got, want)
		}
	})

	t.Run("no args returns zero value", func(t *testing.T) {
		got, err := payloadFromMap(cmdType, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := &fakeAPICmd{}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, wanted %v", got, want)
		}
	})

	t.Run("invalid value returns error", func(t *testing.T) {
		args := map[string]string{"name": "unquoted string"}
		if _, err := payloadFromMap(cmdType, args); err == nil {
			t.Fatal("expected error")
		}
	})
}
