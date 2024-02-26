// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package config

import (
	"os"
	"testing"
)

type MyConfig struct {
	IamString         string
	IamRequiredString string
	IamUint64         uint64
	IamInt32          int32
}

var (
	cfg        = MyConfig{}
	cm  CfgMap = CfgMap{
		"STRING": Config{
			Value:        &cfg.IamString,
			DefaultValue: "default",
			Help:         "helpstring",
			Print:        PrintAll,
		},
		"UINT64": Config{
			Value:        &cfg.IamUint64,
			DefaultValue: uint64(1234),
			Help:         "helpuint64",
			Print:        PrintAll,
		},
		"INT32": Config{
			Value:        &cfg.IamInt32,
			DefaultValue: int32(4321),
			Help:         "helpint32",
			Print:        PrintAll,
		},
	}
)

func TestConfigTypesDefault(t *testing.T) {
	err := Parse(cm)
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfigTypesRequired(t *testing.T) {
	cmr := make(CfgMap)
	for k, v := range cm {
		v.Required = true
		cmr[k] = v
	}
	err := Parse(cmr)
	if err == nil {
		t.Fatal("expected failure, got nil")
	}

	// Set env
	for k, v := range cmr {
		switch v.DefaultValue.(type) {
		case string:
			if err := os.Setenv(k, "ENVSTRING"); err != nil {
				t.Fatal(err)
			}

		case int32, uint64:
			if err := os.Setenv(k, "31337"); err != nil {
				t.Fatal(err)
			}
		}
		v.Required = true
		cmr[k] = v
	}
	err = Parse(cmr)
	if err != nil {
		t.Fatal(err)
	}
}
