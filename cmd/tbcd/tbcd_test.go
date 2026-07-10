// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import "testing"

func TestOrdinalVerifyBigOConfig(t *testing.T) {
	c, ok := cm["TBC_ORDINAL_VERIFY_BIGO"]
	if !ok {
		t.Fatal("TBC_ORDINAL_VERIFY_BIGO not registered")
	}
	if def, ok := c.DefaultValue.(bool); !ok || def {
		t.Fatalf("default must be false, got %v", c.DefaultValue)
	}
	if c.Value != any(&cfg.OrdinalVerifyBigO) {
		t.Fatal("not wired to cfg.OrdinalVerifyBigO")
	}
}

func TestOrdinalWarmConfig(t *testing.T) {
	c, ok := cm["TBC_ORDINAL_WARM"]
	if !ok {
		t.Fatal("TBC_ORDINAL_WARM not registered")
	}
	if def, ok := c.DefaultValue.(bool); !ok || !def {
		t.Fatalf("default must be true, got %v", c.DefaultValue)
	}
	if c.Value != any(&cfg.OrdinalWarm) {
		t.Fatal("not wired to cfg.OrdinalWarm")
	}
}
