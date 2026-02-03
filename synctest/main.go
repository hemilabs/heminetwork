// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"log"

	"synctest"
)

func main() {
	if err := synctest.WaitForSync(context.Background()); err != nil {
		log.Fatalf("error syncing: %s", err)
	}
}
