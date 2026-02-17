// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
)

func main() {
	if err := waitForSync(context.Background()); err != nil {
		panic(fmt.Sprintf("error syncing: %s", err))
	}
}
