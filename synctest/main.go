// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		// Stop receiving signals as soon as possible.
		<-ctx.Done()
		stop()
	}()

	if err := waitForSync(ctx); err != nil {
		panic(fmt.Sprintf("error syncing: %s", err))
	}
}
