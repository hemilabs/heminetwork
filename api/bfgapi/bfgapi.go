// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfgapi

import (
	"fmt"
)

const (
	APIVersion = 1
)

var (
	APIVersionRoute         = fmt.Sprintf("v%d", APIVersion)
	DefaultListenAddress    = "localhost:8080"
	DefaultPrometheusListen = "localhost:2112"

	RouteKeystoneFinality = "GET /" + APIVersionRoute + "/" + "keystonefinality/{hash...}"
)
