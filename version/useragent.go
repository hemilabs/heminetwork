// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package version

import (
	"runtime"
	"strings"
)

// srcUrl is the URL to the source code for this project.
const srcUrl = "https://github.com/hemilabs/heminetwork"

var (
	// Brand is an identifier that is used to identify the organisation or
	// entity that built the binary.
	//
	// Official binaries built by Hemi Labs, Inc. use the brand "Hemi Labs".
	// If you are building your own specialised version of our binaries, please
	// set this to something that uniquely identifies who you are.
	//
	// This helps us see when people are building on our work, and making their
	// own specialised versions of our packages. We cannot wait to see what you
	// are able to create!
	//
	// This should be set at link-time using:
	//
	//	-ldflags "-X 'github.com/hemilabs/heminetwork/version.Brand=my brand'"
	Brand string

	// Component is an identifier for the binary.
	//
	// This should be set in an init function in the main package:
	//
	//	func init() {
	//	    version.Component = "bfgd"
	//	}
	Component string
)

// userAgent an HTTP User-Agent header value that should be used when making
// HTTP requests.
//
// The User-Agent value contains the component name (e.g. bfgd), version, brand,
// operating system name (GOOS), system architecture, and source code URL.
var userAgent = createUserAgent(Component, String(), Brand,
	runtime.GOOS+"/"+runtime.GOARCH, "+"+srcUrl)

// UserAgent returns an HTTP User-Agent header value that should be used when
// making HTTP requests.
func UserAgent() string {
	return userAgent
}

// createUserAgent creates a RFC9110-compliant User-Agent header value.
// https://www.rfc-editor.org/rfc/rfc9110#name-user-agent
func createUserAgent(product, version string, comments ...string) string {
	if product == "" {
		product = "heminetwork"
	}

	var out strings.Builder
	out.WriteString(product)
	if version != "" {
		out.WriteRune('/')
		out.WriteString(version)
	}

	var cmts []string
	for _, comment := range comments {
		if c := strings.TrimSpace(comment); c != "" {
			cmts = append(cmts, c)
		}
	}
	if len(cmts) > 0 {
		out.WriteString(" (")
		for i, c := range cmts {
			out.WriteString(c)
			if i < len(cmts)-1 {
				out.WriteString("; ")
			}
		}
		out.WriteString(")")
	}

	return out.String()
}
