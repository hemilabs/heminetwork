// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package version

import "testing"

func TestCreateUserAgent(t *testing.T) {
	tests := []struct {
		name     string
		product  string
		version  string
		comments []string
		want     string
	}{
		{
			name:     "empty comment",
			version:  "0.0.0",
			comments: []string{"test", ""},
			want:     "heminetwork/0.0.0 (test)",
		},
		{
			name:    "empty version",
			product: "test",
			version: "",
			want:    "test",
		},
		{
			name:     "two empty comments",
			product:  "test",
			version:  "0.0.0",
			comments: []string{"", ""},
			want:     "test/0.0.0",
		},
		{
			name:     "test comment",
			product:  "bfgd",
			version:  "1.0.0",
			comments: []string{"test"},
			want:     "bfgd/1.0.0 (test)",
		},
		{
			name:     "empty comments with one test comment",
			product:  "bssd",
			version:  "1.0.0",
			comments: []string{"", "test", ""},
			want:     "bssd/1.0.0 (test)",
		},
		{
			name:     "whitespace comments with one test comment",
			product:  "bssd",
			version:  "1.0.0",
			comments: []string{" ", "test", " "},
			want:     "bssd/1.0.0 (test)",
		},
		{
			name:     "realistic",
			product:  "popmd",
			version:  "0.1.0",
			comments: []string{"Hemi Labs", "linux/amd64", "+https://github.com/hemilabs/heminetwork"},
			want:     "popmd/0.1.0 (Hemi Labs; linux/amd64; +https://github.com/hemilabs/heminetwork)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createUserAgent(tt.product, tt.version, tt.comments...); got != tt.want {
				t.Errorf("createUserAgent(%q, %q, %q) = %v, want %v",
					tt.product, tt.version, tt.comments, got, tt.want)
			}
		})
	}
}
