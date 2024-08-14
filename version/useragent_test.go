package version

import "testing"

func TestCreateUserAgent(t *testing.T) {
	tests := []struct {
		product  string
		version  string
		comments []string
		want     string
	}{
		{
			version:  "0.0.0",
			comments: []string{"test", ""},
			want:     "heminetwork/0.0.0 (test)",
		},
		{
			product: "test",
			version: "",
			want:    "test",
		},
		{
			product:  "test",
			version:  "0.0.0",
			comments: []string{"", ""},
			want:     "test/0.0.0",
		},
		{
			product:  "bfgd",
			version:  "1.0.0",
			comments: []string{"test"},
			want:     "bfgd/1.0.0 (test)",
		},
		{
			product:  "bssd",
			version:  "1.0.0",
			comments: []string{"", "test", ""},
			want:     "bssd/1.0.0 (test)",
		},
		{
			product:  "bssd",
			version:  "1.0.0",
			comments: []string{" ", "test", " "},
			want:     "bssd/1.0.0 (test)",
		},
		{
			product:  "popmd",
			version:  "0.1.0",
			comments: []string{"Hemi Labs", "linux/amd64", "+https://github.com/hemilabs/heminetwork"},
			want:     "popmd/0.1.0 (Hemi Labs; linux/amd64; +https://github.com/hemilabs/heminetwork)",
		},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := createUserAgent(tt.product, tt.version, tt.comments...); got != tt.want {
				t.Errorf("createUserAgent(%q, %q, %q) = %v, want %v",
					tt.product, tt.version, tt.comments, got, tt.want)
			}
		})
	}
}
