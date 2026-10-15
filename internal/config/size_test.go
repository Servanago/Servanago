package config

import "testing"

func TestParseSize(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int64
		bad  bool
	}{
		{"2GB", 2 << 30, false},
		{"2gb", 2 << 30, false},
		{" 512 MB ", 512 << 20, false},
		{"100KB", 100 << 10, false},
		{"1048576", 1 << 20, false},
		{"100GB", 100 << 30, false},
		{"101GB", 0, true},
		{"0", 0, true},
		{"-1MB", 0, true},
		{"2XB", 0, true},
		{"GB", 0, true},
		{"1.5GB", 0, true},
		{"", 0, true},
	} {
		got, err := ParseSize(c.in)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d, bad=%v", c.in, got, err, c.want, c.bad)
		}
	}
}

func TestFormatSize(t *testing.T) {
	for in, want := range map[int64]string{0: "", 2 << 30: "2GB", 512 << 20: "512MB", 100 << 10: "100KB", 1500: "1500"} {
		if got := FormatSize(in); got != want {
			t.Errorf("FormatSize(%d) = %q, want %q", in, got, want)
		}
	}
}
