package differ

import "testing"

func TestSeverityString(t *testing.T) {
	tests := []struct {
		level    SeverityLevel
		expected string
	}{
		{SeverityCritical, "critical"},
		{SeverityModerate, "moderate"},
		{SeveritySafe, "info"},
		{SeverityLevel(99), "unknown"}, // out-of-range value
		{SeverityLevel(-1), "unknown"}, // negative value
	}

	for _, tt := range tests {
		got := SeverityString(tt.level)
		if got != tt.expected {
			t.Errorf("SeverityString(%d) = %q, want %q", tt.level, got, tt.expected)
		}
	}
}
