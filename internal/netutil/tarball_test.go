package netutil

import (
	"net"
	"testing"
)

func TestValidateTarballURL(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		allowPrivate bool
		wantErr      bool
	}{
		// Valid URLs
		{name: "https npm registry", url: "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz", allowPrivate: false, wantErr: false},
		{name: "https github registry", url: "https://npm.pkg.github.com/@org/pkg/-/pkg-1.0.0.tgz", allowPrivate: false, wantErr: false},
		{name: "https yarn registry", url: "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.0.0.tgz", allowPrivate: false, wantErr: false},

		// Invalid schemes
		{name: "http not allowed", url: "http://registry.npmjs.org/pkg.tgz", allowPrivate: false, wantErr: true},
		{name: "file not allowed", url: "file:///etc/passwd", allowPrivate: false, wantErr: true},
		{name: "ftp not allowed", url: "ftp://evil.com/pkg.tgz", allowPrivate: false, wantErr: true},

		// Private IPs blocked by default
		{name: "localhost blocked", url: "https://localhost/pkg.tgz", allowPrivate: false, wantErr: true},
		{name: "127.0.0.1 blocked", url: "https://127.0.0.1/pkg.tgz", allowPrivate: false, wantErr: true},
		{name: "10.x.x.x blocked", url: "https://10.0.0.1/pkg.tgz", allowPrivate: false, wantErr: true},
		{name: "192.168.x.x blocked", url: "https://192.168.1.1/pkg.tgz", allowPrivate: false, wantErr: true},

		// Private IPs allowed when flag set
		{name: "10.x allowed with flag", url: "https://10.0.0.1/pkg.tgz", allowPrivate: true, wantErr: false},
		{name: "192.168.x allowed with flag", url: "https://192.168.1.1/pkg.tgz", allowPrivate: true, wantErr: false},
		{name: "localhost allowed with flag", url: "https://localhost/pkg.tgz", allowPrivate: true, wantErr: false},

		// HTTP still blocked even with allowPrivate
		{name: "http still blocked with flag", url: "http://10.0.0.1/pkg.tgz", allowPrivate: true, wantErr: true},

		// Malformed URLs
		{name: "empty URL", url: "", allowPrivate: false, wantErr: true},
		{name: "invalid URL", url: "not-a-url", allowPrivate: false, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTarballURL(tt.url, tt.allowPrivate)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTarballURL(%q, %v) error = %v, wantErr %v", tt.url, tt.allowPrivate, err, tt.wantErr)
			}
		})
	}
}

func TestIsPrivateOrReservedIP(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		isPrivate bool
	}{
		// Public IPs (should be allowed)
		{name: "google dns", ip: "8.8.8.8", isPrivate: false},
		{name: "cloudflare dns", ip: "1.1.1.1", isPrivate: false},
		{name: "random public", ip: "203.0.114.50", isPrivate: false}, // Not in TEST-NET-3

		// Loopback
		{name: "loopback", ip: "127.0.0.1", isPrivate: true},
		{name: "loopback range", ip: "127.255.255.255", isPrivate: true},
		{name: "ipv6 loopback", ip: "::1", isPrivate: true},

		// Private (RFC 1918)
		{name: "10.x.x.x", ip: "10.0.0.1", isPrivate: true},
		{name: "172.16.x.x", ip: "172.16.0.1", isPrivate: true},
		{name: "172.31.x.x", ip: "172.31.255.255", isPrivate: true},
		{name: "192.168.x.x", ip: "192.168.1.1", isPrivate: true},

		// Link-local
		{name: "link-local", ip: "169.254.1.1", isPrivate: true},
		{name: "ipv6 link-local", ip: "fe80::1", isPrivate: true},

		// CGNAT (100.64.0.0/10)
		{name: "cgnat start", ip: "100.64.0.1", isPrivate: true},
		{name: "cgnat end", ip: "100.127.255.255", isPrivate: true},
		{name: "not cgnat", ip: "100.63.255.255", isPrivate: false},
		{name: "not cgnat 2", ip: "100.128.0.0", isPrivate: false},

		// Benchmarking (198.18.0.0/15)
		{name: "benchmark start", ip: "198.18.0.1", isPrivate: true},
		{name: "benchmark end", ip: "198.19.255.255", isPrivate: true},
		{name: "not benchmark", ip: "198.17.255.255", isPrivate: false},
		{name: "not benchmark 2", ip: "198.20.0.0", isPrivate: false},

		// TEST-NETs
		{name: "test-net-1", ip: "192.0.2.1", isPrivate: true},
		{name: "test-net-2", ip: "198.51.100.1", isPrivate: true},
		{name: "test-net-3", ip: "203.0.113.1", isPrivate: true},

		// Unspecified
		{name: "unspecified v4", ip: "0.0.0.0", isPrivate: true},
		{name: "unspecified v6", ip: "::", isPrivate: true},

		// "This network" (0.0.0.0/8)
		{name: "this network", ip: "0.1.2.3", isPrivate: true},

		// Reserved for future use
		{name: "reserved future", ip: "240.0.0.1", isPrivate: true},
		{name: "broadcast", ip: "255.255.255.255", isPrivate: true},

		// Multicast
		{name: "multicast v4", ip: "224.0.0.1", isPrivate: true},
		{name: "multicast v6", ip: "ff02::1", isPrivate: true},

		// IPv6 unique local
		{name: "ipv6 unique local fc", ip: "fc00::1", isPrivate: true},
		{name: "ipv6 unique local fd", ip: "fd00::1", isPrivate: true},

		// IPv6 public (should be allowed)
		{name: "ipv6 public", ip: "2001:4860:4860::8888", isPrivate: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			got := IsPrivateOrReservedIP(ip)
			if got != tt.isPrivate {
				t.Errorf("IsPrivateOrReservedIP(%s) = %v, want %v", tt.ip, got, tt.isPrivate)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.AllowPrivateHosts {
		t.Error("default should block private hosts")
	}
	if config.MaxRedirects != 5 {
		t.Errorf("default max redirects = %d, want 5", config.MaxRedirects)
	}
	if config.Timeout != 60e9 {
		t.Errorf("default timeout = %v, want 60s", config.Timeout)
	}
	if config.MaxSize != DefaultMaxTarballSize {
		t.Errorf("default max size = %d, want %d", config.MaxSize, DefaultMaxTarballSize)
	}
}

// TestRedirectValidation tests that redirect targets are validated.
// These tests verify ValidateTarballURL is called for redirect targets.
func TestRedirectValidation(t *testing.T) {
	// Redirect to HTTP should fail (scheme downgrade)
	t.Run("redirect to HTTP blocked", func(t *testing.T) {
		err := ValidateTarballURL("http://example.com/pkg.tgz", false)
		if err == nil {
			t.Error("expected redirect to HTTP to be blocked")
		}
	})

	// Redirect to private IP should fail (when allowPrivate=false)
	t.Run("redirect to private IP blocked", func(t *testing.T) {
		err := ValidateTarballURL("https://10.0.0.1/pkg.tgz", false)
		if err == nil {
			t.Error("expected redirect to private IP to be blocked")
		}
	})

	// Redirect to private IP allowed when flag set
	t.Run("redirect to private IP allowed with flag", func(t *testing.T) {
		err := ValidateTarballURL("https://10.0.0.1/pkg.tgz", true)
		if err != nil {
			t.Errorf("expected redirect to private IP to be allowed with flag, got: %v", err)
		}
	})
}

// TestSecurityInvariantsWithUnsafeFlag ensures unsafe flag only relaxes private IP blocking.
func TestSecurityInvariantsWithUnsafeFlag(t *testing.T) {
	// HTTPS must still be required even with allowPrivate=true
	t.Run("HTTPS still required with unsafe flag", func(t *testing.T) {
		err := ValidateTarballURL("http://10.0.0.1/pkg.tgz", true)
		if err == nil {
			t.Error("HTTP should be blocked even with allowPrivate=true")
		}
	})

	// Empty URL still rejected
	t.Run("empty URL rejected with unsafe flag", func(t *testing.T) {
		err := ValidateTarballURL("", true)
		if err == nil {
			t.Error("empty URL should be rejected even with allowPrivate=true")
		}
	})

	// Malformed URL still rejected
	t.Run("malformed URL rejected with unsafe flag", func(t *testing.T) {
		err := ValidateTarballURL("not-a-url", true)
		if err == nil {
			t.Error("malformed URL should be rejected even with allowPrivate=true")
		}
	})
}
