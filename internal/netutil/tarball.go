package netutil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type TarballDownloadConfig struct {
	AllowPrivateHosts bool
	MaxRedirects      int
	Timeout           time.Duration
	MaxSize           int64
}

const DefaultMaxTarballSize = 500 * 1024 * 1024

func DefaultConfig() TarballDownloadConfig {
	return TarballDownloadConfig{
		AllowPrivateHosts: false,
		MaxRedirects:      5,
		Timeout:           60 * time.Second,
		MaxSize:           DefaultMaxTarballSize,
	}
}

type TarballDownloadResult struct {
	Path    string
	SHA256  string
	Size    int64
	Cleanup func()
}

func DownloadTarball(ctx context.Context, tarballURL string, config TarballDownloadConfig) (*TarballDownloadResult, error) {
	if err := ValidateTarballURL(tarballURL, config.AllowPrivateHosts); err != nil {
		return nil, fmt.Errorf("invalid tarball URL: %w", err)
	}

	client := createSecureClient(config)

	return downloadWithSHA256(ctx, client, tarballURL, config.MaxSize)
}

func ValidateTarballURL(rawURL string, allowPrivate bool) error {
	if rawURL == "" {
		return fmt.Errorf("empty URL")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}

	// SECURITY: Only allow https:// scheme
	if parsed.Scheme != "https" {
		return fmt.Errorf("only https:// URLs allowed for tarball downloads; got %q", parsed.Scheme)
	}

	// SECURITY: Block private/reserved IPs (unless explicitly allowed)
	if !allowPrivate {
		host := strings.ToLower(parsed.Hostname())
		if err := validateHostNotPrivate(host); err != nil {
			return fmt.Errorf("%w (use --unsafe-allow-private-tarball-hosts to override)", err)
		}
	}

	return nil
}

func validateHostNotPrivate(host string) error {
	if host == "localhost" {
		return fmt.Errorf("localhost not allowed")
	}

	ip := net.ParseIP(host)
	if ip != nil && IsPrivateOrReservedIP(ip) {
		return fmt.Errorf("private/reserved IP address not allowed: %s", host)
	}

	return nil
}

func IsPrivateOrReservedIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}

	if ip.IsPrivate() {
		return true
	}

	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	if ip.IsUnspecified() {
		return true
	}

	if ip.IsMulticast() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0 {
			return true
		}
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
			return true
		}
		if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
			return true
		}
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return true
		}
		if ip4[0] >= 240 {
			return true
		}
		if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 {
			return true
		}
	}

	return false
}

func createSecureClient(config TarballDownloadConfig) *http.Client {
	var dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
	if config.AllowPrivateHosts {
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		dialCtx = dialer.DialContext
	} else {
		dialCtx = safeDialContext
	}

	maxRedirects := config.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = 5
	}

	redirectCount := 0

	return &http.Client{
		Timeout: config.Timeout,
		// SECURITY: Validate each redirect target
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirectCount++
			if redirectCount > maxRedirects {
				return fmt.Errorf("too many redirects (%d)", redirectCount)
			}

			if err := ValidateTarballURL(req.URL.String(), config.AllowPrivateHosts); err != nil {
				return fmt.Errorf("redirect to insecure URL blocked: %w", err)
			}

			if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme == "http" {
				return fmt.Errorf("HTTPS to HTTP downgrade not allowed")
			}

			return nil
		},
		Transport: &http.Transport{
			// SECURITY: Validate resolved IPs at connect time
			DialContext: dialCtx,
			// SECURITY: Disable proxy to prevent SSRF via proxy
			Proxy: nil,
		},
	}
}

func NewSecureAPIClient(timeout time.Duration, allowPrivateHosts bool) *http.Client {
	var dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
	if allowPrivateHosts {
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		dialCtx = dialer.DialContext
	} else {
		dialCtx = safeDialContext
	}

	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			// SECURITY: Validate resolved IPs at connect time
			DialContext: dialCtx,
			// SECURITY: Disable proxy to prevent SSRF via proxy
			Proxy: nil,
		},
	}
}

func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", host)
	}

	// SECURITY: Collect only safe (non-private/reserved) IPs
	var safeIPs []net.IP
	for _, ip := range ips {
		if IsPrivateOrReservedIP(ip) {
			return nil, fmt.Errorf("DNS resolved to private/reserved IP address (%s -> %s); connection blocked", host, ip.String())
		}
		safeIPs = append(safeIPs, ip)
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(safeIPs[0].String(), port))
}

func downloadWithSHA256(ctx context.Context, client *http.Client, tarballURL string, maxSize int64) (*TarballDownloadResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", tarballURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "mcptrust-tarball-*.tgz")
	if err != nil {
		return nil, err
	}

	var body io.Reader = resp.Body
	if maxSize > 0 {
		body = io.LimitReader(resp.Body, maxSize+1)
	}

	h := sha256.New()
	tee := io.TeeReader(body, h)

	size, err := io.Copy(tmpFile, tee)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, err
	}
	tmpFile.Close()

	if maxSize > 0 && size > maxSize {
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("tarball exceeds maximum size limit (%d bytes > %d bytes)", size, maxSize)
	}

	return &TarballDownloadResult{
		Path:   tmpFile.Name(),
		SHA256: hex.EncodeToString(h.Sum(nil)),
		Size:   size,
		Cleanup: func() {
			os.Remove(tmpFile.Name())
		},
	}, nil
}
