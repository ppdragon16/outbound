// Package ua derives HTTP request headers from the uTLS ClientHelloID that a
// dialer impersonates.
//
// Rationale: a connection is only as consistent as its weakest layer. A
// Chrome/133 JA3 paired with a "curl/8.4.0" or default-Go User-Agent is
// trivially linkable — the TLS fingerprint claims one client while the
// cleartext HTTP layer claims another. This package keeps the two layers in
// sync so that every transport (TLS/REALITY spider, WebSocket, HTTPUpgrade,
// gRPC) emits the headers a real browser of the same family and major version
// would emit.
//
// The mapping is intentionally conservative: when a family serves a proprietary
// client whose exact UA string cannot be reproduced faithfully (QQ/360
// browsers, randomized fingerprints), we fall back to the Chromium-based UA of
// the same client family rather than inventing a string that no real client
// sends.
package ua

import (
	"fmt"
	"net/http"
	"strings"

	utls "github.com/refraction-networking/utls"
)

const (
	// defaultChromeVersion is used when the fingerprint carries no usable
	// version (randomized/custom handshakes). Chrome is the most common
	// browser on the wire, so it is the least conspicuous fallback.
	defaultChromeVersion = "133"

	chromeUAFormat  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36"
	edgeUAFormat    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36 Edg/%s.0.0.0"
	firefoxUAFormat = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%s.0) Gecko/20100101 Firefox/%s.0"
	safariUAFormat  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15"
	iosUAFormat     = "Mozilla/5.0 (iPhone; CPU iPhone OS %s like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Mobile/15E148 Safari/604.1"

	chromeAccept    = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	firefoxAccept   = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
	safariAccept    = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	acceptLanguage  = "en-US,en;q=0.9"
	okhttpUserAgent = "okhttp/4.12.0"
)

// normalizeVersion strips uTLS's variant suffixes ("100_PSK", "115_PQ") and
// returns the wire-visible major version, plus a dotted form used by the
// Safari/iOS UA strings.
func normalizeVersion(version string) (major string, dotted string) {
	if version == "" {
		return "", ""
	}
	if i := strings.IndexByte(version, '_'); i >= 0 {
		version = version[:i]
	}
	major = version
	if strings.Contains(version, ".") {
		return strings.SplitN(version, ".", 2)[0], version
	}
	return version, version + ".0"
}

// iosDotted renders an iOS version the way Safari reports it. uTLS encodes
// iOS 11.1 as the legacy "111", and bare majors ("14") need an explicit minor.
func iosDotted(version string) string {
	if i := strings.IndexByte(version, '_'); i >= 0 {
		version = version[:i]
	}
	switch {
	case strings.Contains(version, "."):
		return version
	case len(version) == 3: // legacy "111" means 11.1
		return version[:2] + "." + version[2:]
	case version == "":
		return "14.0"
	default:
		return version + ".0"
	}
}

// UserAgent returns the User-Agent string matching the given uTLS
// ClientHelloID. A nil id yields the default Chromium UA.
func UserAgent(id *utls.ClientHelloID) string {
	if id == nil {
		return fmt.Sprintf(chromeUAFormat, defaultChromeVersion)
	}
	version, dotted := normalizeVersion(id.Version)
	if version == "" {
		version, dotted = defaultChromeVersion, defaultChromeVersion
	}
	switch strings.ToLower(id.Client) {
	case "chrome":
		return fmt.Sprintf(chromeUAFormat, version)
	case "edge":
		return fmt.Sprintf(edgeUAFormat, version, version)
	case "firefox":
		return fmt.Sprintf(firefoxUAFormat, version, version)
	case "safari":
		return fmt.Sprintf(safariUAFormat, dotted)
	case "ios":
		dotted = iosDotted(id.Version)
		return fmt.Sprintf(iosUAFormat, strings.ReplaceAll(dotted, ".", "_"), dotted)
	case "android":
		return okhttpUserAgent
	case "qq", "360":
		// Proprietary Chromium-based clients: an inexact hand-written UA is
		// worse than the Chromium UA of the same family.
		return fmt.Sprintf(chromeUAFormat, defaultChromeVersion)
	default:
		// Randomized and custom fingerprints have no faithful UA; use the
		// most common browser on the wire rather than the Go default.
		return fmt.Sprintf(chromeUAFormat, version)
	}
}

// isChromiumFamily reports whether the UA is expected to carry the
// Sec-CH-UA client hints (Chromium-based browsers do, Firefox/Safari do not).
func isChromiumFamily(id *utls.ClientHelloID) bool {
	if id == nil {
		return true
	}
	switch strings.ToLower(id.Client) {
	case "firefox", "safari", "ios":
		return false
	default:
		return true
	}
}

// Headers returns the request headers a real browser of the same family and
// version would send, so the HTTP layer matches the TLS fingerprint. The
// returned header set is deliberately narrow: only headers that are safe on a
// proxy handshake (notably no Origin/Referer, which servers may validate).
func Headers(id *utls.ClientHelloID) http.Header {
	h := http.Header{}
	h.Set("User-Agent", UserAgent(id))

	switch {
	case isChromiumFamily(id):
		h.Set("Accept", chromeAccept)
		h.Set("Accept-Language", acceptLanguage)
		h.Set("Sec-Ch-Ua", secChUa(id))
		h.Set("Sec-Ch-Ua-Mobile", "?0")
		h.Set("Sec-Ch-Ua-Platform", `"Windows"`)
		h.Set("Upgrade-Insecure-Requests", "1")
	case strings.EqualFold(clientOf(id), "firefox"):
		h.Set("Accept", firefoxAccept)
		h.Set("Accept-Language", acceptLanguage)
		h.Set("Upgrade-Insecure-Requests", "1")
	default:
		h.Set("Accept", safariAccept)
		h.Set("Accept-Language", acceptLanguage)
	}
	return h
}

func clientOf(id *utls.ClientHelloID) string {
	if id == nil {
		return "chrome"
	}
	return id.Client
}

// secChUa renders the Sec-CH-UA header for a Chromium-based fingerprint.
func secChUa(id *utls.ClientHelloID) string {
	version := ""
	if id != nil {
		version, _ = normalizeVersion(id.Version)
	}
	if version == "" {
		version = defaultChromeVersion
	}
	return fmt.Sprintf(`"Chromium";v="%s", "Not(A:Brand";v="24"`, version)
}

// ApplyTo copies the derived headers into dst without overwriting keys that
// the caller has already set (an explicit user-supplied header wins).
func ApplyTo(dst http.Header, id *utls.ClientHelloID) {
	for k, v := range Headers(id) {
		if dst.Get(k) == "" {
			dst[k] = v
		}
	}
}
