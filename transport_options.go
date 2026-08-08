package repost

import (
	"context"
	"crypto/tls"
	"net/netip"
	"net/url"
	"slices"
	"time"
)

// ClientCertificate configures the certificate chain and private key used
// for mutual TLS. KeyPEM may contain an encrypted PKCS #8 private key; legacy
// RFC 1423 encrypted PEM blocks are rejected.
type ClientCertificate struct {
	CertificatePEM string
	KeyPEM         string
	Passphrase     string
}

// TLSOptions configures trust, protocol versions, ciphers, and mutual TLS.
// When CACertificatesPEM is non-nil, those certificates replace system trust.
type TLSOptions struct {
	CACertificatesPEM []string
	MinVersion        uint16
	MaxVersion        uint16
	Ciphers           []uint16
	ClientCertificate *ClientCertificate
}

// ProxyCredentials are requested only after an HTTP CONNECT 407 challenge.
type ProxyCredentials struct {
	Username string
	Password string
}

// ProxyOptions configures one explicit HTTP CONNECT proxy.
type ProxyOptions struct {
	URL                 string
	CredentialsProvider func(context.Context) (ProxyCredentials, error)
}

// DNSResolver resolves one host for each new connection. Results are not
// cached by the SDK.
type DNSResolver func(context.Context, string) ([]netip.Addr, error)

// HTTPTransportOptions configures the built-in raw transport. Referenced
// callbacks are borrowed; all slices and value structs are snapshotted.
type HTTPTransportOptions struct {
	TLS         *TLSOptions
	Proxy       *ProxyOptions
	DNSResolver DNSResolver
	HTTP2       *bool

	MaxConnectionsPerOrigin *int
	ConnectionLifetime      *time.Duration
	ConnectionIdleTimeout   *time.Duration
}

const (
	defaultMaxConnectionsPerOrigin = 32
	defaultConnectionLifetime      = 5 * time.Minute
	defaultConnectionIdleTimeout   = 2 * time.Minute
)

func supportedTLSVersion(version uint16) bool {
	return version == 0 || version == tls.VersionTLS12 || version == tls.VersionTLS13
}

func snapshotHTTPTransportOptions(input HTTPTransportOptions) (HTTPTransportOptions, *Error) {
	result := HTTPTransportOptions{
		DNSResolver: input.DNSResolver,
	}
	http2 := true
	if input.HTTP2 != nil {
		http2 = *input.HTTP2
	}
	result.HTTP2 = &http2
	maxConnections := defaultMaxConnectionsPerOrigin
	if input.MaxConnectionsPerOrigin != nil {
		maxConnections = *input.MaxConnectionsPerOrigin
	}
	if maxConnections < 1 || maxConnections > 65_536 {
		return HTTPTransportOptions{}, invalidHTTPTransportOptions(ConfigurationIssueCodeOutOfRange)
	}
	result.MaxConnectionsPerOrigin = &maxConnections
	connectionLifetime := defaultConnectionLifetime
	if input.ConnectionLifetime != nil {
		connectionLifetime = *input.ConnectionLifetime
	}
	if !validConfiguredDuration(connectionLifetime) {
		return HTTPTransportOptions{}, invalidHTTPTransportOptions(ConfigurationIssueCodeOutOfRange)
	}
	result.ConnectionLifetime = &connectionLifetime
	idleTimeout := defaultConnectionIdleTimeout
	if input.ConnectionIdleTimeout != nil {
		idleTimeout = *input.ConnectionIdleTimeout
	}
	if !validConfiguredDuration(idleTimeout) {
		return HTTPTransportOptions{}, invalidHTTPTransportOptions(ConfigurationIssueCodeOutOfRange)
	}
	result.ConnectionIdleTimeout = &idleTimeout

	if input.TLS != nil {
		copied := *input.TLS
		if copied.MinVersion == 0 {
			copied.MinVersion = tls.VersionTLS12
		}
		if !supportedTLSVersion(copied.MinVersion) || !supportedTLSVersion(copied.MaxVersion) ||
			copied.MaxVersion != 0 && copied.MinVersion > copied.MaxVersion {
			return HTTPTransportOptions{}, invalidHTTPTransportOptions(ConfigurationIssueCodeUnsupported)
		}
		if copied.CACertificatesPEM != nil && len(copied.CACertificatesPEM) == 0 {
			return HTTPTransportOptions{}, invalidHTTPTransportOptions(ConfigurationIssueCodeInvalidValue)
		}
		copied.CACertificatesPEM = slices.Clone(copied.CACertificatesPEM)
		copied.Ciphers = slices.Clone(copied.Ciphers)
		if copied.ClientCertificate != nil {
			certificate := *copied.ClientCertificate
			if certificate.CertificatePEM == "" || certificate.KeyPEM == "" {
				return HTTPTransportOptions{}, invalidHTTPTransportOptions(ConfigurationIssueCodeInvalidValue)
			}
			copied.ClientCertificate = &certificate
		}
		result.TLS = &copied
	}
	if input.Proxy != nil {
		copied := *input.Proxy
		parsed, parseErr := url.Parse(copied.URL)
		if parseErr != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil ||
			parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return HTTPTransportOptions{}, invalidHTTPTransportOptions(ConfigurationIssueCodeInvalidValue)
		}
		result.Proxy = &copied
	}
	return result, nil
}

func validConfiguredDuration(value time.Duration) bool {
	return value > 0 && value <= maximumConfiguredDuration && value%time.Millisecond == 0
}

func invalidHTTPTransportOptions(code ConfigurationIssueCode) *Error {
	return configurationError(code, ClientOptionKeyHTTPTransportOptions)
}
