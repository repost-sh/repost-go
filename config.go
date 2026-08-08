package repost

import (
	"context"
	cryptorand "crypto/rand"
	"math/big"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/repost-sh/repost-go/internal/cuid2"
)

const (
	defaultConnectTimeout        = 10 * time.Second
	defaultAttemptTimeout        = 30 * time.Second
	defaultOperationTimeout      = 120 * time.Second
	defaultMaxAttempts           = 4
	defaultRetryBaseDelay        = 250 * time.Millisecond
	defaultRetryMaxDelay         = 60 * time.Second
	defaultMaxInFlightOperations = 256
	defaultMaxBufferedBytes      = int64(67_108_864)
	maximumConfiguredDuration    = time.Duration(9_223_372_036_854) * time.Millisecond
)

var tlsVerificationClock = time.Now

// runtimeConfig is the construction-time snapshot consumed by the runtime.
type runtimeConfig struct {
	endpoint string

	apiKeyProvider func(context.Context) (string, error)
	apiKey         string

	httpTransportOptions HTTPTransportOptions
	transport            Transport
	generators           Generators

	connectTimeout        time.Duration
	attemptTimeout        time.Duration
	operationTimeout      time.Duration
	maxAttempts           int
	retryBaseDelay        time.Duration
	retryMaxDelay         time.Duration
	maxInFlightOperations int
	maxBufferedBytes      int64

	idempotencyKeyGenerator func() (string, error)
	retryEntropy            RetryEntropy
	monotonicClock          func() int64
	wallClock               func() time.Time
	scheduler               Scheduler
	observer                Observer
	telemetry               Telemetry
	userAgentSuffix         string
}

// snapshotConfig validates and copies options and environment fallbacks once.
func snapshotConfig(options *ClientOptions) (*runtimeConfig, *Error) {
	fixedAPIKeyPresent := options.APIKey != "" || options.apiKeySet
	if fixedAPIKeyPresent && options.APIKeyProvider != nil {
		return nil, configurationError(ConfigurationIssueCodeConflict, ClientOptionKeyAPIKey, ClientOptionKeyAPIKeyProvider)
	}
	if options.Transport != nil && options.HTTPTransportOptions != nil {
		return nil, configurationError(ConfigurationIssueCodeConflict, ClientOptionKeyHTTPTransportOptions, ClientOptionKeyTransport)
	}

	config := &runtimeConfig{
		apiKeyProvider:        options.APIKeyProvider,
		transport:             options.Transport,
		generators:            options.Generators.withDefaults(),
		connectTimeout:        defaultConnectTimeout,
		attemptTimeout:        defaultAttemptTimeout,
		operationTimeout:      defaultOperationTimeout,
		maxAttempts:           defaultMaxAttempts,
		retryBaseDelay:        defaultRetryBaseDelay,
		retryMaxDelay:         defaultRetryMaxDelay,
		maxInFlightOperations: defaultMaxInFlightOperations,
		maxBufferedBytes:      defaultMaxBufferedBytes,
		observer:              options.Observer,
		telemetry:             options.Telemetry,
	}

	httpOptions := HTTPTransportOptions{}
	if options.HTTPTransportOptions != nil {
		httpOptions = *options.HTTPTransportOptions
	}
	var httpOptionsErr *Error
	config.httpTransportOptions, httpOptionsErr = snapshotHTTPTransportOptions(httpOptions)
	if httpOptionsErr != nil {
		return nil, httpOptionsErr
	}

	if options.APIKeyProvider == nil {
		apiKeyPresent := fixedAPIKeyPresent
		config.apiKey = options.APIKey
		if !apiKeyPresent {
			apiKeyPresent = lookupCredential("REPOST_SEND_API_KEY", &config.apiKey)
		}
		if !apiKeyPresent {
			apiKeyPresent = lookupCredential("REPOST_TOKEN", &config.apiKey)
		}
		if apiKeyPresent && !validCredential(config.apiKey) {
			return nil, configurationError(ConfigurationIssueCodeInvalidValue, ClientOptionKeyAPIKey)
		}
	}

	baseURI := options.APIURL
	if baseURI == "" {
		if value, present := os.LookupEnv("REPOST_API_URL"); present {
			baseURI = value
		} else {
			baseURI = defaultAPIURL
		}
	}
	if issue := baseURIPortIssue(baseURI); issue != "" {
		return nil, configurationError(issue, ClientOptionKeyBaseURI)
	}
	endpoint, ok := canonicalEndpoint(baseURI)
	if !ok {
		return nil, configurationError(ConfigurationIssueCodeInvalidValue, ClientOptionKeyBaseURI)
	}
	config.endpoint = endpoint

	if err := resolveDuration(options.ConnectTimeout, &config.connectTimeout, ClientOptionKeyConnectTimeout); err != nil {
		return nil, err
	}
	if err := resolveDuration(options.AttemptTimeout, &config.attemptTimeout, ClientOptionKeyAttemptTimeout); err != nil {
		return nil, err
	}
	if err := resolveDuration(options.OperationTimeout, &config.operationTimeout, ClientOptionKeyOperationTimeout); err != nil {
		return nil, err
	}
	if err := resolveInt(options.MaxAttempts, &config.maxAttempts, 1, 10, ClientOptionKeyMaxAttempts); err != nil {
		return nil, err
	}
	if err := resolveDuration(options.RetryBaseDelay, &config.retryBaseDelay, ClientOptionKeyRetryBaseDelay); err != nil {
		return nil, err
	}
	if err := resolveDuration(options.RetryMaxDelay, &config.retryMaxDelay, ClientOptionKeyRetryMaxDelay); err != nil {
		return nil, err
	}
	if options.RetryBaseDelay != nil && options.RetryMaxDelay != nil && config.retryBaseDelay > config.retryMaxDelay {
		return nil, configurationError(ConfigurationIssueCodeConflict, ClientOptionKeyRetryBaseDelay, ClientOptionKeyRetryMaxDelay)
	}
	if err := resolveInt(options.MaxInFlightOperations, &config.maxInFlightOperations, 1, 65_536, ClientOptionKeyMaxInFlightOperations); err != nil {
		return nil, err
	}
	if options.MaxBufferedBytes != nil {
		if *options.MaxBufferedBytes < 4_194_304 || *options.MaxBufferedBytes > 1_073_741_824 {
			return nil, configurationError(ConfigurationIssueCodeOutOfRange, ClientOptionKeyMaxBufferedBytes)
		}
		config.maxBufferedBytes = *options.MaxBufferedBytes
	}
	if options.UserAgentSuffix != nil {
		if !validUserAgentSuffix(*options.UserAgentSuffix) {
			return nil, configurationError(ConfigurationIssueCodeInvalidValue, ClientOptionKeyUserAgentSuffix)
		}
		config.userAgentSuffix = *options.UserAgentSuffix
	}

	config.idempotencyKeyGenerator = options.IdempotencyKeyGenerator
	if config.idempotencyKeyGenerator == nil {
		config.idempotencyKeyGenerator = func() (string, error) { return cuid2.New(), nil }
	}
	config.retryEntropy = options.RetryEntropy
	if config.retryEntropy == nil {
		config.retryEntropy = cryptoRetryEntropy{}
	}
	config.monotonicClock = options.MonotonicClock
	if config.monotonicClock == nil {
		started := time.Now()
		config.monotonicClock = func() int64 { return time.Since(started).Nanoseconds() }
	}
	config.wallClock = options.WallClock
	if config.wallClock == nil {
		config.wallClock = time.Now
	}
	config.scheduler = options.Scheduler
	if config.scheduler == nil {
		config.scheduler = timerScheduler{}
	}
	return config, nil
}

func baseURIPortIssue(raw string) ConfigurationIssueCode {
	var authority string
	switch {
	case strings.HasPrefix(raw, "https://"):
		authority = raw[len("https://"):]
	case strings.HasPrefix(raw, "http://"):
		authority = raw[len("http://"):]
	default:
		return ""
	}
	if slash := strings.IndexByte(authority, '/'); slash >= 0 {
		authority = authority[:slash]
	}
	if strings.Contains(authority, "@") {
		return ""
	}

	var port string
	portPresent := false
	if strings.HasPrefix(authority, "[") {
		closingBracket := strings.IndexByte(authority, ']')
		if closingBracket < 0 {
			return ""
		}
		rest := authority[closingBracket+1:]
		if strings.HasPrefix(rest, ":") {
			port, portPresent = rest[1:], true
		}
	} else if strings.Count(authority, ":") == 1 {
		_, port, portPresent = strings.Cut(authority, ":")
	}
	if !portPresent {
		return ""
	}
	if port == "" || port[0] == '+' || len(port) > 1 && port[0] == '0' {
		return ConfigurationIssueCodeInvalidValue
	}
	digits := port
	if port[0] == '-' {
		digits = port[1:]
		if digits == "" {
			return ConfigurationIssueCodeInvalidValue
		}
	}
	for i := range digits {
		if digits[i] < '0' || digits[i] > '9' {
			return ConfigurationIssueCodeInvalidValue
		}
	}
	parsed, err := strconv.ParseUint(digits, 10, 16)
	if err != nil || port[0] == '-' || parsed < 1 || parsed > 65535 {
		return ConfigurationIssueCodeOutOfRange
	}
	return ""
}

func lookupCredential(name string, value *string) bool {
	var present bool
	*value, present = os.LookupEnv(name)
	return present
}

func configurationError(code ConfigurationIssueCode, keys ...ClientOptionKey) *Error {
	return &Error{
		Code:          ErrorCodeConfiguration,
		DeliveryState: DeliveryStateNotSent,
		IssueCount:    1,
		ConfigurationIssues: []ConfigurationIssue{{
			Code:       code,
			OptionKeys: append([]ClientOptionKey(nil), keys...),
		}},
	}
}

func resolveDuration(option, target *time.Duration, key ClientOptionKey) *Error {
	if option == nil {
		return nil
	}
	if !validConfiguredDuration(*option) {
		return configurationError(ConfigurationIssueCodeOutOfRange, key)
	}
	*target = *option
	return nil
}

func resolveInt(option, target *int, minimum, maximum int, key ClientOptionKey) *Error {
	if option == nil {
		return nil
	}
	if *option < minimum || *option > maximum {
		return configurationError(ConfigurationIssueCodeOutOfRange, key)
	}
	*target = *option
	return nil
}

func validCredential(value string) bool {
	if value == "" || len(value) > 4096 {
		return false
	}
	nonSpace := false
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
		nonSpace = nonSpace || value[i] != ' '
	}
	return nonSpace
}

func validUserAgentSuffix(value string) bool {
	if value == "" || len(value) > 256 || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func canonicalEndpoint(raw string) (string, bool) {
	if raw == "" || len(raw) > 2048 || !printableASCII(raw) || strings.ContainsAny(raw, "\\?#") {
		return "", false
	}
	if !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.String() != raw || u.Opaque != "" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	if len(u.Host) > 512 {
		return "", false
	}
	host, port, bracketed, portPresent, ok := splitAuthority(u.Host)
	if !ok || !validPort(port, portPresent) || !validHost(u.Scheme, host, bracketed) {
		return "", false
	}
	path := u.EscapedPath()
	if len(path) > 1536 || !validBasePath(path) {
		return "", false
	}

	trimmedPath := strings.TrimRight(path, "/")
	if !strings.HasSuffix(trimmedPath, "/v1/messages") {
		trimmedPath += "/v1/messages"
	}
	if trimmedPath == "" {
		trimmedPath = "/v1/messages"
	}
	endpoint := u.Scheme + "://" + u.Host + trimmedPath
	if len(trimmedPath) > 2048 || len(endpoint) > 4096 {
		return "", false
	}
	return endpoint, true
}

func printableASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func splitAuthority(authority string) (host, port string, bracketed, portPresent, valid bool) {
	if strings.HasPrefix(authority, "[") {
		closingBracket := strings.IndexByte(authority, ']')
		if closingBracket < 0 {
			return "", "", false, false, false
		}
		host = authority[1:closingBracket]
		rest := authority[closingBracket+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", "", false, false, false
			}
			port = rest[1:]
			portPresent = true
		}
		return host, port, true, portPresent, host != ""
	}
	if strings.Count(authority, ":") > 1 {
		return "", "", false, false, false
	}
	host, port, portPresent = strings.Cut(authority, ":")
	return host, port, false, portPresent, host != ""
}

func validPort(port string, present bool) bool {
	if !present {
		return true
	}
	if port == "" {
		return false
	}
	if len(port) > 1 && port[0] == '0' {
		return false
	}
	for i := range port {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

func validHost(scheme, host string, bracketed bool) bool {
	if bracketed {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() || address.Is4In6() || address.Zone() != "" || address.String() != host {
			return false
		}
		if scheme == "http" {
			return host == "::1"
		}
		return true
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.Is4() || address.String() != host {
			return false
		}
		return scheme == "https" || address.As4()[0] == 127
	}
	if scheme == "http" {
		return host == "localhost"
	}
	if strings.Trim(host, "0123456789.") == "" {
		return false
	}
	return validDNSName(host)
}

func validDNSName(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			b := label[i]
			if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '-' {
				return false
			}
		}
	}
	return true
}

func validBasePath(path string) bool {
	if path != "" && path[0] != '/' {
		return false
	}
	for i := 0; i < len(path); i++ {
		b := path[i]
		if b == '/' || isPChar(b) {
			continue
		}
		if b != '%' || i+2 >= len(path) || !upperHex(path[i+1]) || !upperHex(path[i+2]) {
			return false
		}
		decoded := unhex(path[i+1])<<4 | unhex(path[i+2])
		if decoded == '/' || decoded == '\\' {
			return false
		}
		i += 2
	}
	for _, segment := range strings.Split(path, "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "." || decoded == ".." {
			return false
		}
	}
	return true
}

func isPChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		strings.ContainsRune("-._~!$&'()*+,;=:@", rune(b))
}

func upperHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'F'
}

func unhex(b byte) byte {
	if b <= '9' {
		return b - '0'
	}
	return b - 'A' + 10
}

type cryptoRetryEntropy struct{}

func (cryptoRetryEntropy) NextInt64(exclusiveBound int64) int64 {
	value, err := cryptorand.Int(cryptorand.Reader, big.NewInt(exclusiveBound))
	if err != nil {
		panic(err)
	}
	return value.Int64()
}

type timerScheduler struct{}

func (timerScheduler) Sleep(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
