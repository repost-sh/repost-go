package repost

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/repost-sh/repost-go/internal/h1"
	"github.com/repost-sh/repost-go/internal/h2"
	"github.com/repost-sh/repost-go/internal/pool"
	"github.com/repost-sh/repost-go/internal/proxyconnect"
	"github.com/repost-sh/repost-go/internal/tlsx"
)

type rawTransport struct {
	options      HTTPTransportOptions
	connections  *pool.Pool
	proxyAddress string
	tlsConfig    *tls.Config
}

type rawEndpoint struct {
	scheme      string
	authority   string
	target      string
	dialAddress string
	serverName  string
}

type countingReader struct {
	reader io.Reader
	bytes  int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.bytes += int64(n)
	return n, err
}

type rawH1Connection struct {
	net.Conn
	reader                     *bufio.Reader
	received                   *countingReader
	clientCertificateRequested bool
}

type rawExchange struct {
	response       h1.Response
	headerSnapshot responseHeaderSnapshot
	responseBytes  int64
	requestWrote   bool
	committed      bool
	err            error
}

type responseHeaderSnapshot struct {
	at     time.Time
	set    bool
	failed bool
}

type rawTLSNegotiationError struct{}

func (*rawTLSNegotiationError) Error() string { return "raw transport: TLS negotiation failed" }

func newRawTransport(input HTTPTransportOptions) (*rawTransport, *Error) {
	options, err := snapshotHTTPTransportOptions(input)
	if err != nil {
		return nil, err
	}
	return newRawTransportFromSnapshot(options)
}

func newRawTransportFromSnapshot(options HTTPTransportOptions) (*rawTransport, *Error) {
	baseTLSConfig, tlsErr := buildRawTLSConfig(options)
	if tlsErr != nil {
		return nil, invalidHTTPTransportOptions(ConfigurationIssueCodeInvalidValue)
	}
	transport := &rawTransport{
		options: options, tlsConfig: baseTLSConfig,
		connections: pool.New(pool.Options{
			MaxConnections: *options.MaxConnectionsPerOrigin,
			Lifetime:       *options.ConnectionLifetime,
			IdleTimeout:    *options.ConnectionIdleTimeout,
		}),
	}
	if options.Proxy != nil {
		parsed, _ := url.Parse(options.Proxy.URL)
		transport.proxyAddress = addressWithDefaultPort(parsed.Hostname(), parsed.Port(), "80")
	}
	return transport, nil
}

func (t *rawTransport) Send(parent context.Context, request *AttemptRequest) AttemptOutcome {
	ctx := parent
	if request.AttemptTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, request.AttemptTimeout)
		defer cancel()
	}
	endpoint, err := parseRawEndpoint(request.APIURL)
	if err != nil {
		return rawFailure(ErrorCodeIO, FailureReasonUnknown, false)
	}
	h1Request, err := makeH1Request(&endpoint, request)
	if err != nil {
		return rawFailure(ErrorCodeIO, FailureReasonUnknown, false)
	}
	var h2Snapshot responseHeaderSnapshot
	h2Request := makeH2Request(&endpoint, &h1Request, request.CommitTracker, func(status int, headers []h2.Header) {
		h2Snapshot.capture(request, status, h2Headers(headers))
	})
	connectTimeout := request.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = defaultConnectTimeout
	}

	lease, err := t.connections.Acquire(ctx, endpoint.scheme+"://"+endpoint.authority, func(dialContext context.Context) (pool.Resource, pool.Mode, error) {
		return t.dial(dialContext, &endpoint, connectTimeout)
	})
	if err != nil {
		return dialFailure(ctx, err)
	}
	switch connection := lease.Resource().(type) {
	case *rawH1Connection:
		return t.sendH1(ctx, request, &endpoint, &h1Request, connectTimeout, lease, connection)
	case *h2.Session:
		response, sendErr := connection.Do(ctx, &h2Request)
		lease.Release(connection.Reusable())
		return mapH2Exchange(ctx, request, &response, sendErr, h2Snapshot)
	default:
		lease.Release(false)
		return rawFailure(ErrorCodeIO, FailureReasonUnknown, false)
	}
}

func (t *rawTransport) sendH1(ctx context.Context, request *AttemptRequest, endpoint *rawEndpoint, h1Request *h1.Request, connectTimeout time.Duration, lease *pool.Lease, connection *rawH1Connection) AttemptOutcome {
	exchange := exchangeH1(ctx, connection, h1Request, request, request.CommitTracker)
	if exchange.err != nil && connection.clientCertificateRequested {
		lease.Release(false)
		return rawFailure(ErrorCodeTLS, FailureReasonTLSNegotiation, false)
	}
	if exchange.err != nil && lease.Reused() && exchange.requestWrote && exchange.responseBytes == 0 && staleH1Failure(exchange.err) {
		lease.Release(false)
		resource, mode, dialErr := t.dial(ctx, endpoint, connectTimeout)
		if dialErr != nil {
			failure := dialFailure(ctx, dialErr)
			failure.Failure.Committed = exchange.committed
			return failure
		}
		fresh, ok := resource.(*rawH1Connection)
		if !ok || mode != pool.Exclusive {
			_ = resource.Close()
			return rawFailure(ErrorCodeIO, FailureReasonUnknown, exchange.committed)
		}
		defer func() { _ = fresh.Close() }()
		replayed := exchangeH1(ctx, fresh, h1Request, request, request.CommitTracker)
		replayed.committed = exchange.committed || replayed.committed
		return mapH1Exchange(ctx, &replayed)
	}

	reusable := exchange.err == nil && ctx.Err() == nil && exchange.response.Status >= 200 && !responseClosesConnection(exchange.response.Headers)
	lease.Release(reusable)
	return mapH1Exchange(ctx, &exchange)
}

func (t *rawTransport) dial(ctx context.Context, endpoint *rawEndpoint, timeout time.Duration) (pool.Resource, pool.Mode, error) {
	connectContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resolver := tlsx.Resolver(t.options.DNSResolver)
	var connection net.Conn
	var err error
	if t.options.Proxy == nil {
		connection, err = tlsx.DialTCP(connectContext, endpoint.dialAddress, remainingBudget(connectContext, timeout), resolver)
	} else {
		connection, err = t.dialProxy(connectContext, endpoint, timeout, resolver)
	}
	if err != nil {
		return nil, pool.Exclusive, err
	}
	clientCertificateRequested := false
	if endpoint.scheme == "https" {
		config := t.tlsConfig.Clone()
		config.ServerName = endpoint.serverName
		if len(config.Certificates) == 0 {
			config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				clientCertificateRequested = true
				return &tls.Certificate{}, nil
			}
		}
		tlsConnection, tlsErr := tlsx.Client(connectContext, connection, config)
		if tlsErr != nil {
			_ = connection.Close()
			if clientCertificateRequested {
				return nil, pool.Exclusive, &rawTLSNegotiationError{}
			}
			return nil, pool.Exclusive, tlsErr
		}
		connection = tlsConnection
		if connectionState := tlsConnection.ConnectionState(); connectionState.NegotiatedProtocol == "h2" {
			session, sessionErr := h2.NewSession(connectContext, connection)
			if sessionErr != nil {
				_ = connection.Close()
				if clientCertificateRequested {
					return nil, pool.Shared, &rawTLSNegotiationError{}
				}
				return nil, pool.Shared, sessionErr
			}
			return session, pool.Shared, nil
		}
	}
	counted := &countingReader{reader: connection}
	return &rawH1Connection{
		Conn: connection, received: counted, reader: bufio.NewReader(counted),
		clientCertificateRequested: clientCertificateRequested,
	}, pool.Exclusive, nil
}

func (t *rawTransport) dialProxy(ctx context.Context, endpoint *rawEndpoint, timeout time.Duration, resolver tlsx.Resolver) (net.Conn, error) {
	dial := func(dialContext context.Context) (net.Conn, error) {
		return tlsx.DialTCP(dialContext, t.proxyAddress, remainingBudget(ctx, timeout), resolver)
	}
	var provider proxyconnect.CredentialsProvider
	if t.options.Proxy.CredentialsProvider != nil {
		provider = func(providerContext context.Context) (proxyconnect.Credentials, error) {
			credentials, err := t.options.Proxy.CredentialsProvider(providerContext)
			return proxyconnect.Credentials{Username: credentials.Username, Password: credentials.Password}, err
		}
	}
	connection, failure := proxyconnect.Connect(ctx, endpoint.dialAddress, dial, provider)
	if failure != nil {
		return nil, failure
	}
	return connection, nil
}

func buildRawTLSConfig(options HTTPTransportOptions) (*tls.Config, error) {
	input := tlsx.Config{HTTP2: *options.HTTP2}
	if tlsOptions := options.TLS; tlsOptions != nil {
		input.MinVersion, input.MaxVersion = tlsOptions.MinVersion, tlsOptions.MaxVersion
		input.Ciphers = append([]uint16(nil), tlsOptions.Ciphers...)
		if tlsOptions.CACertificatesPEM != nil {
			input.CACertificatesPEM = make([][]byte, len(tlsOptions.CACertificatesPEM))
			for index, certificate := range tlsOptions.CACertificatesPEM {
				input.CACertificatesPEM[index] = []byte(certificate)
			}
		}
		if tlsOptions.ClientCertificate != nil {
			input.ClientCertificate = &tlsx.ClientCertificate{
				CertificatePEM: []byte(tlsOptions.ClientCertificate.CertificatePEM),
				KeyPEM:         []byte(tlsOptions.ClientCertificate.KeyPEM),
				Passphrase:     []byte(tlsOptions.ClientCertificate.Passphrase),
			}
		}
	}
	return tlsx.BuildConfig(&input)
}

func dialFailure(ctx context.Context, err error) AttemptOutcome {
	var tlsNegotiation *rawTLSNegotiationError
	if errors.As(err, &tlsNegotiation) {
		return rawFailure(ErrorCodeTLS, FailureReasonTLSNegotiation, false)
	}
	var proxyErr *proxyconnect.Failure
	if errors.As(err, &proxyErr) {
		if proxyErr.Kind == proxyconnect.FailureCredentials {
			outcome := rawFailure(ErrorCodeConfiguration, FailureReasonUnknown, false)
			outcome.Failure.causeCategory = CauseCategoryProxyCredentialProvider
			return outcome
		}
		reason := FailureReasonProxyConnectFailed
		if proxyErr.Kind == proxyconnect.FailureAuthRequired {
			reason = FailureReasonProxyAuthRequired
		}
		return rawFailure(ErrorCodeProxy, reason, false)
	}
	if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
		return rawFailure(ErrorCodeConnect, FailureReasonConnectTimeout, false)
	}
	code, reason := classifyTransportCause(ctx, err)
	return rawFailure(code, reason, false)
}

func (t *rawTransport) Close() error {
	t.connections.Close()
	return nil
}

func (t *rawTransport) closeIdleConnections() { _ = t.Close() }

func exchangeH1(ctx context.Context, connection *rawH1Connection, wireRequest *h1.Request, request *AttemptRequest, tracker *CommitTracker) rawExchange {
	before := connection.received.bytes
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return rawExchange{err: err}
		}
	}
	cancelled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
		close(cancelled)
	})
	defer func() {
		if !stop() {
			<-cancelled
		}
		_ = connection.SetDeadline(time.Time{})
	}()

	committed := false
	err := h1.WriteRequest(connection, wireRequest, func() {
		committed = true
		tracker.MarkCommitted()
	})
	if err != nil {
		return rawExchange{committed: committed, err: err}
	}
	var snapshot responseHeaderSnapshot
	response, err := h1.ReadResponseWithHeaders(connection.reader, func(response h1.Response) {
		snapshot.capture(request, response.Status, h1Headers(response.Headers))
	})
	return rawExchange{
		response: response, headerSnapshot: snapshot, responseBytes: connection.received.bytes - before,
		requestWrote: true, committed: committed, err: err,
	}
}

func mapH1Exchange(ctx context.Context, exchange *rawExchange) AttemptOutcome {
	if exchange.err == nil {
		return h1Outcome(&exchange.response, exchange.headerSnapshot)
	}
	if errors.Is(exchange.err, h1.ErrBodyTooLarge) {
		outcome := h1ErrorOutcome(exchange)
		markBodyLimitViolation(outcome.Response)
		outcome.Response.retryForbidden = exchange.response.Status < 200 || exchange.response.Status >= 300
		return outcome
	}
	if errors.Is(exchange.err, h1.ErrExpansionRatio) {
		outcome := h1ErrorOutcome(exchange)
		outcome.Response.protocolViolation = true
		outcome.Response.retryForbidden = exchange.response.Status < 200 || exchange.response.Status >= 300
		return outcome
	}
	if errors.Is(exchange.err, h1.ErrHeaderLimit) {
		outcome := h1ErrorOutcome(exchange)
		outcome.Response.limitViolation = true
		outcome.Response.retryForbidden = true
		outcome.Response.headerLimitViolation = true
		return outcome
	}
	if errors.Is(exchange.err, h1.ErrProtocol) {
		outcome := h1ErrorOutcome(exchange)
		outcome.Response.protocolViolation = true
		outcome.Response.retryForbidden = exchange.response.Status < 200 || exchange.response.Status >= 300
		return outcome
	}
	if errors.Is(exchange.err, h1.ErrIncompleteBody) {
		outcome := h1Outcome(&exchange.response, exchange.headerSnapshot)
		outcome.Response.incomplete = true
		return outcome
	}
	code, reason := classifyTransportCause(ctx, exchange.err)
	if code == ErrorCodeAttemptTimeout && exchange.response.Status >= 100 && exchange.response.Status <= 599 {
		outcome := h1Outcome(&exchange.response, exchange.headerSnapshot)
		outcome.Response.attemptFailureCode, outcome.Response.attemptFailureReason = code, reason
		return outcome
	}
	return rawFailure(code, reason, exchange.committed)
}

func h1ErrorOutcome(exchange *rawExchange) AttemptOutcome {
	response := exchange.response
	response.Body = []byte{}
	response.Truncated = false
	return h1Outcome(&response, exchange.headerSnapshot)
}

func h1Outcome(response *h1.Response, snapshot responseHeaderSnapshot) AttemptOutcome {
	headers := h1Headers(response.Headers)
	body := append([]byte{}, response.Body...)
	status := response.Status
	if status < 100 || status > 599 {
		status = 202
		body = []byte{}
	}
	return AttemptOutcome{Response: &AttemptResponse{
		Status: status, Headers: headers, Body: body,
		CompressedBytes: response.CompressedBytes, DecompressedBytes: response.DecompressedBytes,
		Truncated:         response.Truncated,
		HeadersReceivedAt: snapshot.at, HeadersReceivedAtSet: snapshot.set,
		HeaderClockFailed: snapshot.failed,
	}}
}

func h1Headers(headers []h1.Header) []HeaderField {
	result := make([]HeaderField, len(headers))
	for index, header := range headers {
		result[index] = HeaderField{Name: header.Name, Value: header.Value}
	}
	return result
}

func (snapshot *responseHeaderSnapshot) capture(request *AttemptRequest, status int, headers []HeaderField) {
	at, set, failed := snapshotResponseWallTime(request, status, headers)
	if !set && !failed {
		return
	}
	snapshot.at, snapshot.set, snapshot.failed = at, set, failed
}

func mapH2Exchange(ctx context.Context, request *AttemptRequest, response *h2.Response, err error, snapshot responseHeaderSnapshot) AttemptOutcome {
	if err == nil {
		return h2Outcome(response, snapshot)
	}
	if errors.Is(err, h2.ErrResponseTooLarge) {
		outcome := h2Outcome(response, snapshot)
		markBodyLimitViolation(outcome.Response)
		outcome.Response.retryForbidden = response.Status < 200 || response.Status >= 300
		return outcome
	}
	if errors.Is(err, h2.ErrResponseProtocol) {
		outcome := h2Outcome(response, snapshot)
		outcome.Response.protocolViolation = true
		outcome.Response.retryForbidden = response.Status < 200 || response.Status >= 300
		return outcome
	}
	var goAway *h2.GoAwayError
	if errors.As(err, &goAway) {
		return rawFailure(ErrorCodeIO, FailureReasonConnectionClosed, false)
	}
	var reset *h2.StreamResetError
	if errors.As(err, &reset) {
		return rawFailure(ErrorCodeIO, FailureReasonConnectionReset, request.CommitTracker.isCommitted())
	}
	code, reason := classifyTransportCause(ctx, err)
	if code == ErrorCodeAttemptTimeout && response.Status >= 100 && response.Status <= 599 {
		outcome := h2Outcome(response, snapshot)
		outcome.Response.attemptFailureCode, outcome.Response.attemptFailureReason = code, reason
		return outcome
	}
	return rawFailure(code, reason, request.CommitTracker.isCommitted())
}

func markBodyLimitViolation(response *AttemptResponse) {
	encoding, _ := responseContentEncoding(response.Headers)
	if encoding == "gzip" {
		response.protocolViolation = true
	} else {
		response.limitViolation = true
	}
}

func h2Outcome(response *h2.Response, snapshot responseHeaderSnapshot) AttemptOutcome {
	headers := h2Headers(response.Headers)
	status := response.Status
	body := append([]byte{}, response.Body...)
	if status < 100 || status > 599 {
		status = 202
		body = []byte{}
	}
	return AttemptOutcome{Response: &AttemptResponse{
		Status: status, Headers: headers, Body: body,
		CompressedBytes: response.CompressedBytes, DecompressedBytes: response.DecompressedBytes,
		Truncated:         response.Truncated,
		HeadersReceivedAt: snapshot.at, HeadersReceivedAtSet: snapshot.set,
		HeaderClockFailed: snapshot.failed,
	}}
}

func h2Headers(headers []h2.Header) []HeaderField {
	result := make([]HeaderField, len(headers))
	for index, header := range headers {
		result[index] = HeaderField{Name: header.Name, Value: header.Value}
	}
	return result
}

func makeH1Request(endpoint *rawEndpoint, request *AttemptRequest) (h1.Request, error) {
	want := []string{"authorization", "content-type", "accept-encoding", "user-agent", "idempotency-key"}
	if len(request.Headers) < len(want) || len(request.Headers) > len(want)+2 {
		return h1.Request{}, h1.ErrInvalidRequest
	}
	for index, name := range want {
		if !strings.EqualFold(request.Headers[index].Name, name) {
			return h1.Request{}, h1.ErrInvalidRequest
		}
	}
	if request.Headers[1].Value != "application/json" || request.Headers[2].Value != "gzip" {
		return h1.Request{}, h1.ErrInvalidRequest
	}
	result := h1.Request{
		Target: endpoint.target, Authority: endpoint.authority,
		Authorization: request.Headers[0].Value, UserAgent: request.Headers[3].Value,
		IdempotencyKey: request.Headers[4].Value, Body: request.Body,
	}
	if len(request.Headers) > len(want) {
		if !strings.EqualFold(request.Headers[5].Name, "traceparent") {
			return h1.Request{}, h1.ErrInvalidRequest
		}
		result.Traceparent = request.Headers[5].Value
	}
	if len(request.Headers) > len(want)+1 {
		if !strings.EqualFold(request.Headers[6].Name, "tracestate") {
			return h1.Request{}, h1.ErrInvalidRequest
		}
		result.Tracestate = request.Headers[6].Value
	}
	return result, nil
}

func makeH2Request(endpoint *rawEndpoint, request *h1.Request, tracker *CommitTracker, headersReceived func(int, []h2.Header)) h2.Request {
	return h2.Request{
		Scheme: endpoint.scheme, Authority: endpoint.authority, Path: endpoint.target,
		Authorization: request.Authorization, UserAgent: request.UserAgent, IdempotencyKey: request.IdempotencyKey,
		TraceParent: request.Traceparent, TraceState: request.Tracestate, Body: request.Body,
		MarkCommitted: tracker.MarkCommitted, HeadersReceived: headersReceived,
	}
}

func parseRawEndpoint(raw string) (rawEndpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" || parsed.Opaque != "" ||
		parsed.Scheme != "http" && parsed.Scheme != "https" {
		return rawEndpoint{}, errors.New("raw transport: invalid endpoint")
	}
	target := parsed.EscapedPath()
	if target == "" {
		target = "/"
	}
	if parsed.RawQuery != "" {
		target += "?" + parsed.RawQuery
	}
	for index := range target {
		if target[index] <= 0x20 || target[index] == 0x7f {
			return rawEndpoint{}, errors.New("raw transport: invalid target")
		}
	}
	port := parsed.Port()
	defaultPort := "80"
	if parsed.Scheme == "https" {
		defaultPort = "443"
	}
	return rawEndpoint{
		scheme: parsed.Scheme, authority: parsed.Host, target: target,
		dialAddress: addressWithDefaultPort(parsed.Hostname(), port, defaultPort), serverName: parsed.Hostname(),
	}, nil
}

func addressWithDefaultPort(host, port, fallback string) string {
	if port == "" {
		port = fallback
	}
	return net.JoinHostPort(host, port)
}

func remainingBudget(ctx context.Context, fallback time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		return max(time.Until(deadline), time.Nanosecond)
	}
	return fallback
}

func responseClosesConnection(headers []h1.Header) bool {
	for _, header := range headers {
		if strings.EqualFold(header.Name, "connection") {
			for _, token := range strings.Split(header.Value, ",") {
				if strings.EqualFold(strings.TrimSpace(token), "close") {
					return true
				}
			}
		}
	}
	return false
}

func staleH1Failure(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET)
}

func rawFailure(code ErrorCode, reason FailureReason, committed bool) AttemptOutcome {
	return AttemptOutcome{Failure: &AttemptFailure{Code: code, FailureReason: reason, Committed: committed}}
}
