package repost

import (
	"errors"
	"fmt"
	"log/slog"
)

// ErrorCode is a stable, low-cardinality failure code.
type ErrorCode string

// Error codes returned by Runtime.
const (
	ErrorCodeConfiguration     ErrorCode = "CONFIGURATION"
	ErrorCodeClosed            ErrorCode = "CLOSED"
	ErrorCodeValidation        ErrorCode = "VALIDATION"
	ErrorCodeSerialization     ErrorCode = "SERIALIZATION"
	ErrorCodeRequestTooLarge   ErrorCode = "REQUEST_TOO_LARGE"
	ErrorCodeDNS               ErrorCode = "DNS"
	ErrorCodeConnect           ErrorCode = "CONNECT"
	ErrorCodeProxy             ErrorCode = "PROXY"
	ErrorCodeTLS               ErrorCode = "TLS"
	ErrorCodeIO                ErrorCode = "IO"
	ErrorCodeAttemptTimeout    ErrorCode = "ATTEMPT_TIMEOUT"
	ErrorCodeOperationDeadline ErrorCode = "OPERATION_DEADLINE"
	ErrorCodeCancelled         ErrorCode = "CANCELLED"
	ErrorCodeOverloaded        ErrorCode = "OVERLOADED"
	ErrorCodeRateLimited       ErrorCode = "RATE_LIMITED"
	ErrorCodeHTTPRejected      ErrorCode = "HTTP_REJECTED"
	ErrorCodeServerFailure     ErrorCode = "SERVER_FAILURE"
	ErrorCodeResponseTooLarge  ErrorCode = "RESPONSE_TOO_LARGE"
	ErrorCodeResponseProtocol  ErrorCode = "RESPONSE_PROTOCOL"
	ErrorCodeDescriptorVersion ErrorCode = "DESCRIPTOR_VERSION"
)

// DeliveryState is the best-known delivery state for an operation.
type DeliveryState string

// Delivery states reported for completed and failed operations.
const (
	DeliveryStateNotSent          DeliveryState = "NOT_SENT"
	DeliveryStatePossiblySent     DeliveryState = "POSSIBLY_SENT"
	DeliveryStateAccepted         DeliveryState = "ACCEPTED"
	DeliveryStateRejected         DeliveryState = "REJECTED"
	DeliveryStateCancelledUnknown DeliveryState = "CANCELLED_UNKNOWN"
)

// ErrorCategory groups error codes by remediation boundary.
type ErrorCategory string

// Error categories group stable error codes.
const (
	ErrorCategoryConfiguration     ErrorCategory = "CONFIGURATION"
	ErrorCategoryValidation        ErrorCategory = "VALIDATION"
	ErrorCategorySerialization     ErrorCategory = "SERIALIZATION"
	ErrorCategoryTransport         ErrorCategory = "TRANSPORT"
	ErrorCategoryPublish           ErrorCategory = "PUBLISH"
	ErrorCategoryDescriptorVersion ErrorCategory = "DESCRIPTOR_VERSION"
)

// FailureReason is a stable network failure classification.
type FailureReason string

// Failure reasons classify network failures without exposing sensitive data.
const (
	FailureReasonDNSNotFound               FailureReason = "DNS_NOT_FOUND"
	FailureReasonDNSTimeout                FailureReason = "DNS_TIMEOUT"
	FailureReasonConnectRefused            FailureReason = "CONNECT_REFUSED"
	FailureReasonConnectTimeout            FailureReason = "CONNECT_TIMEOUT"
	FailureReasonConnectionReset           FailureReason = "CONNECTION_RESET"
	FailureReasonConnectionClosed          FailureReason = "CONNECTION_CLOSED"
	FailureReasonTLSUntrusted              FailureReason = "TLS_UNTRUSTED"
	FailureReasonTLSCertificateExpired     FailureReason = "TLS_CERTIFICATE_EXPIRED"
	FailureReasonTLSCertificateNotYetValid FailureReason = "TLS_CERTIFICATE_NOT_YET_VALID"
	FailureReasonTLSHostnameMismatch       FailureReason = "TLS_HOSTNAME_MISMATCH"
	FailureReasonTLSNegotiation            FailureReason = "TLS_NEGOTIATION"
	FailureReasonProxyAuthRequired         FailureReason = "PROXY_AUTH_REQUIRED"
	FailureReasonProxyConnectFailed        FailureReason = "PROXY_CONNECT_FAILED"
	FailureReasonUnknown                   FailureReason = "UNKNOWN"
)

// CauseCategory is a safe, low-cardinality local-cause classification.
type CauseCategory string

// Cause categories identify safe local failure boundaries.
const (
	CauseCategoryAPIKeyProvider               CauseCategory = "API_KEY_PROVIDER"
	CauseCategoryDefaultGenerator             CauseCategory = "DEFAULT_GENERATOR"
	CauseCategoryIdempotencyGenerator         CauseCategory = "IDEMPOTENCY_GENERATOR"
	CauseCategoryRetryEntropy                 CauseCategory = "RETRY_ENTROPY"
	CauseCategoryDNSResolver                  CauseCategory = "DNS_RESOLVER"
	CauseCategoryProxyCredentialProvider      CauseCategory = "PROXY_" + "CREDENTIAL_PROVIDER"
	CauseCategoryTLSProvider                  CauseCategory = "TLS_PROVIDER"
	CauseCategoryCustomTransport              CauseCategory = "CUSTOM_TRANSPORT"
	CauseCategoryResponseBody                 CauseCategory = "RESPONSE_BODY"
	CauseCategoryObserver                     CauseCategory = "OBSERVER"
	CauseCategoryHTTPRuntime                  CauseCategory = "HTTP_RUNTIME"
	CauseCategoryTransportClose               CauseCategory = "TRANSPORT_CLOSE"
	CauseCategorySchedulerClose               CauseCategory = "SCHEDULER_CLOSE"
	CauseCategoryOperationExecutorClose       CauseCategory = "OPERATION_EXECUTOR_CLOSE"
	CauseCategoryDNSExecutorClose             CauseCategory = "DNS_EXECUTOR_CLOSE"
	CauseCategoryProxyCredentialExecutorClose CauseCategory = "PROXY_" + "CREDENTIAL_EXECUTOR_CLOSE"
	CauseCategoryTLSExecutorClose             CauseCategory = "TLS_EXECUTOR_CLOSE"
	CauseCategoryTerminalSettlementClose      CauseCategory = "TERMINAL_SETTLEMENT_CLOSE"
	CauseCategoryObserverClose                CauseCategory = "OBSERVER_CLOSE"
	CauseCategoryUnknown                      CauseCategory = "UNKNOWN"
)

// ValidationIssueCode is a stable validation issue classification.
type ValidationIssueCode string

// Validation issue codes identify bounded input failures.
const (
	ValidationIssueCodeRequired        ValidationIssueCode = "REQUIRED"
	ValidationIssueCodeNullNotAllowed  ValidationIssueCode = "NULL_NOT_ALLOWED"
	ValidationIssueCodeTypeMismatch    ValidationIssueCode = "TYPE_MISMATCH"
	ValidationIssueCodeOutOfRange      ValidationIssueCode = "OUT_OF_RANGE"
	ValidationIssueCodeNonFinite       ValidationIssueCode = "NON_FINITE"
	ValidationIssueCodeInvalidDatetime ValidationIssueCode = "INVALID_DATETIME"
	ValidationIssueCodeInvalidEnum     ValidationIssueCode = "INVALID_ENUM"
	ValidationIssueCodeInvalidJSON     ValidationIssueCode = "INVALID_JSON"
	ValidationIssueCodeInvalidUnicode  ValidationIssueCode = "INVALID_UNICODE"
	ValidationIssueCodeCollectionLimit ValidationIssueCode = "COLLECTION_LIMIT"
	ValidationIssueCodeCycle           ValidationIssueCode = "CYCLE"
)

// ConfigurationIssueCode is a stable configuration issue classification.
type ConfigurationIssueCode string

// Configuration issue codes identify invalid client options.
const (
	ConfigurationIssueCodeMissing          ConfigurationIssueCode = "MISSING"
	ConfigurationIssueCodeConflict         ConfigurationIssueCode = "CONFLICT"
	ConfigurationIssueCodeInvalidValue     ConfigurationIssueCode = "INVALID_VALUE"
	ConfigurationIssueCodeOutOfRange       ConfigurationIssueCode = "OUT_OF_RANGE"
	ConfigurationIssueCodeUnsupported      ConfigurationIssueCode = "UNSUPPORTED"
	ConfigurationIssueCodeResourceMismatch ConfigurationIssueCode = "RESOURCE_MISMATCH"
)

// ClientOptionKey is a stable identifier for a client configuration field.
type ClientOptionKey string

// Client option keys identify public configuration fields.
const (
	ClientOptionKeyAPIKey                  ClientOptionKey = "API_KEY"
	ClientOptionKeyAPIKeyProvider          ClientOptionKey = "API_KEY_PROVIDER"
	ClientOptionKeyBaseURI                 ClientOptionKey = "BASE_URI"
	ClientOptionKeyConnectTimeout          ClientOptionKey = "CONNECT_TIMEOUT"
	ClientOptionKeyAttemptTimeout          ClientOptionKey = "ATTEMPT_TIMEOUT"
	ClientOptionKeyOperationTimeout        ClientOptionKey = "OPERATION_TIMEOUT"
	ClientOptionKeyMaxAttempts             ClientOptionKey = "MAX_ATTEMPTS"
	ClientOptionKeyMaxInFlightOperations   ClientOptionKey = "MAX_IN_FLIGHT_OPERATIONS"
	ClientOptionKeyMaxBufferedBytes        ClientOptionKey = "MAX_BUFFERED_BYTES"
	ClientOptionKeyRetryBaseDelay          ClientOptionKey = "RETRY_BASE_DELAY"
	ClientOptionKeyRetryMaxDelay           ClientOptionKey = "RETRY_MAX_DELAY"
	ClientOptionKeyHTTPTransportOptions    ClientOptionKey = "HTTP_TRANSPORT_OPTIONS"
	ClientOptionKeyTransport               ClientOptionKey = "TRANSPORT"
	ClientOptionKeyExecutor                ClientOptionKey = "EXECUTOR"
	ClientOptionKeyScheduler               ClientOptionKey = "SCHEDULER"
	ClientOptionKeyObserver                ClientOptionKey = "OBSERVER"
	ClientOptionKeyObserverExecutor        ClientOptionKey = "OBSERVER_EXECUTOR"
	ClientOptionKeyTelemetry               ClientOptionKey = "TELEMETRY"
	ClientOptionKeyDefaultValueGenerators  ClientOptionKey = "DEFAULT_VALUE_GENERATORS"
	ClientOptionKeyIdempotencyKeyGenerator ClientOptionKey = "IDEMPOTENCY_KEY_GENERATOR"
	ClientOptionKeyMonotonicClock          ClientOptionKey = "MONOTONIC_CLOCK"
	ClientOptionKeyWallClock               ClientOptionKey = "WALL_CLOCK"
	ClientOptionKeyRetryEntropy            ClientOptionKey = "RETRY_ENTROPY"
	ClientOptionKeyUserAgentSuffix         ClientOptionKey = "USER_AGENT_SUFFIX"
)

// ValidationIssue contains only a stable code and safe schema path.
type ValidationIssue struct {
	Code ValidationIssueCode `json:"code"`
	Path string              `json:"path"`
}

// ConfigurationIssue contains only a stable code and option keys.
type ConfigurationIssue struct {
	Code       ConfigurationIssueCode `json:"code"`
	OptionKeys []ClientOptionKey      `json:"optionKeys"`
}

// Error describes a Repost operation failure without retaining unsafe cause
// text or response content.
type Error struct {
	Code                 ErrorCode
	DeliveryState        DeliveryState
	Retryable            bool
	OperationID          string
	IdempotencyKey       string
	AttemptCount         int
	HTTPStatus           int
	FailureReason        FailureReason
	CauseCategory        CauseCategory
	CompressedBytes      int64
	DecompressedBytes    int64
	ResponseHeaderFields int
	ResponseHeaderBytes  int64
	Truncated            bool
	ValidationIssues     []ValidationIssue
	ConfigurationIssues  []ConfigurationIssue
	IssueCount           int
	IssuesTruncated      bool
}

// Error returns the frozen public message for the error code.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	switch e.Code {
	case ErrorCodeConfiguration:
		return "Invalid transport configuration"
	case ErrorCodeClosed:
		return "Client is closed"
	case ErrorCodeValidation:
		return "Message validation failed"
	case ErrorCodeSerialization:
		return "Message serialization failed"
	case ErrorCodeRequestTooLarge:
		return "Request exceeds the size limit"
	case ErrorCodeDNS:
		return "DNS resolution failed"
	case ErrorCodeConnect:
		return "Connection failed"
	case ErrorCodeProxy:
		return "Proxy connection failed"
	case ErrorCodeTLS:
		return "TLS negotiation failed"
	case ErrorCodeIO:
		return "Transport I/O failed"
	case ErrorCodeAttemptTimeout:
		return "Transport attempt timed out"
	case ErrorCodeOperationDeadline:
		return "Operation deadline exceeded"
	case ErrorCodeCancelled:
		return "Operation cancelled"
	case ErrorCodeOverloaded:
		return "Transport is at capacity"
	case ErrorCodeRateLimited:
		return "Request was rate limited"
	case ErrorCodeHTTPRejected:
		return "Request was rejected"
	case ErrorCodeServerFailure:
		return "Server failed to process the request"
	case ErrorCodeResponseTooLarge:
		return "Response exceeds the size limit"
	case ErrorCodeResponseProtocol:
		return "Response protocol is invalid"
	case ErrorCodeDescriptorVersion:
		return "Descriptor version is not supported"
	default:
		return ""
	}
}

// String returns the frozen catalog message.
func (e *Error) String() string {
	return e.Error()
}

// Format keeps every fmt representation on the frozen catalog surface.
func (e *Error) Format(state fmt.State, verb rune) {
	if verb == 'q' {
		_, _ = fmt.Fprintf(state, "%q", e.Error())
		return
	}
	_, _ = fmt.Fprint(state, e.Error())
}

// LogValue exposes only validated enums and safe scalar contract fields.
func (e *Error) LogValue() slog.Value {
	if e == nil {
		return slog.GroupValue()
	}
	attrs := make([]slog.Attr, 0, 12)
	if category := e.Category(); category != "" {
		attrs = append(attrs,
			slog.String("code", string(e.Code)),
			slog.String("category", string(category)),
		)
	}
	switch e.DeliveryState {
	case DeliveryStateNotSent, DeliveryStatePossiblySent, DeliveryStateAccepted,
		DeliveryStateRejected, DeliveryStateCancelledUnknown:
		attrs = append(attrs, slog.String("delivery_state", string(e.DeliveryState)))
	}
	attrs = append(attrs,
		slog.Bool("retryable", e.Retryable),
		slog.Int("attempt_count", e.AttemptCount),
		slog.Int("http_status", e.HTTPStatus),
		slog.Int64("compressed_bytes", e.CompressedBytes),
		slog.Int64("decompressed_bytes", e.DecompressedBytes),
		slog.Int("response_header_fields", e.ResponseHeaderFields),
		slog.Int64("response_header_bytes", e.ResponseHeaderBytes),
		slog.Bool("truncated", e.Truncated),
	)
	return slog.GroupValue(attrs...)
}

// Category returns the stable category for Code.
func (e *Error) Category() ErrorCategory {
	if e == nil {
		return ""
	}
	switch e.Code {
	case ErrorCodeConfiguration, ErrorCodeClosed:
		return ErrorCategoryConfiguration
	case ErrorCodeValidation:
		return ErrorCategoryValidation
	case ErrorCodeSerialization, ErrorCodeRequestTooLarge:
		return ErrorCategorySerialization
	case ErrorCodeDNS, ErrorCodeConnect, ErrorCodeProxy, ErrorCodeTLS, ErrorCodeIO,
		ErrorCodeAttemptTimeout, ErrorCodeOperationDeadline, ErrorCodeCancelled, ErrorCodeOverloaded:
		return ErrorCategoryTransport
	case ErrorCodeRateLimited, ErrorCodeHTTPRejected, ErrorCodeServerFailure,
		ErrorCodeResponseTooLarge, ErrorCodeResponseProtocol:
		return ErrorCategoryPublish
	case ErrorCodeDescriptorVersion:
		return ErrorCategoryDescriptorVersion
	default:
		return ""
	}
}

// IsRetryable reports whether err contains a retryable Repost Error.
func IsRetryable(err error) bool {
	var repostErr *Error
	return errors.As(err, &repostErr) && repostErr != nil && repostErr.Retryable
}
