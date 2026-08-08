package repost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

func classifyTransportCause(ctx context.Context, err error) (ErrorCode, FailureReason) {
	deadlineReached := false
	if deadline, ok := ctx.Deadline(); ok {
		deadlineReached = !time.Now().Before(deadline)
	}
	if deadlineReached || errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return ErrorCodeAttemptTimeout, FailureReasonUnknown
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return ErrorCodeCancelled, FailureReasonUnknown
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.IsTimeout {
			return ErrorCodeDNS, FailureReasonDNSTimeout
		}
		if dns.IsNotFound {
			return ErrorCodeDNS, FailureReasonDNSNotFound
		}
		return ErrorCodeDNS, FailureReasonUnknown
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		reason, _ := classifyCertificateError(verification.Err)
		return ErrorCodeTLS, reason
	}
	if reason, ok := classifyCertificateError(err); ok {
		return ErrorCodeTLS, reason
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return ErrorCodeTLS, FailureReasonTLSNegotiation
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return ErrorCodeTLS, FailureReasonTLSNegotiation
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ErrorCodeConnect, FailureReasonConnectRefused
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return ErrorCodeIO, FailureReasonConnectionReset
	}
	if errors.Is(err, io.EOF) {
		return ErrorCodeIO, FailureReasonConnectionReset
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return ErrorCodeIO, FailureReasonConnectionClosed
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrorCodeConnect, FailureReasonConnectTimeout
	}
	return ErrorCodeIO, FailureReasonUnknown
}

func classifyCertificateError(err error) (FailureReason, bool) {
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return FailureReasonTLSHostnameMismatch, true
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		if invalid.Reason == x509.Expired {
			if invalid.Cert != nil && invalid.Cert.NotBefore.After(tlsVerificationClock()) {
				return FailureReasonTLSCertificateNotYetValid, true
			}
			return FailureReasonTLSCertificateExpired, true
		}
		return FailureReasonTLSUntrusted, true
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return FailureReasonTLSUntrusted, true
	}
	var systemRoots x509.SystemRootsError
	if errors.As(err, &systemRoots) {
		return FailureReasonTLSUntrusted, true
	}
	return FailureReasonTLSUntrusted, false
}
