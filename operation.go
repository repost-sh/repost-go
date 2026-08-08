package repost

import (
	"context"
	"errors"
	"strings"
	"time"
)

type stringResult struct {
	value string
	ok    bool
}

type serializationResult struct {
	data     *OrderedObject
	err      error
	panicked bool
}

type marshalResult struct {
	body []byte
	err  error
}

func (r *Runtime) sendAdmitted(ctx context.Context, permit *operationPermit, schema SchemaDescriptor, group, member string, input SendInput) (result *SendResult, finalErr error) {
	operationID := "op_" + defaultUUID()
	decorate := func(err *Error) *Error {
		if err != nil {
			err.OperationID = operationID
		}
		return err
	}
	if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, ""); terminal != nil {
		return nil, terminal
	}
	observability := r.startObservability(permit, operationID)
	defer func() { observability.finish(finalErr) }()
	if err := ValidateSchemaDescriptor(schema); err != nil {
		if schema.DescriptorFormatVersion != DescriptorFormatVersion {
			return nil, decorate(operationError(ErrorCodeDescriptorVersion))
		}
		return nil, decorate(operationError(ErrorCodeConfiguration))
	}
	members, ok := schema.Webhooks[group]
	if !ok {
		return nil, decorate(operationError(ErrorCodeConfiguration))
	}
	event, ok := members[member]
	if !ok {
		return nil, decorate(operationError(ErrorCodeConfiguration))
	}

	apiKey := r.config.apiKey
	if r.config.apiKeyProvider != nil {
		if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, ""); terminal != nil {
			return nil, terminal
		}
		provider, completed := boundedPermitCall(permit.deadlineContext, permit, func() stringResult {
			value, ok := callAPIKeyProvider(ctx, r.config.apiKeyProvider)
			return stringResult{value: value, ok: ok}
		})
		if !completed {
			return nil, r.preAttemptTerminal(ctx, permit, false, 0, operationID, "")
		}
		if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, ""); terminal != nil {
			return nil, terminal
		}
		apiKey = provider.value
		if !provider.ok {
			if ctx.Err() != nil {
				return nil, decorate(cancelledError(DeliveryStateNotSent))
			}
			return nil, hookConfigurationError(DeliveryStateNotSent, operationID, "", 0,
				ClientOptionKeyAPIKeyProvider, CauseCategoryAPIKeyProvider)
		}
		if !validCredential(apiKey) {
			return nil, decorate(configurationError(ConfigurationIssueCodeInvalidValue, ClientOptionKeyAPIKeyProvider))
		}
	} else if r.config.apiKey == "" {
		return nil, decorate(configurationError(ConfigurationIssueCodeMissing, ClientOptionKeyAPIKey))
	}
	if err := r.preAttemptTerminal(ctx, permit, false, 0, operationID, ""); err != nil {
		return nil, err
	}

	idempotencyKey := input.IdempotencyKey
	callerIdempotencyKey := idempotencyKey != ""
	if idempotencyKey == "" {
		if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, ""); terminal != nil {
			return nil, terminal
		}
		generated, completed := boundedPermitCall(permit.deadlineContext, permit, func() stringResult {
			value, ok := callIdempotencyGenerator(r.config.idempotencyKeyGenerator)
			return stringResult{value: value, ok: ok}
		})
		if !completed {
			return nil, r.preAttemptTerminal(ctx, permit, false, 0, operationID, "")
		}
		if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, ""); terminal != nil {
			return nil, terminal
		}
		idempotencyKey = generated.value
		if !generated.ok {
			return nil, hookConfigurationError(DeliveryStateNotSent, operationID, "", 0,
				ClientOptionKeyIdempotencyKeyGenerator, CauseCategoryIdempotencyGenerator)
		}
	}
	if !validIdempotencyKey(idempotencyKey) {
		if callerIdempotencyKey {
			issueCode := ValidationIssueCodeInvalidUnicode
			if len(idempotencyKey) > 255 {
				issueCode = ValidationIssueCodeCollectionLimit
			}
			return nil, &Error{Code: ErrorCodeValidation, DeliveryState: DeliveryStateNotSent, OperationID: operationID,
				ValidationIssues: []ValidationIssue{{Code: issueCode, Path: "$"}}}
		}
		err := configurationError(ConfigurationIssueCodeInvalidValue, ClientOptionKeyIdempotencyKeyGenerator)
		err.OperationID = operationID
		return nil, err
	}

	if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, idempotencyKey); terminal != nil {
		return nil, terminal
	}
	generatedNow, completed := boundedPermitCall(permit.deadlineContext, permit, func() stringResult {
		value, ok := callGenerator(r.config.generators.Now)
		return stringResult{value: value, ok: ok}
	})
	if !completed {
		return nil, r.preAttemptTerminal(ctx, permit, false, 0, operationID, idempotencyKey)
	}
	if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, idempotencyKey); terminal != nil {
		return nil, terminal
	}
	operationNow := generatedNow.value
	if !generatedNow.ok {
		return nil, hookConfigurationError(DeliveryStateNotSent, operationID, idempotencyKey, 0,
			ClientOptionKeyDefaultValueGenerators, CauseCategoryDefaultGenerator)
	}
	if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, idempotencyKey); terminal != nil {
		return nil, terminal
	}
	serialized, completed := boundedPermitCall(permit.deadlineContext, permit, func() serializationResult {
		data, panicked, err := serializeOperation(schema, event.Model, input.Data, operationNow, r.config.generators)
		return serializationResult{data: data, err: err, panicked: panicked}
	})
	if !completed {
		return nil, r.preAttemptTerminal(ctx, permit, false, 0, operationID, idempotencyKey)
	}
	if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, idempotencyKey); terminal != nil {
		return nil, terminal
	}
	data, err, generatorPanicked := serialized.data, serialized.err, serialized.panicked
	if generatorPanicked {
		return nil, hookConfigurationError(DeliveryStateNotSent, operationID, idempotencyKey, 0,
			ClientOptionKeyDefaultValueGenerators, CauseCategoryDefaultGenerator)
	}
	if err != nil {
		return nil, serializerOperationError(err, operationID, idempotencyKey)
	}
	if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, idempotencyKey); terminal != nil {
		return nil, terminal
	}
	marshaled, completed := boundedPermitCall(permit.deadlineContext, permit, func() marshalResult {
		body, err := marshalEnvelope(input.CustomerID, event.Type, operationNow, data)
		return marshalResult{body: body, err: err}
	})
	if !completed {
		return nil, r.preAttemptTerminal(ctx, permit, false, 0, operationID, idempotencyKey)
	}
	if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, idempotencyKey); terminal != nil {
		return nil, terminal
	}
	body := marshaled.body
	if marshaled.err != nil {
		return nil, &Error{Code: ErrorCodeSerialization, DeliveryState: DeliveryStateNotSent, OperationID: operationID, IdempotencyKey: idempotencyKey}
	}
	if len(body) > maxPayloadBytes {
		return nil, &Error{Code: ErrorCodeRequestTooLarge, DeliveryState: DeliveryStateNotSent, OperationID: operationID, IdempotencyKey: idempotencyKey}
	}
	permit.shrinkRequest(int64(len(body)))
	if terminal := r.preAttemptTerminal(ctx, permit, false, 0, operationID, idempotencyKey); terminal != nil {
		return nil, terminal
	}

	headers := []HeaderField{
		{Name: "authorization", Value: "Bearer " + apiKey},
		{Name: "content-type", Value: "application/json"},
		{Name: "accept-encoding", Value: "gzip"},
		{Name: "user-agent", Value: operationUserAgent(r.config.userAgentSuffix)},
		{Name: "idempotency-key", Value: idempotencyKey},
	}
	committed := false
	for attempt := 1; attempt <= r.config.maxAttempts; attempt++ {
		if terminal := r.preAttemptTerminal(ctx, permit, committed, attempt-1, operationID, idempotencyKey); terminal != nil {
			return nil, terminal
		}
		now, clockOK := callMonotonicClock(r.config.monotonicClock)
		if terminal := r.preAttemptTerminal(ctx, permit, committed, attempt-1, operationID, idempotencyKey); terminal != nil {
			return nil, terminal
		}
		if !clockOK {
			return nil, hookConfigurationError(deliveryForCommit(committed), operationID, idempotencyKey, attempt-1,
				ClientOptionKeyMonotonicClock, CauseCategoryUnknown)
		}
		remaining := permit.exclusiveDeadline - now
		attemptBudget := min(r.config.attemptTimeout, time.Duration(remaining))
		propagationHeaders := observability.startAttempt(attempt)
		attemptCtx, attemptDeadlineCtx, cleanupAttemptContexts := newAttemptContexts(observability.context(ctx), observability.context(permit.deadlineContext), attemptBudget)
		tracker := &CommitTracker{}
		committedBeforeAttempt := committed
		request := AttemptRequest{
			OperationID: operationID, APIURL: r.config.endpoint, Headers: append(append([]HeaderField(nil), headers...), propagationHeaders...), Body: body,
			AttemptNumber: attempt, ConnectTimeout: r.config.connectTimeout, AttemptTimeout: attemptBudget, CommitTracker: tracker,
			SnapshotResponseWallTime: func() (time.Time, bool) { return callWallClock(r.config.wallClock) },
		}
		outcome, completed := boundedAttemptCall(
			attemptDeadlineCtx,
			permit.deadlineContext,
			permit,
			func() AttemptOutcome { return r.attempt(attemptCtx, &request) },
			func(abandoned AttemptOutcome) {
				if abandoned.Response != nil && abandoned.Response.close() != nil {
					r.state.recordResponseCloseFailure()
				}
			},
		)
		cleanupAttemptContexts()
		if !completed {
			if outcome.Response != nil && outcome.Response.close() != nil {
				r.state.recordResponseCloseFailure()
			}
			if terminal := r.preAttemptTerminal(ctx, permit, committed || tracker.isCommitted(), attempt, operationID, idempotencyKey); terminal != nil {
				observability.endAttempt(terminal, false)
				return nil, terminal
			}
			outcome = AttemptOutcome{Failure: &AttemptFailure{Code: ErrorCodeAttemptTimeout, Committed: tracker.isCommitted()}}
		}
		outcome.Response = snapshotAttemptResponse(outcome.Response)
		if outcome.Response != nil && outcome.Response.headerLimitViolation {
			r.state.recordResponseHeaderLimitFailure()
		}
		attemptCommitted := tracker.isCommitted() || outcome.Failure != nil && outcome.Failure.Committed
		if outcome.Response != nil {
			// A completed response can prove that this attempt was rejected.
			// Only ambiguous/success-class responses raise the acceptance floor
			// carried into a later retry.
			attemptCommitted = responseMayHaveBeenAccepted(outcome.Response.Status)
		}
		if outcome.Failure != nil && preCommitFailure(outcome.Failure.Code) {
			attemptCommitted = false
		}
		committed = committedBeforeAttempt || attemptCommitted
		if outcome.Response != nil && outcome.Failure != nil || outcome.Response == nil && outcome.Failure == nil ||
			outcome.Failure != nil && !validAttemptFailure(outcome.Failure) ||
			outcome.Response != nil && !validAttemptResponseShape(outcome.Response) {
			if outcome.Response.close() != nil {
				r.state.recordResponseCloseFailure()
			}
			state := DeliveryStatePossiblySent
			cause := CauseCategoryCustomTransport
			if r.ownsTransport {
				cause = CauseCategoryHTTPRuntime
			}
			malformed := &Error{Code: ErrorCodeIO, DeliveryState: state, OperationID: operationID, IdempotencyKey: idempotencyKey,
				AttemptCount: attempt, FailureReason: FailureReasonUnknown, CauseCategory: cause}
			observability.endAttempt(malformed, false)
			return nil, malformed
		}

		// A completed success wins a concurrent cancellation.
		if outcome.Response != nil {
			result, responseErr := validateAttemptResponse(outcome.Response, event.Type, input.CustomerID, operationNow)
			if outcome.Response.close() != nil {
				r.state.recordResponseCloseFailure()
			}
			if responseErr == nil {
				if terminal := r.deadlineTerminal(permit, committed, attempt, operationID, idempotencyKey); terminal != nil {
					terminal = withResponseEvidence(terminal, attemptResponseEvidence(outcome.Response))
					observability.endAttempt(terminal, false)
					return nil, terminal
				}
				observability.endAttempt(nil, false)
				return result, nil
			}
			responseErr.OperationID, responseErr.IdempotencyKey, responseErr.AttemptCount = operationID, idempotencyKey, attempt
			if outcome.Response.Status == statusProxyAuthRequired {
				r.setAttemptCause(responseErr)
			}
			if committedBeforeAttempt && (responseErr.Code == ErrorCodeProxy || responseErr.DeliveryState == DeliveryStateRejected) {
				responseErr.DeliveryState = DeliveryStatePossiblySent
			}
			if terminal := r.preAttemptTerminal(ctx, permit, committed, attempt, operationID, idempotencyKey); terminal != nil {
				terminal = withResponseEvidence(terminal, responseErr)
				observability.endAttempt(terminal, false)
				return nil, terminal
			}
			if !responseErr.Retryable || attempt == r.config.maxAttempts {
				observability.endAttempt(responseErr, false)
				return nil, responseErr
			}
			observability.endAttempt(responseErr, true)
			if err := r.backoff(ctx, permit, responseErr, outcome.Response, attempt, committed, observability); err != nil {
				return nil, err
			}
			continue
		}

		failure := classifyAttemptFailure(outcome.Failure, committed)
		r.setAttemptCause(failure)
		failure.OperationID, failure.IdempotencyKey, failure.AttemptCount = operationID, idempotencyKey, attempt
		if terminal := r.preAttemptTerminal(ctx, permit, committed, attempt, operationID, idempotencyKey); terminal != nil {
			observability.endAttempt(terminal, false)
			return nil, terminal
		}
		if !failure.Retryable || attempt == r.config.maxAttempts {
			observability.endAttempt(failure, false)
			return nil, failure
		}
		observability.endAttempt(failure, true)
		if err := r.backoff(ctx, permit, failure, nil, attempt, committed, observability); err != nil {
			return nil, err
		}
	}
	panic("unreachable")
}

func newAttemptContexts(cooperativeParent, hardParent context.Context, budget time.Duration) (transportContext, hardContext context.Context, cleanup func()) {
	hardContext, cancelHard := context.WithTimeout(hardParent, budget)
	transportContext, cancelTransport := context.WithCancel(hardContext)
	stopCooperativeCancellation := context.AfterFunc(cooperativeParent, cancelTransport)
	if cooperativeParent.Err() != nil {
		cancelTransport()
	}
	return transportContext, hardContext, func() {
		stopCooperativeCancellation()
		cancelTransport()
		cancelHard()
	}
}

func validAttemptResponseShape(response *AttemptResponse) bool {
	if response == nil || response.Status < 100 || response.Status > 599 ||
		response.Headers == nil || response.Body == nil ||
		response.CompressedBytes < 0 || response.DecompressedBytes < 0 ||
		response.attemptFailureCode != "" && response.attemptFailureCode != ErrorCodeAttemptTimeout {
		return false
	}
	hasHeaderTime := !response.HeadersReceivedAt.IsZero()
	needsHeaderTime := responseNeedsWallSnapshotForStatus(response.Status, response.Headers)
	if response.HeadersReceivedAtSet != hasHeaderTime ||
		response.HeaderClockFailed && (response.HeadersReceivedAtSet || hasHeaderTime) ||
		(response.HeadersReceivedAtSet || response.HeaderClockFailed) && !needsHeaderTime ||
		needsHeaderTime && !response.HeadersReceivedAtSet && !response.HeaderClockFailed {
		return false
	}
	return true
}

func (r *Runtime) attempt(ctx context.Context, request *AttemptRequest) (outcome AttemptOutcome) {
	defer func() {
		if recover() != nil {
			outcome = AttemptOutcome{}
		}
	}()
	return r.transport.Send(ctx, request)
}

func marshalEnvelope(customerID, eventType, timestamp string, data *OrderedObject) ([]byte, error) {
	body := NewOrderedObject()
	body.Set("type", eventType)
	body.Set("customerId", customerID)
	body.Set("timestamp", timestamp)
	body.Set("data", data)
	return body.marshalJSONLimit(maxPayloadBytes)
}

func (r *Runtime) preAttemptTerminal(ctx context.Context, permit *operationPermit, committed bool, attempts int, operationID, key string) *Error {
	if permit.deadlineContext.Err() != nil {
		return operationDeadlineError(committed, attempts, operationID, key)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(permit.callerContext.Err(), context.DeadlineExceeded) {
		return operationDeadlineError(committed, attempts, operationID, key)
	}
	if r.context.Err() != nil {
		state := DeliveryStateNotSent
		if committed {
			state = DeliveryStateCancelledUnknown
		}
		return &Error{Code: ErrorCodeClosed, DeliveryState: state, OperationID: operationID, IdempotencyKey: key, AttemptCount: attempts}
	}
	if ctx.Err() != nil || permit.callerContext.Err() != nil {
		state := DeliveryStateNotSent
		if committed {
			state = DeliveryStateCancelledUnknown
		}
		return &Error{Code: ErrorCodeCancelled, DeliveryState: state, OperationID: operationID, IdempotencyKey: key, AttemptCount: attempts}
	}
	now, ok := callMonotonicClock(r.config.monotonicClock)
	if !ok {
		return hookConfigurationError(deliveryForCommit(committed), operationID, key, attempts,
			ClientOptionKeyMonotonicClock, CauseCategoryUnknown)
	}
	if now >= permit.exclusiveDeadline {
		return operationDeadlineError(committed, attempts, operationID, key)
	}
	return nil
}

func (r *Runtime) deadlineTerminal(permit *operationPermit, committed bool, attempts int, operationID, key string) *Error {
	if permit.deadlineContext.Err() != nil {
		return operationDeadlineError(committed, attempts, operationID, key)
	}
	now, ok := callMonotonicClock(r.config.monotonicClock)
	if !ok {
		return hookConfigurationError(deliveryForCommit(committed), operationID, key, attempts,
			ClientOptionKeyMonotonicClock, CauseCategoryUnknown)
	}
	if now >= permit.exclusiveDeadline {
		return operationDeadlineError(committed, attempts, operationID, key)
	}
	return nil
}

func operationDeadlineError(committed bool, attempts int, operationID, key string) *Error {
	return &Error{Code: ErrorCodeOperationDeadline, DeliveryState: deliveryForCommit(committed), OperationID: operationID, IdempotencyKey: key, AttemptCount: attempts}
}

func withResponseEvidence(terminal, last *Error) *Error {
	terminal.HTTPStatus = last.HTTPStatus
	terminal.CompressedBytes, terminal.DecompressedBytes = last.CompressedBytes, last.DecompressedBytes
	terminal.ResponseHeaderFields, terminal.ResponseHeaderBytes, terminal.Truncated = last.ResponseHeaderFields, last.ResponseHeaderBytes, last.Truncated
	return terminal
}

func attemptResponseEvidence(response *AttemptResponse) *Error {
	return &Error{HTTPStatus: response.Status, CompressedBytes: response.CompressedBytes,
		DecompressedBytes: response.DecompressedBytes, Truncated: response.Truncated}
}

func deliveryForCommit(committed bool) DeliveryState {
	if committed {
		return DeliveryStatePossiblySent
	}
	return DeliveryStateNotSent
}

func (r *Runtime) backoff(ctx context.Context, permit *operationPermit, last *Error, response *AttemptResponse, attempt int, committed bool, observability *operationObservability) *Error {
	now, ok := callMonotonicClock(r.config.monotonicClock)
	if !ok {
		return withResponseEvidence(hookConfigurationError(deliveryForCommit(committed), last.OperationID, last.IdempotencyKey, attempt,
			ClientOptionKeyMonotonicClock, CauseCategoryUnknown), last)
	}
	remainingNanos := permit.exclusiveDeadline - now
	if remainingNanos <= 0 {
		return withResponseEvidence(operationDeadlineError(committed, attempt, last.OperationID, last.IdempotencyKey), last)
	}
	remainingMillis := remainingNanos / int64(time.Millisecond)
	if remainingMillis <= 0 {
		return withResponseEvidence(operationDeadlineError(committed, attempt, last.OperationID, last.IdempotencyKey), last)
	}
	capMillis := r.config.retryBaseDelay.Milliseconds()
	maximumMillis := r.config.retryMaxDelay.Milliseconds()
	for range attempt - 1 {
		if capMillis > maximumMillis-capMillis {
			capMillis = maximumMillis
			break
		}
		capMillis *= 2
	}
	capMillis = min(capMillis, maximumMillis, remainingMillis)
	entropy, completed := boundedPermitCall(permit.deadlineContext, permit, func() entropyResult {
		value, ok, panicked := sampleRetryEntropy(r.config.retryEntropy, capMillis+1)
		return entropyResult{value: value, ok: ok, panicked: panicked}
	})
	if !completed {
		return r.preAttemptTerminal(ctx, permit, committed, attempt, last.OperationID, last.IdempotencyKey)
	}
	jitter, ok := entropy.value, entropy.ok
	if !ok {
		cause := CauseCategory("")
		if entropy.panicked {
			cause = CauseCategoryRetryEntropy
		}
		return withResponseEvidence(hookConfigurationError(last.DeliveryState, last.OperationID, last.IdempotencyKey, attempt,
			ClientOptionKeyRetryEntropy, cause), last)
	}
	delayMillis := jitter
	var headers []HeaderField
	if response != nil {
		headers = response.Headers
	}
	if value, ok := retryAfterValue(headers); ok {
		retryAfter, valid, needsWall := parseRetryAfterDelta(value)
		if needsWall {
			switch {
			case response == nil || !responseNeedsWallSnapshotForStatus(response.Status, headers):
				valid = false
			case response.HeaderClockFailed || !response.HeadersReceivedAtSet:
				return withResponseEvidence(hookConfigurationError(last.DeliveryState, last.OperationID, last.IdempotencyKey, attempt,
					ClientOptionKeyWallClock, CauseCategoryUnknown), last)
			default:
				retryAfter, valid = parseRetryAfterDate(value, response.HeadersReceivedAt)
			}
		}
		if valid {
			delayMillis = max(delayMillis, min(retryAfter.Milliseconds(), retryAfterCap.Milliseconds(), remainingMillis))
		}
	}
	observability.retry(time.Duration(delayMillis)*time.Millisecond, last)
	scheduler := schedulerResult{}
	if _, builtIn := r.config.scheduler.(timerScheduler); builtIn {
		scheduler.ok, scheduler.err = callScheduler(ctx, r.config.scheduler, time.Duration(delayMillis)*time.Millisecond)
		completed = true
	} else {
		scheduler, completed = boundedPermitCall(permit.deadlineContext, permit, func() schedulerResult {
			ok, err := callScheduler(ctx, r.config.scheduler, time.Duration(delayMillis)*time.Millisecond)
			return schedulerResult{err: err, ok: ok}
		})
	}
	if !completed {
		return withResponseEvidence(r.preAttemptTerminal(ctx, permit, committed, attempt, last.OperationID, last.IdempotencyKey), last)
	}
	if terminal := r.preAttemptTerminal(ctx, permit, committed, attempt, last.OperationID, last.IdempotencyKey); terminal != nil {
		return withResponseEvidence(terminal, last)
	}
	if scheduler.err != nil || !scheduler.ok {
		if terminal := r.preAttemptTerminal(ctx, permit, committed, attempt, last.OperationID, last.IdempotencyKey); terminal != nil {
			return withResponseEvidence(terminal, last)
		}
		return withResponseEvidence(hookConfigurationError(last.DeliveryState, last.OperationID, last.IdempotencyKey, attempt,
			ClientOptionKeyScheduler, CauseCategoryUnknown), last)
	}
	return nil
}

type schedulerResult struct {
	err error
	ok  bool
}

type entropyResult struct {
	value    int64
	ok       bool
	panicked bool
}

func classifyAttemptFailure(failure *AttemptFailure, committed bool) *Error {
	if failure == nil {
		failure = &AttemptFailure{Code: ErrorCodeIO, Committed: committed}
	}
	state := DeliveryStateNotSent
	if committed || failure.Committed {
		state = DeliveryStatePossiblySent
	}
	retryable := failure.Code == ErrorCodeDNS || failure.Code == ErrorCodeConnect || failure.Code == ErrorCodeIO || failure.Code == ErrorCodeAttemptTimeout ||
		failure.Code == ErrorCodeProxy && failure.FailureReason != FailureReasonProxyAuthRequired
	return &Error{Code: failure.Code, DeliveryState: state, Retryable: retryable, FailureReason: failure.FailureReason, CauseCategory: failure.causeCategory}
}

func (r *Runtime) setAttemptCause(err *Error) {
	if err.CauseCategory != "" {
		return
	}
	if r.ownsTransport {
		err.CauseCategory = CauseCategoryHTTPRuntime
	} else {
		err.CauseCategory = CauseCategoryCustomTransport
	}
}

func validAttemptFailure(failure *AttemptFailure) bool {
	if failure == nil {
		return false
	}
	switch failure.Code {
	case ErrorCodeConfiguration:
		return failure.causeCategory == CauseCategoryProxyCredentialProvider
	case ErrorCodeDNS, ErrorCodeConnect, ErrorCodeProxy, ErrorCodeTLS, ErrorCodeIO, ErrorCodeAttemptTimeout, ErrorCodeCancelled:
		return true
	default:
		return false
	}
}

func validIdempotencyKey(value string) bool {
	if value == "" || len(value) > 255 || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for i := range value {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func callIdempotencyGenerator(generator func() (string, error)) (value string, ok bool) {
	defer func() {
		if recover() != nil {
			value, ok = "", false
		}
	}()
	value, err := generator()
	return value, err == nil
}

func callAPIKeyProvider(ctx context.Context, provider func(context.Context) (string, error)) (value string, ok bool) {
	defer func() {
		if recover() != nil {
			value, ok = "", false
		}
	}()
	value, err := provider(ctx)
	return value, err == nil
}

func callGenerator(generator func() string) (value string, ok bool) {
	defer func() {
		if recover() != nil {
			value, ok = "", false
		}
	}()
	return generator(), true
}

func serializeOperation(schema SchemaDescriptor, model string, input any, operationNow string, generators Generators) (data *OrderedObject, panicked bool, err error) {
	defer func() {
		if recover() != nil {
			data, panicked, err = nil, true, nil
		}
	}()
	data, err = serializeModelAtUnchecked(schema.Models, schema.Enums, model, input, Generators{
		Now: func() string { return operationNow }, UUID: generators.UUID, CUID: generators.CUID,
	}, "$")
	return data, false, err
}

func callWallClock(clock func() time.Time) (value time.Time, ok bool) {
	defer func() {
		if recover() != nil {
			value, ok = time.Time{}, false
		}
	}()
	return clock(), true
}

func callMonotonicClock(clock func() int64) (value int64, ok bool) {
	defer func() {
		if recover() != nil {
			value, ok = 0, false
		}
	}()
	return clock(), true
}

func callScheduler(ctx context.Context, scheduler Scheduler, delay time.Duration) (ok bool, err error) {
	defer func() {
		if recover() != nil {
			ok, err = false, nil
		}
	}()
	return true, scheduler.Sleep(ctx, delay)
}

func boundedPermitCall[T any](ctx context.Context, permit *operationPermit, call func() T) (zero T, completed bool) {
	if ctx.Err() != nil {
		return zero, false
	}
	permit.beginCall()
	result := make(chan T, 1)
	go func() {
		value := func() T {
			defer permit.endCall()
			return call()
		}()
		result <- value
	}()
	select {
	case value := <-result:
		return value, true
	case <-ctx.Done():
		return zero, false
	}
}

func boundedAttemptCall(
	attemptDeadline, operationDeadline context.Context,
	permit *operationPermit,
	call func() AttemptOutcome,
	abandon func(AttemptOutcome),
) (zero AttemptOutcome, completed bool) {
	if operationDeadline.Err() != nil {
		return zero, false
	}
	permit.beginCall()
	result := make(chan AttemptOutcome)
	go func() { result <- call() }()
	select {
	case value := <-result:
		permit.endCall()
		return value, attemptDeadline.Err() == nil
	case <-attemptDeadline.Done():
		select {
		case value := <-result:
			permit.endCall()
			return value, false
		case <-operationDeadline.Done():
			go func() {
				abandon(<-result)
				permit.endCall()
			}()
			return zero, false
		}
	case <-operationDeadline.Done():
		go func() {
			abandon(<-result)
			permit.endCall()
		}()
		return zero, false
	}
}

func serializerOperationError(err error, operationID, key string) *Error {
	mapIssue := func(validation *serializerValidationError) ValidationIssue {
		issue := ValidationIssue{Code: ValidationIssueCodeTypeMismatch, Path: "$"}
		if validation == nil {
			return issue
		}
		issue.Path = validation.path
		switch validation.issueCode {
		case "REQUIRED_FIELD":
			issue.Code = ValidationIssueCodeRequired
		case "NULL_NOT_ALLOWED", "NULL_LIST_ELEMENT":
			issue.Code = ValidationIssueCodeNullNotAllowed
		case "TYPE_MISMATCH":
			issue.Code = ValidationIssueCodeTypeMismatch
		case "NON_FINITE_NUMBER":
			issue.Code = ValidationIssueCodeNonFinite
		case "INVALID_JSON":
			issue.Code = ValidationIssueCodeInvalidJSON
		case "CYCLE":
			issue.Code = ValidationIssueCodeCycle
		case "INVALID_UNICODE":
			issue.Code = ValidationIssueCodeInvalidUnicode
		}
		return issue
	}
	var issues []ValidationIssue
	var issueCount int
	var aggregate *serializerValidationErrors
	if errors.As(err, &aggregate) {
		issues = make([]ValidationIssue, len(aggregate.issues))
		for index, validation := range aggregate.issues {
			issues[index] = mapIssue(validation)
		}
		issueCount = aggregate.issueCount
	} else {
		var validation *serializerValidationError
		if errors.As(err, &validation) {
			issues = append(issues, mapIssue(validation))
		} else {
			issues = append(issues, mapIssue(nil))
		}
		issueCount = 1
	}
	return &Error{Code: ErrorCodeValidation, DeliveryState: DeliveryStateNotSent, OperationID: operationID,
		IdempotencyKey: key, ValidationIssues: issues, IssueCount: issueCount, IssuesTruncated: issueCount != len(issues)}
}

func sampleRetryEntropy(entropy RetryEntropy, bound int64) (value int64, ok, panicked bool) {
	defer func() {
		if recover() != nil {
			value, ok, panicked = 0, false, true
		}
	}()
	value = entropy.NextInt64(bound)
	return value, value >= 0 && value < bound, false
}

func hookConfigurationError(state DeliveryState, operationID, key string, attempts int, option ClientOptionKey, cause CauseCategory) *Error {
	return &Error{Code: ErrorCodeConfiguration, DeliveryState: state, OperationID: operationID, IdempotencyKey: key,
		AttemptCount: attempts, CauseCategory: cause, IssueCount: 1, ConfigurationIssues: []ConfigurationIssue{{
			Code: ConfigurationIssueCodeInvalidValue, OptionKeys: []ClientOptionKey{option},
		}}}
}

func preCommitFailure(code ErrorCode) bool {
	return code == ErrorCodeDNS || code == ErrorCodeConnect || code == ErrorCodeProxy || code == ErrorCodeTLS
}

func responseMayHaveBeenAccepted(status int) bool {
	return status >= 200 && status < 300 || status == statusConflict || status >= 500
}

func validOperationID(value string) bool {
	if len(value) != 39 || !strings.HasPrefix(value, "op_") {
		return false
	}
	for i, b := range value[3:] {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if b != '-' {
				return false
			}
		} else if b < '0' || b > '9' && b < 'a' || b > 'f' {
			return false
		}
	}
	return value[17] == '4' && (value[22] == '8' || value[22] == '9' || value[22] == 'a' || value[22] == 'b')
}

func operationUserAgent(suffix string) string {
	if suffix == "" {
		return "repost-client-go/" + Version
	}
	return "repost-client-go/" + Version + " " + suffix
}
