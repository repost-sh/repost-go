package repost

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/repost-sh/repost-go/internal/strictjson"
)

var messageIDPattern = regexp.MustCompile(`^msg_[A-Za-z0-9_-]{1,124}$`)

func validateAttemptResponse(response *AttemptResponse, sentType, customerID, timestamp string) (*SendResult, *Error) {
	base := &Error{HTTPStatus: response.Status, CompressedBytes: response.CompressedBytes,
		DecompressedBytes: response.DecompressedBytes, Truncated: response.Truncated}
	if response.attemptFailureCode != "" {
		base.Code, base.DeliveryState, base.Retryable = response.attemptFailureCode, DeliveryStatePossiblySent, true
		base.FailureReason = response.attemptFailureReason
		return nil, base
	}
	if response.headerLimitViolation {
		base.ResponseHeaderFields, base.ResponseHeaderBytes = headerCounts(response.Headers)
	}
	if response.Status < 200 || response.Status >= 300 {
		base.DeliveryState = DeliveryStatePossiblySent
		base.Retryable = responseStatusRetryable(response.Status)
		switch {
		case response.Status >= 300 && response.Status < 400:
			base.Code, base.DeliveryState = ErrorCodeHTTPRejected, DeliveryStateRejected
		case response.Status == statusProxyAuthRequired:
			base.Code, base.DeliveryState, base.FailureReason = ErrorCodeProxy, DeliveryStateNotSent, FailureReasonProxyAuthRequired
		case response.Status == statusTooManyRequests:
			base.Code, base.DeliveryState = ErrorCodeRateLimited, DeliveryStateRejected
		case response.Status == statusConflict:
			base.Code = ErrorCodeHTTPRejected
		case response.Status >= 500:
			base.Code = ErrorCodeServerFailure
		default:
			base.Code, base.DeliveryState = ErrorCodeHTTPRejected, DeliveryStateRejected
		}
		if response.retryForbidden {
			base.Retryable = false
		}
		return nil, base
	}
	base.Code, base.DeliveryState, base.Retryable = ErrorCodeResponseProtocol, DeliveryStatePossiblySent, responseStatusRetryable(response.Status)
	if response.limitViolation || !response.normalized && !response.protocolViolation && responseExceedsLimits(response) {
		base.Code, base.Retryable = ErrorCodeResponseTooLarge, false
		return nil, base
	}
	if response.protocolViolation {
		base.Retryable = false
		return nil, base
	}
	if response.Truncated && !response.incomplete {
		base.Code, base.Retryable = ErrorCodeResponseTooLarge, false
		return nil, base
	}
	if !validJSONContentType(response.Headers) || len(response.Body) == 0 || !utf8.Valid(response.Body) {
		return nil, base
	}
	result, jsonErr := decodeSendResult(response.Body)
	if jsonErr != nil {
		if jsonErr.Kind == strictjson.FailureLimit {
			base.Code, base.Retryable = ErrorCodeResponseTooLarge, false
		}
		return nil, base
	}
	if !messageIDPattern.MatchString(result.ID) || result.Type != sentType || result.CustomerID != customerID || result.Timestamp != timestamp {
		return nil, base
	}
	return result, nil
}

func validJSONContentType(headers []HeaderField) bool {
	values := headerValues(headers, "content-type")
	if len(values) != 1 {
		return false
	}
	value := values[0]
	for i := range value {
		if value[i] != '\t' && (value[i] < 0x20 || value[i] > 0x7e) {
			return false
		}
	}
	mediaType, parameter, hasParameter := strings.Cut(trimOWS(value), ";")
	if !strings.EqualFold(trimOWS(mediaType), "application/json") {
		return false
	}
	if !hasParameter {
		return true
	}
	if strings.Contains(parameter, ";") {
		return false
	}
	name, charset, ok := strings.Cut(parameter, "=")
	if !ok || !strings.EqualFold(trimOWS(name), "charset") {
		return false
	}
	charset = trimOWS(charset)
	if len(charset) >= 2 && charset[0] == '"' && charset[len(charset)-1] == '"' {
		charset = charset[1 : len(charset)-1]
	}
	return strings.EqualFold(charset, "utf-8")
}

func trimOWS(value string) string { return strings.Trim(value, " \t") }

func decodeSendResult(body []byte) (*SendResult, *strictjson.Error) {
	decoded, err := strictjson.Parse(body)
	if err != nil {
		return nil, err
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, &strictjson.Error{Kind: strictjson.FailureProtocol}
	}
	stringField := func(name string) (string, bool) {
		value, present := object[name]
		text, valid := value.(string)
		return text, present && valid
	}
	id, idOK := stringField("id")
	eventType, typeOK := stringField("type")
	customerID, customerOK := stringField("customerId")
	timestamp, timestampOK := stringField("timestamp")
	if !idOK || !typeOK || !customerOK || !timestampOK {
		return nil, &strictjson.Error{Kind: strictjson.FailureProtocol}
	}
	return &SendResult{ID: id, Type: eventType, CustomerID: customerID, Timestamp: timestamp}, nil
}

func parseRetryAfterHeaders(headers []HeaderField, wallNow time.Time) (time.Duration, bool) {
	value, ok := retryAfterValue(headers)
	if !ok {
		return 0, false
	}
	delay, valid, needsWall := parseRetryAfterDelta(value)
	if !needsWall {
		return delay, valid
	}
	return parseRetryAfterDate(value, wallNow)
}

func retryAfterValue(headers []HeaderField) (string, bool) {
	values := headerValues(headers, "retry-after")
	if len(values) == 0 || values[0] == "" {
		return "", false
	}
	for _, value := range values[1:] {
		if value != values[0] {
			return "", false
		}
	}
	return values[0], true
}

func responseNeedsWallSnapshot(headers []HeaderField) bool {
	value, ok := retryAfterValue(headers)
	if !ok {
		return false
	}
	_, _, needsWall := parseRetryAfterDelta(value)
	if !needsWall {
		return false
	}
	date, err := time.Parse(httpDateLayout, value)
	return err == nil && date.UTC().Format(httpDateLayout) == value
}

func responseNeedsWallSnapshotForStatus(status int, headers []HeaderField) bool {
	return responseStatusRetryable(status) && responseNeedsWallSnapshot(headers)
}

func responseStatusRetryable(status int) bool {
	return status >= 200 && status < 300 || status == statusConflict || status == statusTooManyRequests || status >= 500 && status <= 599
}

func snapshotResponseWallTime(request *AttemptRequest, status int, headers []HeaderField) (at time.Time, set, failed bool) {
	if !responseNeedsWallSnapshotForStatus(status, headers) {
		return time.Time{}, false, false
	}
	if request != nil && request.SnapshotResponseWallTime != nil {
		at, set = request.SnapshotResponseWallTime()
	}
	return at, set, !set
}

func parseRetryAfterDelta(value string) (delay time.Duration, valid, needsWall bool) {
	allDigits := value != ""
	for i := range value {
		allDigits = allDigits && value[i] >= '0' && value[i] <= '9'
	}
	if !allDigits {
		return 0, false, true
	}
	if seconds, err := strconv.ParseUint(value, 10, 63); err == nil {
		if seconds == 0 || seconds > uint64((time.Duration(1<<63-1))/time.Second) {
			return 0, false, false
		}
		return time.Duration(seconds) * time.Second, true, false
	}
	return 0, false, false
}

func parseRetryAfterDate(value string, wallNow time.Time) (time.Duration, bool) {
	date, err := time.Parse(httpDateLayout, value)
	if err != nil || date.UTC().Format(httpDateLayout) != value || !date.After(wallNow) {
		return 0, false
	}
	delay := date.Sub(wallNow)
	return delay, delay > 0
}

func headerValues(headers []HeaderField, name string) []string {
	values := make([]string, 0, 1)
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			values = append(values, strings.Trim(header.Value, " \t"))
		}
	}
	return values
}

func headerCounts(headers []HeaderField) (fields int, bytes int64) {
	for _, header := range headers {
		bytes += int64(len(header.Name) + 2 + len(header.Value) + 2)
	}
	return len(headers), bytes
}
