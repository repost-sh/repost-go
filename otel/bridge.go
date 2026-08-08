// Package otelrepost adapts Repost telemetry and observer records to OpenTelemetry.
package otelrepost

import (
	"context"
	"strings"
	"time"

	"github.com/repost-sh/repost-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	scopeName    = "github.com/repost-sh/repost-go/otel"
	scopeVersion = repost.Version

	operationSpanName = "repost.send"
	attemptSpanName   = "repost.send.attempt"

	httpMethodKey      = "http.request.method"
	retryAttemptKey    = "repost.retry.attempt"
	networkProtocolKey = "network.protocol.name"
	httpStatusKey      = "http.response.status_code"
	errorTypeKey       = "error.type"

	operationsName        = "repost.client.operations"
	operationDurationName = "repost.client.operation.duration"
	attemptsName          = "repost.client.attempts"
	attemptDurationName   = "repost.client.attempt.duration"
	retryDelayName        = "repost.client.retry.delay"

	outcomeKey         = "outcome"
	errorCodeKey       = "error.code"
	deliveryStateKey   = "delivery.state"
	httpStatusClassKey = "http.status.class"
)

// Option configures a bridge. Providers are borrowed and are never shut down.
type Option func(*options)

type options struct {
	tracerProvider trace.TracerProvider
	meterProvider  metric.MeterProvider
}

// WithTracerProvider uses provider instead of the global tracer provider.
func WithTracerProvider(provider trace.TracerProvider) Option {
	return func(options *options) { options.tracerProvider = provider }
}

// WithMeterProvider uses provider instead of the global meter provider.
func WithMeterProvider(provider metric.MeterProvider) Option {
	return func(options *options) { options.meterProvider = provider }
}

// Telemetry returns a live Repost tracing bridge.
func Telemetry(opts ...Option) repost.Telemetry {
	config := options{tracerProvider: otel.GetTracerProvider()}
	for _, option := range opts {
		option(&config)
	}
	return tracingBridge{tracer: config.tracerProvider.Tracer(scopeName, trace.WithInstrumentationVersion(scopeVersion))}
}

type tracingBridge struct{ tracer trace.Tracer }

func (bridge tracingBridge) CaptureContext(ctx context.Context) context.Context { return ctx }

func (bridge tracingBridge) StartOperation(ctx context.Context, _ repost.TelemetryOperationStart) repost.TelemetryOperation {
	startedAt := time.Now()
	ctx, span := bridge.tracer.Start(ctx, operationSpanName,
		trace.WithSpanKind(trace.SpanKindInternal), trace.WithTimestamp(startedAt))
	return operation{tracer: bridge.tracer, ctx: ctx, span: span, startedAt: startedAt}
}

type operation struct {
	tracer    trace.Tracer
	ctx       context.Context
	span      trace.Span
	startedAt time.Time
}

func (operation operation) Context() context.Context { return operation.ctx }

func (operation operation) StartAttempt(start repost.TelemetryAttemptStart) repost.TelemetryAttempt {
	startedAt := time.Now()
	ctx, span := operation.tracer.Start(operation.ctx, attemptSpanName,
		trace.WithSpanKind(trace.SpanKindInternal), trace.WithTimestamp(startedAt),
		trace.WithAttributes(
			attribute.String(httpMethodKey, "POST"),
			attribute.Int(retryAttemptKey, start.AttemptNumber),
			attribute.String(networkProtocolKey, "http"),
		))
	return attempt{ctx: ctx, span: span, startedAt: startedAt}
}

func (operation operation) End(end repost.TelemetryOperationEnd) {
	setError(operation.span, end.Outcome, end.ErrorCode)
	operation.span.End(trace.WithTimestamp(operation.startedAt.Add(end.Duration)))
}

type attempt struct {
	ctx       context.Context
	span      trace.Span
	startedAt time.Time
}

func (attempt attempt) PropagationHeaders() [][2]string {
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(attempt.ctx, carrier)
	if carrier["traceparent"] == "" {
		return nil
	}
	headers := [][2]string{{"traceparent", carrier["traceparent"]}}
	if carrier["tracestate"] != "" {
		headers = append(headers, [2]string{"tracestate", carrier["tracestate"]})
	}
	return headers
}

func (attempt attempt) End(end repost.TelemetryAttemptEnd) {
	if end.HTTPStatusClass == repost.HTTPStatusClassSuccess {
		attempt.span.SetAttributes(attribute.Int(httpStatusKey, 202))
	}
	setError(attempt.span, end.Outcome, end.ErrorCode)
	attempt.span.End(trace.WithTimestamp(attempt.startedAt.Add(end.Duration)))
}

func setError(span trace.Span, outcome repost.ObserverOutcome, errorCode repost.ErrorCode) {
	if errorCode != "" {
		span.SetAttributes(attribute.String(errorTypeKey, strings.ToLower(string(errorCode))))
	}
	if outcome != repost.ObserverOutcomeAccepted {
		span.SetStatus(codes.Error, "")
	}
}

// MetricsObserver returns a stateless observer that records bounded Repost metrics.
func MetricsObserver(opts ...Option) repost.Observer {
	config := options{meterProvider: otel.GetMeterProvider()}
	for _, option := range opts {
		option(&config)
	}
	meter := config.meterProvider.Meter(scopeName, metric.WithInstrumentationVersion(scopeVersion))
	operations, err := meter.Int64Counter(operationsName,
		metric.WithDescription("Completed Repost client operations"), metric.WithUnit("operations"))
	if err != nil {
		panic(err)
	}
	operationDuration, err := meter.Float64Histogram(operationDurationName,
		metric.WithDescription("Repost client operation duration"), metric.WithUnit("ms"))
	if err != nil {
		panic(err)
	}
	attempts, err := meter.Int64Counter(attemptsName,
		metric.WithDescription("Completed Repost client transport attempts"), metric.WithUnit("attempts"))
	if err != nil {
		panic(err)
	}
	attemptDuration, err := meter.Float64Histogram(attemptDurationName,
		metric.WithDescription("Repost client transport-attempt duration"), metric.WithUnit("ms"))
	if err != nil {
		panic(err)
	}
	retryDelay, err := meter.Float64Histogram(retryDelayName,
		metric.WithDescription("Scheduled Repost client retry delay"), metric.WithUnit("ms"))
	if err != nil {
		panic(err)
	}

	return func(event repost.ObserverEvent) {
		switch event.Kind {
		case repost.ObserverEventKindRetryDelay:
			retryDelay.Record(context.Background(), milliseconds(event.RetryDelay), metric.WithAttributes(metricAttributes(
				repost.ObserverOutcomeRetryableFailure, event.ErrorCode, event.DeliveryState, event.HTTPStatusClass)...))
		case repost.ObserverEventKindOperationEnd:
			attrs := metric.WithAttributes(metricAttributes(event.Outcome, event.ErrorCode, event.DeliveryState, event.HTTPStatusClass)...)
			operations.Add(context.Background(), 1, attrs)
			operationDuration.Record(context.Background(), milliseconds(event.Duration), attrs)
			for _, summary := range event.AttemptSummaries {
				attrs := metric.WithAttributes(metricAttributes(summary.Outcome, summary.ErrorCode, summary.DeliveryState, summary.HTTPStatusClass)...)
				attempts.Add(context.Background(), 1, attrs)
				attemptDuration.Record(context.Background(), milliseconds(summary.Duration), attrs)
			}
		}
	}
}

func metricAttributes(outcome repost.ObserverOutcome, errorCode repost.ErrorCode, deliveryState repost.DeliveryState, status repost.HTTPStatusClass) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(outcomeKey, metricValue(string(outcome))),
		attribute.String(errorCodeKey, metricValue(string(errorCode))),
		attribute.String(deliveryStateKey, metricValue(string(deliveryState))),
		attribute.String(httpStatusClassKey, metricValue(string(status))),
	}
}

func metricValue(value string) string {
	if value == "" {
		return "none"
	}
	return strings.ToLower(value)
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
