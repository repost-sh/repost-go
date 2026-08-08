# repost-go

Official Repost client SDK runtime for Go. The Repost CLI generates typed
models and webhook methods from your `.repost` schema; this module provides
validation, serialization, retries, idempotency, HTTP/1.1 and HTTP/2 transport,
delivery outcomes, and lifecycle management.

The SDK requires Go 1.25 or later. It is for trusted server-side code only
because it carries an environment-scoped publish credential.

## Install and generate

```bash
go get github.com/repost-sh/repost-go
repost schema init --language go --output ../internal/repostclient
repost schema migrate dev --name init
```

The output path is relative to `repost/schema.repost`. Commit the generated
package with the schema migration that produced it. Use
`repost schema generate --check` in CI to detect drift.

## Send an event

```go
client, err := repostclient.NewClient(repost.ClientOptions{})
if err != nil {
    return err
}
defer client.Close()

result, err := client.Webhooks.Order.Created(ctx, repostclient.OrderCreatedInput{
    CustomerID:     "customer_123",
    Data:           repostclient.Order{ID: "order_1001"},
    IdempotencyKey: "order_1001:created",
})
if err != nil {
    return err
}
log.Printf("accepted message %s", result.ID)
```

Set `REPOST_SEND_API_KEY` in the process environment, or pass `APIKey` or
`APIKeyProvider` in `ClientOptions`. Create one client for each application
process and close it during graceful shutdown. The client is safe for
concurrent sends and owns bounded connection pools and observer state.

## Testing

The `reposttest` package provides a no-network scripted transport, fixed and
sequenced generators, a manual clock and scheduler, retry entropy, and a
recording observer:

```go
transport := reposttest.NewScriptedTransport().EnqueueResponse(
    202,
    acceptedBody,
    [2]string{"content-type", "application/json"},
)
client, err := repostclient.NewClient(repost.ClientOptions{
    APIKey:    "test-key",
    Transport: transport,
})
```

Recorded requests contain the serialized body and idempotency key but never
the authorization credential.

## OpenTelemetry

OpenTelemetry integration is isolated in its own module and release tag:

```bash
go get github.com/repost-sh/repost-go/otel
```

```go
client, err := repostclient.NewClient(repost.ClientOptions{
    Telemetry: otelrepost.Telemetry(),
    Observer:  otelrepost.MetricsObserver(),
})
```

See the [Go client documentation](https://repost.sh/docs/send/go/quickstart)
for generation, configuration, reliability, testing, observability, framework
integration, and security guidance.

> **Read-only mirror.** Source of truth is the Repost monorepo. This repository
> is synced and tagged automatically for each release. Please do not open pull
> requests here.
