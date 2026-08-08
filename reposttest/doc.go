// Package reposttest provides deterministic, no-network controls for Repost
// client tests. Injecting ScriptedTransport is the network guard: Go needs no
// process-wide interception because every runtime attempt uses its Transport.
package reposttest
