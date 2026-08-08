// Package proxyconnect establishes explicit, challenge-driven HTTP CONNECT
// tunnels without consulting ambient proxy configuration.
package proxyconnect

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/repost-sh/repost-go/internal/wirelimits"
)

const maxHeaderLineBytes = 8_192

// Credentials are resolved only after a 407 challenge.
type Credentials struct {
	Username string
	Password string
}

// CredentialsProvider supplies proxy credentials after a challenge.
type CredentialsProvider func(context.Context) (Credentials, error)

// DialFunc opens one fresh connection to the configured proxy.
type DialFunc func(context.Context) (net.Conn, error)

// FailureKind is safe to map into the public transport error catalog.
type FailureKind uint8

// CONNECT failure kinds.
const (
	FailureConnect FailureKind = iota + 1
	FailureAuthRequired
	FailureCredentials
)

// Failure contains no proxy response or credential text.
type Failure struct{ Kind FailureKind }

func (f *Failure) Error() string { return "proxy CONNECT failed" }

// Connect establishes a tunnel. The first request never carries credentials;
// after a 407, one fresh connection carries Basic authentication.
func Connect(ctx context.Context, authority string, dial DialFunc, provider CredentialsProvider) (net.Conn, *Failure) {
	connection, status, failure := connectOnce(ctx, authority, dial, "")
	if failure != nil {
		return nil, failure
	}
	if status == 200 {
		return connection, nil
	}
	_ = connection.Close()
	if status != 407 {
		return nil, &Failure{Kind: FailureConnect}
	}
	if provider == nil {
		return nil, &Failure{Kind: FailureAuthRequired}
	}
	credentials, ok := callProvider(ctx, provider)
	if !ok {
		return nil, &Failure{Kind: FailureCredentials}
	}
	token := base64.StdEncoding.EncodeToString([]byte(credentials.Username + ":" + credentials.Password))
	connection, status, failure = connectOnce(ctx, authority, dial, token)
	if failure != nil {
		return nil, failure
	}
	if status == 200 {
		return connection, nil
	}
	_ = connection.Close()
	if status == 407 {
		return nil, &Failure{Kind: FailureAuthRequired}
	}
	return nil, &Failure{Kind: FailureConnect}
}

func connectOnce(ctx context.Context, authority string, dial DialFunc, authorization string) (net.Conn, int, *Failure) {
	if err := ctx.Err(); err != nil {
		return nil, 0, &Failure{Kind: FailureConnect}
	}
	connection, err := dial(ctx)
	if err != nil {
		return nil, 0, &Failure{Kind: FailureConnect}
	}
	canceled := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.Close()
		close(canceled)
	})
	defer stopCancellation()
	request := "CONNECT " + authority + " HTTP/1.1\r\nhost: " + authority + "\r\n"
	if authorization != "" {
		request += "proxy-authorization: Basic " + authorization + "\r\n"
	}
	request += "\r\n"
	if err := writeAll(connection, []byte(request)); err != nil {
		_ = connection.Close()
		return nil, 0, &Failure{Kind: FailureConnect}
	}
	reader := bufio.NewReaderSize(connection, maxHeaderLineBytes+2)
	status, err := readResponseHead(reader)
	if err != nil {
		_ = connection.Close()
		return nil, 0, &Failure{Kind: FailureConnect}
	}
	if !stopCancellation() {
		<-canceled
		return nil, 0, &Failure{Kind: FailureConnect}
	}
	return &bufferedConn{Conn: connection, reader: reader}, status, nil
}

func readResponseHead(reader *bufio.Reader) (int, error) {
	total := 0
	statusLine, err := readLine(reader, &total)
	if err != nil {
		return 0, err
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || parts[0] != "HTTP/1.1" {
		return 0, errors.New("invalid proxy status")
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil || status < 100 || status > 999 {
		return 0, errors.New("invalid proxy status")
	}
	for fields := 0; ; fields++ {
		line, lineErr := readLine(reader, &total)
		if lineErr != nil {
			return 0, lineErr
		}
		if line == "" {
			return status, nil
		}
		if fields >= wirelimits.HeaderFields || !strings.Contains(line, ":") {
			return 0, errors.New("invalid proxy headers")
		}
	}
}

func readLine(reader *bufio.Reader, total *int) (string, error) {
	line, err := reader.ReadString('\n')
	*total += len(line)
	if err != nil || len(line) > maxHeaderLineBytes || *total > wirelimits.HeaderBytes || !strings.HasSuffix(line, "\r\n") {
		return "", errors.New("invalid proxy headers")
	}
	return strings.TrimSuffix(line, "\r\n"), nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func callProvider(ctx context.Context, provider CredentialsProvider) (credentials Credentials, ok bool) {
	defer func() {
		if recover() != nil {
			credentials, ok = Credentials{}, false
		}
	}()
	credentials, err := provider(ctx)
	return credentials, err == nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(data []byte) (int, error) {
	return c.reader.Read(data)
}
