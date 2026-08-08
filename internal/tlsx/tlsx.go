// Package tlsx builds the bounded TLS configuration and connection used by
// the raw transport. It never consults proxy environment variables.
package tlsx

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"hash"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ClientCertificate contains one PEM certificate chain and private key.
type ClientCertificate struct {
	CertificatePEM []byte
	KeyPEM         []byte
	Passphrase     []byte
}

// Config is the transport-owned input to BuildConfig.
type Config struct {
	CACertificatesPEM [][]byte
	MinVersion        uint16
	MaxVersion        uint16
	Ciphers           []uint16
	ClientCertificate *ClientCertificate
	ServerName        string
	HTTP2             bool
}

// Resolver resolves a host for each new connection. Results are not cached.
type Resolver func(context.Context, string) ([]netip.Addr, error)

// BuildConfig validates and snapshots TLS policy. Custom roots replace the
// system pool rather than extending it.
func BuildConfig(input *Config) (*tls.Config, error) {
	if input == nil {
		return nil, errors.New("missing TLS configuration")
	}
	minimum := input.MinVersion
	if minimum == 0 {
		minimum = tls.VersionTLS12
	}
	if !supportedVersion(minimum) || input.MaxVersion != 0 && !supportedVersion(input.MaxVersion) {
		return nil, errors.New("unsupported TLS version")
	}
	if input.MaxVersion != 0 && minimum > input.MaxVersion {
		return nil, errors.New("TLS minimum exceeds maximum")
	}

	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   input.MaxVersion,
		CipherSuites: append([]uint16(nil), input.Ciphers...),
		ServerName:   input.ServerName,
		NextProtos:   []string{"http/1.1"},
	}
	if minimum == tls.VersionTLS13 {
		config.MinVersion = tls.VersionTLS13
	}
	if input.HTTP2 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}
	if input.CACertificatesPEM != nil {
		if len(input.CACertificatesPEM) == 0 {
			return nil, errors.New("custom CA set is empty")
		}
		roots := x509.NewCertPool()
		for _, certificates := range input.CACertificatesPEM {
			if len(certificates) == 0 || !roots.AppendCertsFromPEM(certificates) {
				return nil, errors.New("invalid CA certificate PEM")
			}
		}
		config.RootCAs = roots
	}
	if input.ClientCertificate != nil {
		certificate, err := loadClientCertificate(*input.ClientCertificate)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

func supportedVersion(version uint16) bool {
	return version == tls.VersionTLS12 || version == tls.VersionTLS13
}

func loadClientCertificate(input ClientCertificate) (tls.Certificate, error) {
	if len(input.CertificatePEM) == 0 || len(input.KeyPEM) == 0 {
		return tls.Certificate{}, errors.New("incomplete client certificate")
	}
	keyPEM := input.KeyPEM
	block, rest := pem.Decode(input.KeyPEM)
	if block == nil || len(rest) != 0 {
		return tls.Certificate{}, errors.New("invalid client key PEM")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		if len(input.Passphrase) == 0 {
			return tls.Certificate{}, errors.New("encrypted client key requires passphrase")
		}
		decrypted, err := decryptPKCS8(block.Bytes, input.Passphrase)
		if err != nil {
			return tls.Certificate{}, errors.New("invalid encrypted client key")
		}
		defer clear(decrypted)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: decrypted})
		defer clear(keyPEM)
	} else if legacyEncryptedPEM(block) {
		return tls.Certificate{}, errors.New("legacy encrypted client keys are unsupported")
	}
	certificate, err := tls.X509KeyPair(input.CertificatePEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, errors.New("invalid client certificate")
	}
	return certificate, nil
}

func legacyEncryptedPEM(block *pem.Block) bool {
	return strings.EqualFold(strings.ReplaceAll(block.Headers["Proc-Type"], " ", ""), "4,ENCRYPTED") || block.Headers["DEK-Info"] != ""
}

var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm algorithmIdentifier
	EncryptedData       []byte
}

type pbes2Parameters struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type pbkdf2Parameters struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                 `asn1:"optional"`
	PRF            algorithmIdentifier `asn1:"optional"`
}

func decryptPKCS8(data, passphrase []byte) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(data, &info); err != nil || len(rest) != 0 || !info.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("unsupported encrypted private key")
	}
	var pbes2 pbes2Parameters
	if rest, err := asn1.Unmarshal(info.EncryptionAlgorithm.Parameters.FullBytes, &pbes2); err != nil || len(rest) != 0 || !pbes2.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("invalid PBES2 parameters")
	}
	var derivation pbkdf2Parameters
	if rest, err := asn1.Unmarshal(pbes2.KeyDerivationFunc.Parameters.FullBytes, &derivation); err != nil || len(rest) != 0 ||
		len(derivation.Salt) == 0 || len(derivation.Salt) > 1024 || derivation.IterationCount < 1 || derivation.IterationCount > 10_000_000 {
		return nil, errors.New("invalid PBKDF2 parameters")
	}
	keyBytes, err := aesKeyBytes(pbes2.EncryptionScheme.Algorithm)
	if err != nil || derivation.KeyLength != 0 && derivation.KeyLength != keyBytes {
		return nil, errors.New("unsupported PBES2 cipher")
	}
	hashFactory, err := pbkdf2Hash(derivation.PRF.Algorithm)
	if err != nil {
		return nil, err
	}
	var iv []byte
	if rest, unmarshalErr := asn1.Unmarshal(pbes2.EncryptionScheme.Parameters.FullBytes, &iv); unmarshalErr != nil || len(rest) != 0 || len(iv) != aes.BlockSize || len(info.EncryptedData) == 0 || len(info.EncryptedData)%aes.BlockSize != 0 {
		return nil, errors.New("invalid PBES2 ciphertext")
	}
	key, err := pbkdf2.Key(hashFactory, string(passphrase), derivation.Salt, derivation.IterationCount, keyBytes)
	if err != nil {
		return nil, errors.New("invalid PBKDF2 parameters")
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := append([]byte(nil), info.EncryptedData...)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, plaintext)
	padding := int(plaintext[len(plaintext)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plaintext) {
		clear(plaintext)
		return nil, errors.New("invalid PBES2 padding")
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			clear(plaintext)
			return nil, errors.New("invalid PBES2 padding")
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}

func aesKeyBytes(oid asn1.ObjectIdentifier) (int, error) {
	switch {
	case oid.Equal(oidAES128CBC):
		return 16, nil
	case oid.Equal(oidAES192CBC):
		return 24, nil
	case oid.Equal(oidAES256CBC):
		return 32, nil
	default:
		return 0, errors.New("unsupported PBES2 cipher")
	}
}

func pbkdf2Hash(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case oid.Equal(oidHMACWithSHA256):
		return sha256.New, nil
	case oid.Equal(oidHMACWithSHA384):
		return sha512.New384, nil
	case oid.Equal(oidHMACWithSHA512):
		return sha512.New, nil
	default:
		return nil, errors.New("unsupported PBKDF2 hash")
	}
}

// DialTLS resolves and connects under one total connect budget, then performs
// the TLS handshake with the same context.
func DialTLS(ctx context.Context, address string, timeout time.Duration, resolver Resolver, config *tls.Config) (*tls.Conn, error) {
	connectContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := DialTCP(connectContext, address, timeout, resolver)
	if err != nil {
		return nil, err
	}
	tlsConnection, err := Client(connectContext, connection, config)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return tlsConnection, nil
}

// DialTCP resolves and connects under one total connect budget.
func DialTCP(ctx context.Context, address string, timeout time.Duration, resolver Resolver) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	connectContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &net.Dialer{}
	if resolver == nil {
		if _, parseErr := netip.ParseAddr(host); parseErr != nil {
			return dialer.DialContext(connectContext, "tcp", address)
		}
	}

	addresses, err := resolve(connectContext, host, resolver)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}

	return dialResolved(connectContext, port, addresses, dialer.DialContext)
}

func dialResolved(ctx context.Context, port string, addresses []netip.Addr, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	dialContext, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		connection net.Conn
		err        error
	}
	results := make(chan result, len(addresses))
	for _, address := range addresses {
		go func() {
			connection, err := dial(dialContext, "tcp", net.JoinHostPort(address.String(), port))
			results <- result{connection: connection, err: err}
		}()
	}
	var winner net.Conn
	var lastErr error
	for range addresses {
		current := <-results
		if current.connection != nil {
			if winner == nil {
				winner = current.connection
				cancel()
			} else {
				_ = current.connection.Close()
			}
		} else if current.err != nil {
			lastErr = current.err
		}
	}
	if winner != nil {
		return winner, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, lastErr
}

// Client performs a TLS handshake over an established direct or CONNECT
// tunnel connection.
func Client(ctx context.Context, connection net.Conn, config *tls.Config) (*tls.Conn, error) {
	tlsConnection := tls.Client(connection, config.Clone())
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConnection, nil
}

func resolve(ctx context.Context, host string, resolver Resolver) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{address}, nil
	}
	if resolver != nil {
		return resolver(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
