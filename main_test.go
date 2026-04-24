package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// mockSMTPBackend implements the SMTP backend interface for testing
type mockSMTPBackend struct{}

func (b *mockSMTPBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &mockSMTPSession{}, nil
}

type mockSMTPSession struct{}

func (s *mockSMTPSession) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *mockSMTPSession) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		return nil // Accept any credentials for testing
	}), nil
}

func (s *mockSMTPSession) Mail(from string, opts *smtp.MailOptions) error {
	return nil
}

func (s *mockSMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	return nil
}

func (s *mockSMTPSession) Data(r io.Reader) error {
	// Read and discard the data
	io.Copy(io.Discard, r)
	return nil
}

func (s *mockSMTPSession) Reset() {}

func (s *mockSMTPSession) Logout() error {
	return nil
}

func generateSelfSignedCert() (*tls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "mock.example.com",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
	return &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Accept any SNI and return the same certificate
			return &cert, nil
		},
	}, nil
}

func TestSMTPProxy_EndToEnd(t *testing.T) {
	// Generate TLS config for mock server
	mockTLSConfig, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	// Start mock upstream SMTP server using go-smtp library
	mockBackend := &mockSMTPBackend{}
	mockServer := smtp.NewServer(mockBackend)
	mockServer.Addr = "127.0.0.1:2525"
	mockServer.Domain = "mock.example.com"
	mockServer.AllowInsecureAuth = true
	mockServer.TLSConfig = mockTLSConfig

	go func() {
		if err := mockServer.ListenAndServe(); err != nil {
			t.Logf("mock server error: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond) // Wait for mock server to start

	defer mockServer.Close()

	// Mock DNS resolver: always return 127.0.0.1 for any host
	mockLookupA := func(ctx context.Context, host string) (net.IP, error) {
		return net.ParseIP("127.0.0.1"), nil
	}

	// Mock SMTP dialer: connect to our mock SMTP server (on port 2525)
	mockDialer := func(addr string, tlsConfig *tls.Config) (*smtp.Client, error) {
		// Accept both IPv4 and IPv6 loopback
		if addr == "127.0.0.1:587" || addr == "[::1]:587" {
			// Connect to mock server with STARTTLS
			clientTLSConfig := &tls.Config{InsecureSkipVerify: true}
			return smtp.DialStartTLS("127.0.0.1:2525", clientTLSConfig)
		}
		return nil, &net.AddrError{Err: "unexpected addr", Addr: addr}
	}

	// Start the proxy server (on a test port, IPv4 only)
	proxyBackend := &backend{
		lookupA:          mockLookupA,
		smtpDialStartTLS: mockDialer,
	}
	proxyServer := smtp.NewServer(proxyBackend)
	proxyServer.Addr = "127.0.0.1:2587"
	proxyServer.Domain = "127.0.0.1"
	proxyServer.AllowInsecureAuth = true
	// Use generateTLSConfig() to properly handle SNI and store it
	proxyServer.TLSConfig = generateTLSConfig()

	go func() {
		if err := proxyServer.ListenAndServe(); err != nil {
			t.Logf("proxy server error: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond) // Wait for proxy to start

	defer proxyServer.Close()

	// Connect to the proxy as a client (IPv4 only)
	// Use a hostname for ServerName since SNI isn't sent for IP addresses
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "test.example.com",
	}
	client, err := smtp.DialStartTLS("127.0.0.1:2587", tlsConfig)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer client.Quit()

	if err := client.Auth(sasl.NewPlainClient("", "user@example.com", "secret")); err != nil {
		t.Fatalf("AUTH failed: %v", err)
	}

	// Send MAIL FROM, RCPT TO, DATA
	if err := client.Mail("from@example.com", nil); err != nil {
		t.Fatalf("MAIL failed: %v", err)
	}
	if err := client.Rcpt("to@example.com", nil); err != nil {
		t.Fatalf("RCPT failed: %v", err)
	}
	w, err := client.Data()
	if err != nil {
		t.Fatalf("DATA failed: %v", err)
	}
	if _, err := w.Write([]byte("Test message body")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	t.Log("Test passed successfully!")
}

func TestSessionConnectRequiresSNI(t *testing.T) {
	s := &session{addr: "127.0.0.1:1111"}
	if err := s.connect(); err == nil || !strings.Contains(err.Error(), "SNI required") {
		t.Fatalf("expected SNI required error, got: %v", err)
	}
}

func TestSessionConnectHandlesLookupAndDialErrors(t *testing.T) {
	t.Run("empty SNI", func(t *testing.T) {
		addr := "127.0.0.1:2222"
		sniMap.Store(addr, "")
		t.Cleanup(func() { sniMap.Delete(addr) })

		s := &session{addr: addr}
		if err := s.connect(); err == nil || !strings.Contains(err.Error(), "SNI required") {
			t.Fatalf("expected SNI required error, got: %v", err)
		}
	})

	t.Run("lookup error", func(t *testing.T) {
		addr := "127.0.0.1:2223"
		sniMap.Store(addr, "smtp.example.com")

		expectedErr := errors.New("lookup failed")
		s := &session{
			addr: addr,
			lookupA: func(ctx context.Context, host string) (net.IP, error) {
				if host != "smtp.example.com" {
					t.Fatalf("unexpected host: %s", host)
				}
				return nil, expectedErr
			},
		}

		if err := s.connect(); !errors.Is(err, expectedErr) {
			t.Fatalf("expected lookup error %v, got: %v", expectedErr, err)
		}
	})

	t.Run("dial error", func(t *testing.T) {
		addr := "127.0.0.1:2224"
		sniMap.Store(addr, "smtp.example.com")

		expectedErr := errors.New("dial failed")
		s := &session{
			addr: addr,
			lookupA: func(ctx context.Context, host string) (net.IP, error) {
				return net.ParseIP("127.0.0.1"), nil
			},
			smtpDialStartTLS: func(addr string, tlsConfig *tls.Config) (*smtp.Client, error) {
				if addr != "127.0.0.1:587" {
					t.Fatalf("unexpected dial addr: %s", addr)
				}
				if tlsConfig == nil || tlsConfig.ServerName != "smtp.example.com" {
					t.Fatalf("unexpected tls config: %#v", tlsConfig)
				}
				return nil, expectedErr
			},
		}

		if err := s.connect(); !errors.Is(err, expectedErr) {
			t.Fatalf("expected dial error %v, got: %v", expectedErr, err)
		}
	})
}

func TestSessionMethodsReturnConnectError(t *testing.T) {
	s := &session{addr: "127.0.0.1:3333"}

	if err := s.Mail("from@example.com", nil); err == nil {
		t.Fatal("expected Mail to fail when connect fails")
	} else {
		var smtpErr *smtp.SMTPError
		if !errors.As(err, &smtpErr) {
			t.Fatalf("expected SMTPError, got: %T", err)
		}
		if smtpErr.Code != 451 {
			t.Fatalf("expected SMTP 451, got: %d", smtpErr.Code)
		}
		if strings.Contains(strings.ToLower(smtpErr.Message), "sni") {
			t.Fatalf("client-facing error leaked internal detail: %q", smtpErr.Message)
		}
	}
	if err := s.Rcpt("to@example.com", nil); err == nil {
		t.Fatal("expected Rcpt to fail when connect fails")
	} else {
		var smtpErr *smtp.SMTPError
		if !errors.As(err, &smtpErr) {
			t.Fatalf("expected SMTPError, got: %T", err)
		}
		if smtpErr.Code != 451 {
			t.Fatalf("expected SMTP 451, got: %d", smtpErr.Code)
		}
		if strings.Contains(strings.ToLower(smtpErr.Message), "sni") {
			t.Fatalf("client-facing error leaked internal detail: %q", smtpErr.Message)
		}
	}
	if err := s.Data(strings.NewReader("body")); err == nil {
		t.Fatal("expected Data to fail when connect fails")
	} else {
		var smtpErr *smtp.SMTPError
		if !errors.As(err, &smtpErr) {
			t.Fatalf("expected SMTPError, got: %T", err)
		}
		if smtpErr.Code != 451 {
			t.Fatalf("expected SMTP 451, got: %d", smtpErr.Code)
		}
		if strings.Contains(strings.ToLower(smtpErr.Message), "sni") {
			t.Fatalf("client-facing error leaked internal detail: %q", smtpErr.Message)
		}
	}
}

func TestStripHostPortFallback(t *testing.T) {
	addr := "smtp.example.com"
	if got := stripHostPort(addr); got != addr {
		t.Fatalf("expected %q, got %q", addr, got)
	}
}

func TestLookupAInvalidHost(t *testing.T) {
	if _, err := lookupA(context.Background(), "bad host"); err == nil {
		t.Fatal("expected invalid host error")
	}
}

func TestGenerateTLSConfigEmptySNI(t *testing.T) {
	tlsConfig := generateTLSConfig()
	if tlsConfig.GetConfigForClient == nil {
		t.Fatal("expected GetConfigForClient to be set")
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	_, err := tlsConfig.GetConfigForClient(&tls.ClientHelloInfo{
		Conn:       server,
		ServerName: "",
	})
	if err == nil {
		t.Fatal("expected empty SNI error")
	}
}
