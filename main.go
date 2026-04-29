package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

var sniMap sync.Map

const (
	rootCACertFile = "root-ca.pem"
	rootCAKeyFile  = "root-ca-key.pem"
)

type certificateAuthority struct {
	cert       *x509.Certificate
	privateKey crypto.PrivateKey
}

// Dependency injection types
type lookupAType func(ctx context.Context, host string) (net.IP, error)
type smtpDialStartTLSType func(addr string, tlsConfig *tls.Config) (*smtp.Client, error)

type backend struct {
	lookupA          lookupAType
	smtpDialStartTLS smtpDialStartTLSType
}

func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	addr := c.Conn().RemoteAddr().String()
	session := &session{
		addr:             addr,
		lookupA:          b.lookupA,
		smtpDialStartTLS: b.smtpDialStartTLS,
	}
	session.logf("NewSession")
	return session, nil
}

type session struct {
	addr             string
	client           *smtp.Client
	lookupA          lookupAType
	smtpDialStartTLS smtpDialStartTLSType
}

func (s *session) logAndSanitizeError(err error, code int, enhanced smtp.EnhancedCode, message string) error {
	s.logf("Internal error: %v", err)
	return &smtp.SMTPError{
		Code:         code,
		EnhancedCode: enhanced,
		Message:      message,
	}
}

func (s *session) connect() error {
	if s.client != nil {
		return nil
	}
	sniVal, ok := sniMap.Load(s.addr)
	if !ok {
		return errors.New("SNI required")
	}
	sniMap.Delete(s.addr)
	sni := sniVal.(string)
	if sni == "" {
		return errors.New("SNI required")
	}

	ip, err := s.lookupA(context.Background(), sni)
	if err != nil {
		return err
	}

	s.logf("Connecting to real server: %s (%s)", sni, ip.String())
	client, err := s.smtpDialStartTLS(ip.String()+":587", &tls.Config{ServerName: sni})
	if err != nil {
		return err
	}

	s.client = client
	return nil
}

func (s *session) logf(format string, args ...interface{}) {
	log.Printf("%s: %s", s.addr, fmt.Sprintf(format, args...))
}

func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		s.logf("Auth credentials: identity=%s username=%s password=%s", identity, username, password)
		if err := s.connect(); err != nil {
			return s.logAndSanitizeError(err, 454, smtp.EnhancedCode{4, 7, 0}, "Temporary authentication failure")
		}
		saslClient := sasl.NewPlainClient(identity, username, password)
		if err := s.client.Auth(saslClient); err != nil {
			return s.logAndSanitizeError(err, 454, smtp.EnhancedCode{4, 7, 0}, "Temporary authentication failure")
		}
		return nil
	}), nil
}

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	if err := s.connect(); err != nil {
		return s.logAndSanitizeError(err, 451, smtp.EnhancedCode{4, 3, 0}, "Temporary server failure")
	}
	s.logf("Mail from: %s", from)
	if err := s.client.Mail(from, opts); err != nil {
		return s.logAndSanitizeError(err, 451, smtp.EnhancedCode{4, 3, 0}, "Temporary server failure")
	}
	return nil
}

func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if err := s.connect(); err != nil {
		return s.logAndSanitizeError(err, 451, smtp.EnhancedCode{4, 3, 0}, "Temporary server failure")
	}
	s.logf("Rcpt to: %s", to)
	if err := s.client.Rcpt(to, opts); err != nil {
		return s.logAndSanitizeError(err, 451, smtp.EnhancedCode{4, 3, 0}, "Temporary server failure")
	}
	return nil
}

func (s *session) Data(r io.Reader) error {
	if err := s.connect(); err != nil {
		return s.logAndSanitizeError(err, 451, smtp.EnhancedCode{4, 3, 0}, "Temporary server failure")
	}
	s.logf("Data received")
	w, err := s.client.Data()
	if err != nil {
		return s.logAndSanitizeError(err, 451, smtp.EnhancedCode{4, 3, 0}, "Temporary server failure")
	}
	n, err := io.Copy(w, r)
	if err != nil {
		return s.logAndSanitizeError(err, 451, smtp.EnhancedCode{4, 3, 0}, "Temporary server failure")
	}
	if err = w.Close(); err != nil {
		return s.logAndSanitizeError(err, 451, smtp.EnhancedCode{4, 3, 0}, "Temporary server failure")
	}
	s.logf("Data forwarded to real server (%d bytes)", n)
	return nil
}

func (s *session) Reset() {
	s.logf("Reset")
	if s.client != nil {
		s.client.Reset()
	}
}

func (s *session) Logout() error {
	s.logf("Logout")
	if s.client != nil {
		return s.client.Quit()
	}
	return nil
}

func lookupA(ctx context.Context, host string) (net.IP, error) {
	name := host
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  qname,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	packet, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	url := "https://9.9.9.9/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(packet)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh query failed: %s", httpResp.Status)
	}

	respBuf, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(respBuf); err != nil {
		return nil, err
	}
	for _, answer := range resp.Answers {
		if a, ok := answer.Body.(*dnsmessage.AResource); ok {
			return net.IP(a.A[:]), nil
		}
	}
	return nil, errors.New("no A records found")
}

func stripHostPort(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func randomSerialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func loadOrCreateRootCA(certPath, keyPath string) (*certificateAuthority, error) {
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	if certErr == nil && keyErr == nil {
		certBlock, _ := pem.Decode(certPEM)
		if certBlock == nil || certBlock.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("invalid CA certificate in %s", certPath)
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("certificate in %s is not a CA", certPath)
		}

		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, fmt.Errorf("invalid CA private key in %s", keyPath)
		}
		privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA private key: %w", err)
		}

		return &certificateAuthority{cert: cert, privateKey: privateKey}, nil
	}

	if certErr == nil || keyErr == nil {
		return nil, errors.New("found only one CA file; need both root-ca.pem and root-ca-key.pem")
	}
	if !os.IsNotExist(certErr) && certErr != nil {
		return nil, certErr
	}
	if !os.IsNotExist(keyErr) && keyErr != nil {
		return nil, keyErr
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "smtps-proxy root CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	certOut, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate file: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		certOut.Close()
		return nil, fmt.Errorf("failed to write CA certificate: %w", err)
	}
	if err := certOut.Close(); err != nil {
		return nil, fmt.Errorf("failed to close CA certificate file: %w", err)
	}

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA private key: %w", err)
	}
	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA key file: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key}); err != nil {
		keyOut.Close()
		return nil, fmt.Errorf("failed to write CA private key: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		return nil, fmt.Errorf("failed to close CA key file: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	return &certificateAuthority{cert: cert, privateKey: privateKey}, nil
}

func generateTLSConfig(ca *certificateAuthority) *tls.Config {
	return &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			addr := chi.Conn.RemoteAddr().String()
			sni := stripHostPort(chi.ServerName)
			if sni == "" {
				log.Printf("%s: Empty SNI received - closing connection", addr)
				return nil, errors.New("empty SNI")
			}
			log.Printf("%s: Generating certificate for SNI: %s", addr, sni)

			// Store SNI for later use in session
			sniMap.Store(chi.Conn.RemoteAddr().String(), sni)

			// Generate leaf keypair and sign with the persistent local root CA.
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, err
			}

			serialNumber, err := randomSerialNumber()
			if err != nil {
				return nil, err
			}
			template := x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					CommonName: sni,
				},
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().AddDate(0, 3, 0),
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				DNSNames:              []string{sni}, // Include SNI in SAN
			}

			certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.cert, &priv.PublicKey, ca.privateKey)
			if err != nil {
				return nil, err
			}

			cert := tls.Certificate{
				Certificate: [][]byte{certDER, ca.cert.Raw},
				PrivateKey:  priv,
			}

			return &tls.Config{
				Certificates: []tls.Certificate{cert},
			}, nil
		},
	}
}

func main() {
	ca, err := loadOrCreateRootCA(rootCACertFile, rootCAKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Using root CA from %s (private key in %s)", rootCACertFile, rootCAKeyFile)

	b := &backend{
		lookupA:          lookupA,
		smtpDialStartTLS: smtp.DialStartTLS,
	}

	implicitTLSServer := smtp.NewServer(b)
	implicitTLSServer.Addr = ":465"
	implicitTLSServer.Domain = "localhost"
	implicitTLSServer.AllowInsecureAuth = false

	startTLSServer := smtp.NewServer(b)
	startTLSServer.Addr = ":587"
	startTLSServer.Domain = "localhost"
	startTLSServer.AllowInsecureAuth = false
	startTLSServer.TLSConfig = generateTLSConfig(ca)

	errCh := make(chan error, 2)

	go func() {
		log.Println("Starting SMTP server with implicit TLS on", implicitTLSServer.Addr)
		listener, err := tls.Listen("tcp", implicitTLSServer.Addr, generateTLSConfig(ca))
		if err != nil {
			errCh <- err
			return
		}
		errCh <- implicitTLSServer.Serve(listener)
	}()

	go func() {
		log.Println("Starting SMTP server with STARTTLS on", startTLSServer.Addr)
		errCh <- startTLSServer.ListenAndServe()
	}()

	log.Fatal(<-errCh)
}
