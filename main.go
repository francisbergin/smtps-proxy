package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

var sniMap sync.Map

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

func generateTLSConfig() *tls.Config {
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

			// Generate private key
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, err
			}

			// Generate certificate template
			serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
			template := x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					CommonName: sni,
				},
				NotBefore:             time.Now().Add(-24 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				DNSNames:              []string{sni}, // Include SNI in SAN
			}

			// Create self-signed certificate
			certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
			if err != nil {
				return nil, err
			}

			cert := tls.Certificate{
				Certificate: [][]byte{certDER},
				PrivateKey:  priv,
			}

			return &tls.Config{
				Certificates: []tls.Certificate{cert},
			}, nil
		},
	}
}

func main() {
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
	startTLSServer.TLSConfig = generateTLSConfig()

	errCh := make(chan error, 2)

	go func() {
		log.Println("Starting SMTP server with implicit TLS on", implicitTLSServer.Addr)
		listener, err := tls.Listen("tcp", implicitTLSServer.Addr, generateTLSConfig())
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
