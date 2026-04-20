package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
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
			return err
		}
		saslClient := sasl.NewPlainClient(identity, username, password)
		return s.client.Auth(saslClient)
	}), nil
}

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	if err := s.connect(); err != nil {
		return err
	}
	s.logf("Mail from: %s", from)
	return s.client.Mail(from, opts)
}

func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if err := s.connect(); err != nil {
		return err
	}
	s.logf("Rcpt to: %s", to)
	return s.client.Rcpt(to, opts)
}

func (s *session) Data(r io.Reader) error {
	if err := s.connect(); err != nil {
		return err
	}
	s.logf("Data received")
	w, err := s.client.Data()
	if err != nil {
		return err
	}
	n, err := io.Copy(w, r)
	if err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
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

	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               binary.BigEndian.Uint16(idBytes[:]),
			RecursionDesired: true,
		},
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

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	respBuf := make([]byte, 512)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, err
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(respBuf[:n]); err != nil {
		return nil, err
	}

	for _, answer := range resp.Answers {
		if answer.Header.Type != dnsmessage.TypeA {
			continue
		}
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
	s := smtp.NewServer(b)

	s.Addr = ":587"
	s.Domain = "localhost"
	s.AllowInsecureAuth = false
	s.TLSConfig = generateTLSConfig()

	log.Println("Starting SMTP server with STARTTLS on", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
