package syslog

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// TLSFiles builds the TLS listener's configuration from PEM files. The
// certificate is read again when its file changes (cert-manager renewals);
// with clientCA, senders must present a certificate it signed.
func TLSFiles(certFile, keyFile, clientCA string) (*tls.Config, error) {
	r := &certReloader{cert: certFile, key: keyFile}
	if _, err := r.load(); err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return r.get() }}
	if clientCA != "" {
		pem, err := os.ReadFile(clientCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("syslog: no certificate in %s", clientCA)
		}
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

type certReloader struct {
	cert, key string

	mu      sync.Mutex
	current *tls.Certificate
	mod     time.Time
	checked time.Time
}

// get returns the certificate, checking the file at most every 10s.
func (r *certReloader) get() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) < 10*time.Second {
		return r.current, nil
	}
	r.checked = time.Now()
	if fi, err := os.Stat(r.cert); err == nil && !fi.ModTime().Equal(r.mod) {
		if c, err := r.loadLocked(); err == nil {
			return c, nil
		}
	}
	return r.current, nil
}

func (r *certReloader) load() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loadLocked()
}

func (r *certReloader) loadLocked() (*tls.Certificate, error) {
	if r.cert == "" || r.key == "" {
		return nil, errors.New("syslog: the TLS listener needs a certificate and key file")
	}
	fi, err := os.Stat(r.cert)
	if err != nil {
		return nil, err
	}
	c, err := tls.LoadX509KeyPair(r.cert, r.key)
	if err != nil {
		return nil, fmt.Errorf("syslog: %w", err)
	}
	r.current, r.mod, r.checked = &c, fi.ModTime(), time.Now()
	return r.current, nil
}
