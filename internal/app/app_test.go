package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard) // silence operational logging during tests
	os.Exit(m.Run())
}

// cancelledCtx returns an already-cancelled context so Run starts the server
// and then immediately proceeds to graceful shutdown.
func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestRunFlagError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"-nope"}, nil, &out, &errb); code != 2 {
		t.Errorf("bad flag: got %d, want 2", code)
	}
}

func TestRunVersion(t *testing.T) {
	// Both the `-version` flag and the `version` subcommand print the build info.
	for _, args := range [][]string{{"-version"}, {"version"}} {
		var out, errb bytes.Buffer
		if code := Run(context.Background(), args, nil, &out, &errb); code != 0 {
			t.Errorf("%v: got %d, want 0", args, code)
		}
		if !strings.Contains(out.String(), "wg-status ") {
			t.Errorf("%v output = %q", args, out.String())
		}
	}
}

func TestRunHashPasswordDispatch(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run(context.Background(), []string{"-hash-password"}, strings.NewReader("secret\n"), &out, &errb)
	if code != 0 {
		t.Errorf("hash-password: got %d, want 0", code)
	}
	if !strings.HasPrefix(out.String(), "pbkdf2-sha256$") {
		t.Errorf("hash-password output = %q", out.String())
	}
}

func TestRunConfigError(t *testing.T) {
	t.Setenv("WG_COLLECTOR", "bogus") // fails validation
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"-config", ""}, nil, &out, &errb); code != 1 {
		t.Errorf("config error: got %d, want 1", code)
	}
}

func TestRunFakeCollectorGracefulShutdown(t *testing.T) {
	t.Setenv("WG_COLLECTOR", "fake")
	t.Setenv("WG_LISTEN", "127.0.0.1:0")
	var out, errb bytes.Buffer
	if code := Run(cancelledCtx(), []string{"-config", ""}, nil, &out, &errb); code != 0 {
		t.Errorf("fake run: got %d, want 0 (stderr=%q)", code, errb.String())
	}
}

func TestRunWgCollectorGracefulShutdown(t *testing.T) {
	t.Setenv("WG_COLLECTOR", "wg") // exercises the default collector branch
	t.Setenv("WG_LISTEN", "127.0.0.1:0")
	var out, errb bytes.Buffer
	if code := Run(cancelledCtx(), []string{"-config", ""}, nil, &out, &errb); code != 0 {
		t.Errorf("wg run: got %d, want 0 (stderr=%q)", code, errb.String())
	}
}

func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestRunTLSGracefulShutdown(t *testing.T) {
	cert, key := writeSelfSignedCert(t)
	t.Setenv("WG_COLLECTOR", "fake")
	t.Setenv("WG_LISTEN", "127.0.0.1:0")
	t.Setenv("WG_TLS_CERT", cert)
	t.Setenv("WG_TLS_KEY", key)
	var out, errb bytes.Buffer
	if code := Run(cancelledCtx(), []string{"-config", ""}, nil, &out, &errb); code != 0 {
		t.Errorf("tls run: got %d, want 0 (stderr=%q)", code, errb.String())
	}
}

func TestRunServeError(t *testing.T) {
	t.Setenv("WG_COLLECTOR", "fake")
	t.Setenv("WG_LISTEN", "127.0.0.1:999999") // invalid port -> ListenAndServe fails
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"-config", ""}, nil, &out, &errb); code != 1 {
		t.Errorf("serve error: got %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "serve:") {
		t.Errorf("expected a serve error on stderr, got %q", errb.String())
	}
}

func TestHashPassword(t *testing.T) {
	// Success.
	var out, errb bytes.Buffer
	if code := hashPassword(strings.NewReader("secret\n"), &out, &errb); code != 0 {
		t.Errorf("success: got %d, want 0", code)
	}
	if !strings.HasPrefix(out.String(), "pbkdf2-sha256$") {
		t.Errorf("hash output = %q", out.String())
	}

	// Read error (empty input, immediate EOF).
	out.Reset()
	errb.Reset()
	if code := hashPassword(strings.NewReader(""), &out, &errb); code != 1 {
		t.Errorf("read error: got %d, want 1", code)
	}

	// Empty password (just a newline).
	out.Reset()
	errb.Reset()
	if code := hashPassword(strings.NewReader("\n"), &out, &errb); code != 1 {
		t.Errorf("empty password: got %d, want 1", code)
	}

	// Hash failure via the seam.
	orig := hashFn
	t.Cleanup(func() { hashFn = orig })
	hashFn = func(string) (string, error) { return "", errors.New("rng down") }
	out.Reset()
	errb.Reset()
	if code := hashPassword(strings.NewReader("pw\n"), &out, &errb); code != 1 {
		t.Errorf("hash failure: got %d, want 1", code)
	}
}

func TestEnvOr(t *testing.T) {
	orig := getenv
	t.Cleanup(func() { getenv = orig })

	getenv = func(string) string { return "from-env" }
	if got := envOr("K", "def"); got != "from-env" {
		t.Errorf("envOr with value = %q, want from-env", got)
	}
	getenv = func(string) string { return "" }
	if got := envOr("K", "def"); got != "def" {
		t.Errorf("envOr without value = %q, want def", got)
	}
}
