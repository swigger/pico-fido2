package storage

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

type fixtureCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func authority(t *testing.T) fixtureCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	need(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	need(t, err)
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "synthetic coordinator CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	need(t, err)
	return fixtureCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}
func (ca fixtureCA) leaf(t *testing.T, name string, server bool, expired bool) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	need(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	need(t, err)
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	if expired {
		cert.NotBefore = time.Now().Add(-2 * time.Hour)
		cert.NotAfter = time.Now().Add(-time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca.cert, &key.PublicKey, ca.key)
	need(t, err)
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	need(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
}

// The coordinator and TLS fixtures are platform-independent. Protected profile,
// enrollment and helper process checks use the same setup in their own test.
type secureCoordinatorFixture struct {
	ctx                   context.Context
	config                CoordinatorConfig
	ca                    fixtureCA
	client                *clientv3.Client
	prefix, rootKey, port string
}

func newSecureCoordinatorFixture(t *testing.T) secureCoordinatorFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	ca := authority(t)
	cert, key := ca.leaf(t, "fixture-server", true, false)
	cfg := newConfig(t)
	cfg.ListenClientUrls[0].Scheme = "https"
	cfg.AdvertiseClientUrls = cfg.ListenClientUrls
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		need(t, os.WriteFile(p, []byte(text), 0600))
		return p
	}
	cfg.ClientTLSInfo = transport.TLSInfo{CertFile: write("server.pem", cert), KeyFile: write("server.key", key),
		TrustedCAFile: write("ca.pem", ca.pem), ClientCertAuth: true}
	server := start(t, cfg)
	t.Cleanup(server.Close)
	rootCert, rootKey := ca.leaf(t, "root", false, false)
	setup := CoordinatorConfig{Endpoints: []string{cfg.AdvertiseClientUrls[0].String()}, CAPEM: ca.pem, ClientCertPEM: rootCert, ClientKeyPEM: rootKey}
	if _, err := InspectCoordinator(ctx, setup); err == nil {
		t.Fatal("coordinator without RBAC accepted")
	}
	tlsConfig, err := coordinatorTLS(setup)
	need(t, err)
	admin, err := clientv3.New(clientv3.Config{Endpoints: setup.Endpoints, TLS: tlsConfig, Logger: zap.NewNop()})
	need(t, err)
	t.Cleanup(func() { admin.Close() })
	_, err = admin.UserAddWithOptions(ctx, "root", "", &clientv3.UserAddOptions{NoPassword: true})
	need(t, err)
	_, err = admin.UserGrantRole(ctx, "root", "root")
	need(t, err)
	_, err = admin.UserAddWithOptions(ctx, "fixture", "", &clientv3.UserAddOptions{NoPassword: true})
	need(t, err)
	_, err = admin.RoleAdd(ctx, "fixture-vault")
	need(t, err)
	prefix := "/pico-fido2/v1/" + webdavSpace + "/"
	_, err = admin.RoleGrantPermission(ctx, "fixture-vault", prefix, clientv3.GetPrefixRangeEnd(prefix), clientv3.PermissionType(clientv3.PermReadWrite))
	need(t, err)
	_, err = admin.UserGrantRole(ctx, "fixture", "fixture-vault")
	need(t, err)
	_, err = admin.AuthEnable(ctx)
	need(t, err)
	setup.ClientCertPEM, setup.ClientKeyPEM = ca.leaf(t, "fixture", false, false)
	setup.ClusterID, err = InspectCoordinator(ctx, setup)
	need(t, err)
	client, err := OpenCoordinator(ctx, setup)
	need(t, err)
	t.Cleanup(func() { client.Close() })
	return secureCoordinatorFixture{ctx: ctx, config: setup, ca: ca, client: client, prefix: prefix, rootKey: rootKey, port: cfg.AdvertiseClientUrls[0].Port()}
}

func TestCoordinatorMutualTLSAndNamespacePermissions(t *testing.T) {
	f := newSecureCoordinatorFixture(t)
	ctx, setup, ca, client := f.ctx, f.config, f.ca, f.client
	objects := davObjects(t, startDAV(t))
	writer := acquire(t, ctx, client, objects, webdavSpace, true)
	need(t, writer.Commit(ctx, blob(7), 0))
	need(t, writer.Close())
	reader := acquire(t, ctx, client, objects, webdavSpace, false)
	data, generation, err := reader.Read(ctx)
	need(t, err)
	if generation != 1 || !bytes.Equal(data, blob(7)) {
		t.Fatal("TLS coordinator and WebDAV lost committed data")
	}
	need(t, reader.Close())
	if _, err := Acquire(ctx, client, objects, "00000000000000000000000000000001", true); err == nil {
		t.Fatal("client escaped namespace permission")
	}
	wrong := setup
	wrong.ClusterID = "0000000000000001"
	if c, err := OpenCoordinator(ctx, wrong); err == nil {
		c.Close()
		t.Fatal("wrong cluster accepted")
	}
	wrong = setup
	wrong.ClientKeyPEM = f.rootKey
	if _, err := OpenCoordinator(ctx, wrong); err == nil {
		t.Fatal("mismatched client private key accepted")
	}
	wrong = setup
	wrong.ClientCertPEM, wrong.ClientKeyPEM = ca.leaf(t, "fixture", false, true)
	if _, err := OpenCoordinator(ctx, wrong); err == nil {
		t.Fatal("expired client accepted")
	}
	wrong = setup
	wrong.CAPEM = authority(t).pem
	short, done := context.WithTimeout(ctx, 300*time.Millisecond)
	if c, err := OpenCoordinator(short, wrong); err == nil {
		c.Close()
		t.Fatal("wrong coordinator trust accepted")
	}
	done()
	wrong = setup
	wrong.Endpoints = []string{"https://localhost:" + f.port}
	short, done = context.WithTimeout(ctx, 300*time.Millisecond)
	if c, err := OpenCoordinator(short, wrong); err == nil {
		c.Close()
		t.Fatal("wrong server hostname accepted")
	}
	done()
	for _, endpoint := range []string{"http://127.0.0.1:2379", "https://name:secret@example.invalid", "https://example.invalid/path", "https://example.invalid?token=secret"} {
		wrong = setup
		wrong.Endpoints = []string{endpoint}
		if _, err := coordinatorTLS(wrong); err == nil {
			t.Fatal("unsafe coordinator endpoint")
		}
	}
}
