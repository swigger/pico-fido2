package storage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

// CoordinatorConfig is secret-bearing configuration, intended for DPAPI storage
// and private parent-child IPC, never argv or logs. The certificate Common Name
// identifies a namespace-scoped etcd RBAC user; password authentication is unused.
type CoordinatorConfig struct {
	Endpoints     []string `json:"endpoints"`
	CAPEM         string   `json:"ca_pem"`
	ClientCertPEM string   `json:"client_cert_pem"`
	ClientKeyPEM  string   `json:"client_key_pem"`
	ClusterID     string   `json:"cluster_id"`
}

var clusterPattern = regexp.MustCompile(`^[a-f0-9]{16}$`)

func coordinatorTLS(c CoordinatorConfig) (*tls.Config, error) {
	return coordinatorTLSForProfile(c, false)
}

// Maintenance may decode an expired protected identity in order to replace it.
// Every actual connection still calls coordinatorTLS and checks its validity.
func coordinatorTLSForProfile(c CoordinatorConfig, allowExpired bool) (*tls.Config, error) {
	if len(c.Endpoints) == 0 || len(c.Endpoints) > 3 {
		return nil, errors.New("one to three coordinator endpoints are required")
	}
	seen := make(map[string]bool)
	for _, endpoint := range c.Endpoints {
		u, err := url.Parse(endpoint)
		if err != nil || len(endpoint) > 512 || u.Scheme != "https" || u.Hostname() == "" ||
			u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Opaque != "" || seen[endpoint] {
			return nil, errors.New("invalid HTTPS coordinator endpoint")
		}
		seen[endpoint] = true
	}
	if len(c.CAPEM) == 0 || len(c.CAPEM) > 65536 || len(c.ClientCertPEM) == 0 || len(c.ClientCertPEM) > 65536 ||
		len(c.ClientKeyPEM) == 0 || len(c.ClientKeyPEM) > 16384 {
		return nil, errors.New("coordinator trust and client identity are required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(c.CAPEM)) {
		return nil, errors.New("invalid coordinator CA")
	}
	identity, err := tls.X509KeyPair([]byte(c.ClientCertPEM), []byte(c.ClientKeyPEM))
	if err != nil {
		return nil, errors.New("invalid coordinator client identity")
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	now := time.Now()
	if err != nil || leaf.Subject.CommonName == "" || (!allowExpired && (now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter))) {
		return nil, errors.New("coordinator client identity requires a current certificate with a user name")
	}
	return &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12}, nil
}

// connect performs read-only checks before exposing a client. Configuration never
// disables hostname/date verification, trusts OS roots implicitly, or enables RBAC
// itself. Endpoint cluster identities must agree; no coordinator writes occur here.
func connectCoordinator(parent context.Context, c CoordinatorConfig, enroll bool) (*clientv3.Client, string, error) {
	if !enroll && (!clusterPattern.MatchString(c.ClusterID) || c.ClusterID == "0000000000000000") {
		return nil, "", errors.New("coordinator cluster must be enrolled first")
	}
	secure, err := coordinatorTLS(c)
	if err != nil {
		return nil, "", err
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: c.Endpoints, TLS: secure,
		DialTimeout: 5 * time.Second, DialKeepAliveTime: 5 * time.Second, DialKeepAliveTimeout: 3 * time.Second, Logger: zap.NewNop()})
	if err != nil {
		return nil, "", errors.New("cannot initialize coordinator connection")
	}
	ok := false
	defer func() {
		if !ok {
			client.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	cluster := ""
	for _, endpoint := range c.Endpoints {
		probe, finish := context.WithTimeout(ctx, 5*time.Second)
		status, err := client.Status(probe, endpoint)
		finish()
		if err != nil {
			return nil, "", errors.New("coordinator unavailable or TLS identity rejected")
		}
		identity := fmt.Sprintf("%016x", status.Header.ClusterId)
		if identity == "0000000000000000" || (cluster != "" && cluster != identity) || (!enroll && identity != c.ClusterID) {
			return nil, "", errors.New("coordinator cluster identity mismatch")
		}
		cluster = identity
	}
	status, err := client.AuthStatus(ctx)
	if errors.Is(err, rpctypes.ErrPermissionDenied) {
		// AuthStatus is root-only when RBAC is enabled. A namespace-scoped
		// certificate must not need administrative privileges just to connect.
		leaf, _ := x509.ParseCertificate(secure.Certificates[0].Certificate[0])
		self, ownErr := client.UserGet(ctx, leaf.Subject.CommonName)
		if ownErr != nil || len(self.Roles) == 0 || fmt.Sprintf("%016x", self.Header.ClusterId) != cluster {
			return nil, "", errors.New("coordinator client is not an authorized user")
		}
	} else if err != nil || !status.Enabled || fmt.Sprintf("%016x", status.Header.ClusterId) != cluster {
		return nil, "", errors.New("coordinator access control must be enabled")
	}
	ok = true
	return client, cluster, nil
}

// InspectCoordinator is used during explicit enrollment to discover cluster ID.
// It has no initialization side effects and does not return a writable client.
func InspectCoordinator(ctx context.Context, c CoordinatorConfig) (string, error) {
	client, cluster, err := connectCoordinator(ctx, c, true)
	if client != nil {
		client.Close()
	}
	return cluster, err
}

func OpenCoordinator(ctx context.Context, c CoordinatorConfig) (*clientv3.Client, error) {
	client, _, err := connectCoordinator(ctx, c, false)
	return client, err
}
