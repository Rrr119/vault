// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: BUSL-1.1

package example

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

type testUser struct {
	password   string
	expiresAt  time.Time
	statements []string
}

type testServer struct {
	token string

	mu                   sync.Mutex
	users                map[string]testUser
	calls                []string
	healthCalls          int
	healthStatus         int
	createStatus         int
	createResponse       string
	deleteStatus         int
	lastCreateStatements []string
}

func newTestServer(t *testing.T, token string) (*testServer, *httptest.Server) {
	t.Helper()

	s := &testServer{
		token:        token,
		users:        make(map[string]testUser),
		healthStatus: http.StatusNoContent,
		createStatus: http.StatusCreated,
	}
	server := httptest.NewServer(s)
	t.Cleanup(server.Close)
	return s, server
}

func (s *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.calls = append(s.calls, r.Method+" "+r.URL.EscapedPath())
	s.mu.Unlock()

	if r.Header.Get("Authorization") != "Bearer "+s.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		s.mu.Lock()
		s.healthCalls++
		status := s.healthStatus
		s.mu.Unlock()
		w.WriteHeader(status)
		return

	case r.Method == http.MethodPost && r.URL.Path == "/v1/users":
		s.createUser(w, r)
		return

	case strings.HasPrefix(r.URL.EscapedPath(), "/v1/users/"):
		username, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/v1/users/"))
		if err != nil || username == "" {
			http.Error(w, "invalid username", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPatch:
			s.updateUser(w, r, username)
		case http.MethodDelete:
			s.deleteUser(w, r, username)
		default:
			http.NotFound(w, r)
		}
		return
	}

	http.NotFound(w, r)
}

func (s *testServer) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createStatus >= http.StatusBadRequest {
		status := s.createStatus
		message := s.createResponse
		if message == "" {
			message = "create failed"
		}
		http.Error(w, message, status)
		return
	}

	expiration, err := parseTestExpiration(req.ExpiresAt)
	if err != nil {
		http.Error(w, "invalid expiration", http.StatusBadRequest)
		return
	}
	s.lastCreateStatements = append([]string(nil), req.Statements...)
	s.users[req.Username] = testUser{
		password:   req.Password,
		expiresAt:  expiration,
		statements: append([]string(nil), req.Statements...),
	}
	w.WriteHeader(s.createStatus)
}

func (s *testServer) updateUser(w http.ResponseWriter, r *http.Request, username string) {
	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[username]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if req.Password != "" {
		user.password = req.Password
	}
	if req.ExpiresAt != "" {
		expiration, err := parseTestExpiration(req.ExpiresAt)
		if err != nil {
			http.Error(w, "invalid expiration", http.StatusBadRequest)
			return
		}
		user.expiresAt = expiration
	}
	s.users[username] = user
	w.WriteHeader(http.StatusNoContent)
}

func (s *testServer) deleteUser(w http.ResponseWriter, r *http.Request, username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteStatus >= http.StatusBadRequest {
		http.Error(w, "delete failed", s.deleteStatus)
		return
	}
	if _, ok := s.users[username]; !ok {
		http.NotFound(w, r)
		return
	}
	delete(s.users, username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *testServer) user(username string) (testUser, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[username]
	return user, ok
}

func (s *testServer) callCount(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int
	for _, call := range s.calls {
		if strings.HasPrefix(call, prefix) {
			count++
		}
	}
	return count
}

func (s *testServer) healthCheckCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.healthCalls
}

func parseTestExpiration(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, value)
}

func configFor(address, token string) map[string]interface{} {
	return map[string]interface{}{
		"address": address,
		"token":   token,
	}
}

func TestInitialize(t *testing.T) {
	const token = "admin-token"

	t.Run("verify connection", func(t *testing.T) {
		serverState, server := newTestServer(t, token)
		db := newDatabase()
		t.Cleanup(func() { _ = db.Close() })

		resp, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{
			Config:           configFor(server.URL, token),
			VerifyConnection: true,
		})
		if err != nil {
			t.Fatalf("Initialize returned an error: %v", err)
		}
		if serverState.healthCheckCount() != 1 {
			t.Fatalf("expected one health check, got %d", serverState.healthCheckCount())
		}
		credentialTypes, ok := resp.Config[dbplugin.SupportedCredentialTypesKey].([]interface{})
		if !ok || len(credentialTypes) != 1 || credentialTypes[0] != dbplugin.CredentialTypePassword.String() {
			t.Fatalf("unexpected supported credential types: %#v", resp.Config[dbplugin.SupportedCredentialTypesKey])
		}
	})

	t.Run("skip connection verification", func(t *testing.T) {
		serverState, server := newTestServer(t, token)
		serverState.healthStatus = http.StatusInternalServerError
		db := newDatabase()
		t.Cleanup(func() { _ = db.Close() })

		_, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{
			Config:           configFor(server.URL, token),
			VerifyConnection: false,
		})
		if err != nil {
			t.Fatalf("Initialize returned an error: %v", err)
		}
		if serverState.healthCheckCount() != 0 {
			t.Fatalf("expected no health checks, got %d", serverState.healthCheckCount())
		}
	})

	t.Run("health check failure", func(t *testing.T) {
		serverState, server := newTestServer(t, token)
		serverState.healthStatus = http.StatusServiceUnavailable
		db := newDatabase()
		t.Cleanup(func() { _ = db.Close() })

		_, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{
			Config:           configFor(server.URL, token),
			VerifyConnection: true,
		})
		if err == nil {
			t.Fatal("expected a health check error")
		}
		if serverState.healthCheckCount() != 1 {
			t.Fatalf("expected one health check, got %d", serverState.healthCheckCount())
		}
	})
}

func TestInitializeWithCustomCA(t *testing.T) {
	const token = "admin-token"
	serverState := &testServer{
		token:        token,
		users:        make(map[string]testUser),
		healthStatus: http.StatusNoContent,
	}
	server := httptest.NewTLSServer(serverState)
	t.Cleanup(server.Close)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	cfg := configFor(server.URL, token)
	cfg["ca_cert"] = string(certPEM)

	db := newDatabase()
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config:           cfg,
		VerifyConnection: true,
	}); err != nil {
		t.Fatalf("Initialize with custom CA returned an error: %v", err)
	}
	if serverState.healthCheckCount() != 1 {
		t.Fatalf("expected one health check, got %d", serverState.healthCheckCount())
	}
}

func TestInitializeConfigValidation(t *testing.T) {
	valid := configFor("http://127.0.0.1:8200", "admin-token")

	tests := map[string]struct {
		nilConfig bool
		mutate    func(map[string]interface{})
	}{
		"nil config": {
			nilConfig: true,
		},
		"missing address": {
			mutate: func(cfg map[string]interface{}) { delete(cfg, "address") },
		},
		"unsupported scheme": {
			mutate: func(cfg map[string]interface{}) { cfg["address"] = "ftp://db.example" },
		},
		"missing host": {
			mutate: func(cfg map[string]interface{}) { cfg["address"] = "http://" },
		},
		"credentials in address": {
			mutate: func(cfg map[string]interface{}) { cfg["address"] = "http://user:pass@db.example" },
		},
		"query in address": {
			mutate: func(cfg map[string]interface{}) { cfg["address"] = "http://db.example?token=x" },
		},
		"missing token": {
			mutate: func(cfg map[string]interface{}) { delete(cfg, "token") },
		},
		"newline in token": {
			mutate: func(cfg map[string]interface{}) { cfg["token"] = "admin\ntoken" },
		},
		"invalid timeout": {
			mutate: func(cfg map[string]interface{}) { cfg["timeout"] = "soon" },
		},
		"non-positive timeout": {
			mutate: func(cfg map[string]interface{}) { cfg["timeout"] = "-1s" },
		},
		"relative health path": {
			mutate: func(cfg map[string]interface{}) { cfg["health_path"] = "health" },
		},
		"health path query": {
			mutate: func(cfg map[string]interface{}) { cfg["health_path"] = "/health?full=1" },
		},
		"invalid username template": {
			mutate: func(cfg map[string]interface{}) { cfg["username_template"] = "{{ .Missing | nope }}" },
		},
		"invalid CA certificate": {
			mutate: func(cfg map[string]interface{}) { cfg["ca_cert"] = "not a certificate" },
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var cfg map[string]interface{}
			if !test.nilConfig {
				cfg = make(map[string]interface{}, len(valid))
				for key, value := range valid {
					cfg[key] = value
				}
				if test.mutate != nil {
					test.mutate(cfg)
				}
			}

			db := newDatabase()
			t.Cleanup(func() { _ = db.Close() })
			if _, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{Config: cfg}); err == nil {
				t.Fatal("expected configuration validation error")
			}
		})
	}
}

func TestUserLifecycle(t *testing.T) {
	const (
		token    = "admin-token"
		password = "initial-password"
	)
	serverState, server := newTestServer(t, token)
	db := newDatabase()

	if _, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: configFor(server.URL, token),
	}); err != nil {
		t.Fatalf("Initialize returned an error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	expiration := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	created, err := db.NewUser(context.Background(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "alice",
			RoleName:    "readonly",
		},
		Password:   password,
		Expiration: expiration,
		Statements: dbplugin.Statements{Commands: []string{"policy=readonly"}},
	})
	if err != nil {
		t.Fatalf("NewUser returned an error: %v", err)
	}
	if created.Username == "" {
		t.Fatal("NewUser returned an empty username")
	}

	user, ok := serverState.user(created.Username)
	if !ok {
		t.Fatalf("user %q was not created", created.Username)
	}
	if user.password != password {
		t.Fatalf("unexpected password: %q", user.password)
	}
	if !user.expiresAt.Equal(expiration) {
		t.Fatalf("unexpected expiration: got %s, want %s", user.expiresAt, expiration)
	}
	if len(serverState.lastCreateStatements) != 1 || serverState.lastCreateStatements[0] != "policy=readonly" {
		t.Fatalf("unexpected creation statements: %#v", serverState.lastCreateStatements)
	}

	newPassword := "rotated-password"
	if _, err := db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		Username: created.Username,
		Password: &dbplugin.ChangePassword{
			NewPassword: newPassword,
			Statements:  dbplugin.Statements{Commands: []string{"policy=readwrite"}},
		},
	}); err != nil {
		t.Fatalf("UpdateUser password returned an error: %v", err)
	}
	user, _ = serverState.user(created.Username)
	if user.password != newPassword {
		t.Fatalf("unexpected password after rotation: %q", user.password)
	}

	newExpiration := expiration.Add(2 * time.Hour)
	if _, err := db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		Username: created.Username,
		Expiration: &dbplugin.ChangeExpiration{
			NewExpiration: newExpiration,
		},
	}); err != nil {
		t.Fatalf("UpdateUser expiration returned an error: %v", err)
	}
	user, _ = serverState.user(created.Username)
	if !user.expiresAt.Equal(newExpiration) {
		t.Fatalf("unexpected expiration after update: got %s, want %s", user.expiresAt, newExpiration)
	}

	if _, err := db.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{Username: created.Username}); err != nil {
		t.Fatalf("DeleteUser returned an error: %v", err)
	}
	if _, ok := serverState.user(created.Username); ok {
		t.Fatalf("user %q still exists after deletion", created.Username)
	}
	if _, err := db.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{Username: created.Username}); err != nil {
		t.Fatalf("deleting a missing user should be idempotent, got: %v", err)
	}

	dbType, err := db.Type()
	if err != nil {
		t.Fatalf("Type returned an error: %v", err)
	}
	if dbType != TypeName {
		t.Fatalf("unexpected type: %q", dbType)
	}
}

func TestUsernamePathEscaping(t *testing.T) {
	const token = "admin-token"
	serverState, server := newTestServer(t, token)
	db := newDatabase()

	cfg := configFor(server.URL, token)
	cfg["username_template"] = "{{ .DisplayName }}"
	if _, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{Config: cfg}); err != nil {
		t.Fatalf("Initialize returned an error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	username := "team/alice"
	if _, err := db.NewUser(context.Background(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: username},
		Password:       "password",
		Expiration:     time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("NewUser returned an error: %v", err)
	}
	if _, ok := serverState.user(username); !ok {
		t.Fatalf("user %q was not created using an escaped path", username)
	}

	if _, err := db.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{Username: username}); err != nil {
		t.Fatalf("DeleteUser returned an error: %v", err)
	}
	if _, ok := serverState.user(username); ok {
		t.Fatalf("user %q still exists after deletion", username)
	}
}

func TestNewUserRollback(t *testing.T) {
	const (
		token    = "admin-token"
		password = "do-not-leak"
	)
	serverState, server := newTestServer(t, token)
	serverState.createStatus = http.StatusInternalServerError
	serverState.createResponse = "create failed for password " + password

	db := newDatabase()
	if _, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: configFor(server.URL, token),
	}); err != nil {
		t.Fatalf("Initialize returned an error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	_, err := db.NewUser(context.Background(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: "alice"},
		Password:       password,
		Expiration:     time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("expected NewUser to fail")
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("error leaked the generated password: %v", err)
	}
	if serverState.callCount(http.MethodDelete) != 1 {
		t.Fatalf("expected one rollback delete call, got %d", serverState.callCount(http.MethodDelete))
	}
}

func TestNewUserRollbackFailure(t *testing.T) {
	const token = "admin-token"
	serverState, server := newTestServer(t, token)
	serverState.createStatus = http.StatusInternalServerError
	serverState.deleteStatus = http.StatusInternalServerError

	db := newDatabase()
	if _, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: configFor(server.URL, token),
	}); err != nil {
		t.Fatalf("Initialize returned an error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	_, err := db.NewUser(context.Background(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: "alice"},
		Password:       "password",
		Expiration:     time.Now().Add(time.Hour),
	})
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected rollback failure in error, got: %v", err)
	}
}

func TestUnsupportedAndInvalidRequests(t *testing.T) {
	db := newDatabase()

	if _, err := db.NewUser(context.Background(), dbplugin.NewUserRequest{
		CredentialType: dbplugin.CredentialTypeRSAPrivateKey,
	}); err == nil {
		t.Fatal("expected unsupported credential type error")
	}
	if _, err := db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		PublicKey: &dbplugin.ChangePublicKey{NewPublicKey: []byte("key")},
	}); err == nil {
		t.Fatal("expected unsupported public key error")
	}
	if _, err := db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		Username: "alice",
	}); err == nil {
		t.Fatal("expected no changes requested error")
	}
	if _, err := db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		Password: &dbplugin.ChangePassword{NewPassword: "password"},
	}); err == nil {
		t.Fatal("expected missing username error")
	}
	if _, err := db.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{}); err == nil {
		t.Fatal("expected missing username error")
	}
	if _, err := db.UpdateUser(context.Background(), dbplugin.UpdateUserRequest{
		Username: "alice",
		Password: &dbplugin.ChangePassword{NewPassword: "password"},
	}); err == nil {
		t.Fatal("expected not initialized error")
	}
	if _, err := db.DeleteUser(context.Background(), dbplugin.DeleteUserRequest{Username: "alice"}); err == nil {
		t.Fatal("expected not initialized error")
	}
	if _, err := db.NewUser(context.Background(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: "alice"},
		Password:       "password",
	}); err == nil {
		t.Fatal("expected not initialized error")
	}
}

func TestPluginFactorySanitizesErrors(t *testing.T) {
	const token = "admin-token-that-must-not-leak"
	serverState, server := newTestServer(t, token)
	serverState.createStatus = http.StatusInternalServerError
	serverState.createResponse = "request used token " + token

	raw, err := New()
	if err != nil {
		t.Fatalf("New returned an error: %v", err)
	}
	db, ok := raw.(dbplugin.Plugin)
	if !ok {
		t.Fatalf("New returned %T, which does not implement dbplugin.Plugin", raw)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: configFor(server.URL, token),
	}); err != nil {
		t.Fatalf("Initialize returned an error: %v", err)
	}

	_, err = db.NewUser(context.Background(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: "alice"},
		Password:       "password",
		Expiration:     time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("expected NewUser to fail")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("error leaked the administration token: %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	db := newDatabase()
	if err := db.Close(); err != nil {
		t.Fatalf("first Close returned an error: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("second Close returned an error: %v", err)
	}
}

func TestURLConstruction(t *testing.T) {
	base, err := url.Parse("https://db.example/admin/")
	if err != nil {
		t.Fatalf("unable to parse base URL: %v", err)
	}

	userURL := appendPath(base, "v1", "users", url.PathEscape("team/alice"))
	if got, want := userURL.String(), "https://db.example/admin/v1/users/team%2Falice"; got != want {
		t.Fatalf("unexpected user URL: got %q, want %q", got, want)
	}

	health := healthURL(base, "/health")
	if got, want := health.String(), "https://db.example/admin/health"; got != want {
		t.Fatalf("unexpected health URL: got %q, want %q", got, want)
	}
}
