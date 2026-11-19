// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package example implements a reference database secrets engine plugin for a
// database that exposes an HTTP administration API instead of a SQL endpoint.
//
// It is intentionally small, but it follows the same lifecycle as the built-in
// database plugins so it can be used as a starting point for an in-house
// database.
package example

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/helper/template"
)

const (
	// TypeName is the database type reported by this plugin.
	TypeName = "example"

	defaultHealthPath = "/health"
	defaultTimeout    = 10 * time.Second

	defaultUsernameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 10) (.RoleName | truncate 10) (random 20) (unix_time) | truncate 64 }}`

	maxErrorBodySize = 8 << 10
)

var _ dbplugin.Plugin = (*Database)(nil)

// Database manages users through an HTTP API.
//
// The API contract is documented in README.md. The plugin is stateless with
// respect to users: Vault owns the username, password, expiration, and lease,
// and passes them to the API on each operation.
type Database struct {
	mu sync.RWMutex

	client           *http.Client
	address          *url.URL
	token            string
	rootPassword     string
	usernameProducer template.StringTemplate
	initialized      bool
}

// New returns a plugin instance wrapped with Vault's error sanitizer.
//
// ServeMultiplex calls this factory for every database connection.
func New() (interface{}, error) {
	db := newDatabase()
	wrapped := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return wrapped, nil
}

func newDatabase() *Database {
	return &Database{}
}

// Type returns the name used for metrics and logging.
func (d *Database) Type() (string, error) {
	return TypeName, nil
}

// Initialize validates the connection configuration and optionally verifies
// that the administration API is reachable.
func (d *Database) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	cfg, err := parseConfig(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}

	client := &http.Client{
		Timeout:   cfg.timeout,
		Transport: cfg.transport,
	}
	healthEndpoint := healthURL(cfg.address, cfg.healthPath)

	if req.VerifyConnection {
		if err := checkHealth(ctx, client, healthEndpoint, cfg.token); err != nil {
			client.CloseIdleConnections()
			return dbplugin.InitializeResponse{}, err
		}
	}

	d.mu.Lock()
	oldClient := d.client
	d.client = client
	d.address = cfg.address
	d.token = cfg.token
	d.rootPassword = cfg.rootPassword
	d.usernameProducer = cfg.usernameProducer
	d.initialized = true
	d.mu.Unlock()

	if oldClient != nil {
		oldClient.CloseIdleConnections()
	}

	responseConfig := make(map[string]interface{}, len(req.Config)+1)
	for key, value := range req.Config {
		responseConfig[key] = value
	}
	resp := dbplugin.InitializeResponse{Config: responseConfig}
	resp.SetSupportedCredentialTypes([]dbplugin.CredentialType{dbplugin.CredentialTypePassword})
	return resp, nil
}

// NewUser creates a short-lived account. If the API rejects creation after
// partially creating the account, the plugin makes a best-effort delete call
// before returning the original error.
func (d *Database) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	if req.CredentialType != dbplugin.CredentialTypePassword {
		return dbplugin.NewUserResponse{}, fmt.Errorf("credential type %q is not supported", req.CredentialType.String())
	}

	d.mu.RLock()
	if !d.initialized || d.client == nil {
		d.mu.RUnlock()
		return dbplugin.NewUserResponse{}, errors.New("database plugin is not initialized")
	}
	usernameProducer := d.usernameProducer
	d.mu.RUnlock()

	username, err := usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("unable to generate username: %w", err)
	}
	if username == "" {
		return dbplugin.NewUserResponse{}, errors.New("generated username is empty")
	}

	createReq := createUserRequest{
		Username:   username,
		Password:   req.Password,
		ExpiresAt:  formatExpiration(req.Expiration),
		Statements: req.Statements.Commands,
	}
	usersURL, err := d.usersURL()
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}
	if err := d.request(ctx, http.MethodPost, usersURL, createReq, req.Password); err != nil {
		userURL, urlErr := d.userURL(username)
		if urlErr != nil {
			return dbplugin.NewUserResponse{}, fmt.Errorf("create user failed: %w; rollback failed: %v", err, urlErr)
		}
		rollbackErr := d.request(ctx, http.MethodDelete, userURL, nil, "")
		if rollbackErr != nil && !errors.Is(rollbackErr, errNotFound) {
			return dbplugin.NewUserResponse{}, fmt.Errorf("create user failed: %w; rollback failed: %v", err, rollbackErr)
		}
		return dbplugin.NewUserResponse{}, fmt.Errorf("create user failed: %w", err)
	}

	return dbplugin.NewUserResponse{Username: username}, nil
}

// UpdateUser changes a user's password and/or expiration. This is used for
// password rotation, root credential rotation, and static role renewal.
func (d *Database) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.PublicKey != nil {
		return dbplugin.UpdateUserResponse{}, errors.New("public key credentials are not supported")
	}
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, errors.New("no changes requested")
	}
	if req.Username == "" {
		return dbplugin.UpdateUserResponse{}, errors.New("username is required")
	}

	updateReq := updateUserRequest{}
	var secret string
	if req.Password != nil {
		updateReq.Password = req.Password.NewPassword
		updateReq.PasswordStatements = req.Password.Statements.Commands
		secret = req.Password.NewPassword
	}
	if req.Expiration != nil {
		updateReq.ExpiresAt = formatExpiration(req.Expiration.NewExpiration)
		updateReq.ExpirationStatements = req.Expiration.Statements.Commands
	}

	userURL, err := d.userURL(req.Username)
	if err != nil {
		return dbplugin.UpdateUserResponse{}, err
	}
	if err := d.request(ctx, http.MethodPatch, userURL, updateReq, secret); err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("update user failed: %w", err)
	}
	return dbplugin.UpdateUserResponse{}, nil
}

// DeleteUser removes a user. A missing user is treated as success so that lease
// revocation is idempotent.
func (d *Database) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	if req.Username == "" {
		return dbplugin.DeleteUserResponse{}, errors.New("username is required")
	}

	userURL, err := d.userURL(req.Username)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}
	err = d.request(ctx, http.MethodDelete, userURL, nil, "")
	if err != nil && !errors.Is(err, errNotFound) {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("delete user failed: %w", err)
	}
	return dbplugin.DeleteUserResponse{}, nil
}

// Close releases idle HTTP connections. It is safe to call more than once.
func (d *Database) Close() error {
	d.mu.Lock()
	if d.client != nil {
		d.client.CloseIdleConnections()
	}
	d.client = nil
	d.address = nil
	d.token = ""
	d.rootPassword = ""
	d.initialized = false
	d.mu.Unlock()
	return nil
}

func (d *Database) secretValues() map[string]string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	secrets := make(map[string]string)
	if d.token != "" {
		secrets[d.token] = "[token]"
	}
	if d.rootPassword != "" {
		secrets[d.rootPassword] = "[password]"
	}
	return secrets
}

type createUserRequest struct {
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	Statements []string `json:"statements,omitempty"`
}

type updateUserRequest struct {
	Password             string   `json:"password,omitempty"`
	PasswordStatements   []string `json:"password_statements,omitempty"`
	ExpiresAt            string   `json:"expires_at,omitempty"`
	ExpirationStatements []string `json:"expiration_statements,omitempty"`
}

var errNotFound = errors.New("not found")

func (d *Database) request(ctx context.Context, method string, endpoint *url.URL, body interface{}, secret string) error {
	d.mu.RLock()
	client := d.client
	token := d.token
	d.mu.RUnlock()
	if client == nil {
		return errors.New("database plugin is not initialized")
	}

	var bodyReader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("unable to encode request: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bodyReader)
	if err != nil {
		return fmt.Errorf("unable to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
	if readErr != nil {
		return fmt.Errorf("unable to read response: %w", readErr)
	}
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}

	message := strings.TrimSpace(string(responseBody))
	message = redact(message, token, secret, d.currentRootPassword())
	if message == "" {
		return fmt.Errorf("unexpected response status %s", resp.Status)
	}
	return fmt.Errorf("unexpected response status %s: %s", resp.Status, message)
}

func (d *Database) currentRootPassword() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.rootPassword
}

func redact(message string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	return message
}

func (d *Database) usersURL() (*url.URL, error) {
	base, err := d.baseURL()
	if err != nil {
		return nil, err
	}
	return appendPath(base, "v1", "users"), nil
}

func (d *Database) userURL(username string) (*url.URL, error) {
	base, err := d.baseURL()
	if err != nil {
		return nil, err
	}
	return appendPath(base, "v1", "users", url.PathEscape(username)), nil
}

func (d *Database) baseURL() (*url.URL, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.address == nil {
		return nil, errors.New("database plugin is not initialized")
	}
	return d.address, nil
}

// appendPath appends already-escaped path segments to the configured base URL.
// Keeping RawPath as well as Path prevents names containing slashes from
// changing the endpoint that is called.
func appendPath(base *url.URL, segments ...string) *url.URL {
	result := *base
	prefix := strings.TrimRight(result.EscapedPath(), "/")
	result.RawPath = prefix + "/" + strings.Join(segments, "/")
	unescaped, err := url.PathUnescape(result.RawPath)
	if err != nil {
		result.Path = result.RawPath
		result.RawPath = ""
	} else {
		result.Path = unescaped
	}
	result.RawQuery = ""
	result.Fragment = ""
	return &result
}

func healthURL(address *url.URL, healthPath string) *url.URL {
	result := *address
	prefix := strings.TrimRight(result.Path, "/")
	result.Path = prefix + healthPath
	result.RawPath = ""
	result.RawQuery = ""
	result.Fragment = ""
	return &result
}

func checkHealth(ctx context.Context, client *http.Client, endpoint *url.URL, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("unable to create health check request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		message := redact(strings.TrimSpace(string(body)), token)
		if message == "" {
			return fmt.Errorf("health check failed: unexpected response status %s", resp.Status)
		}
		return fmt.Errorf("health check failed: unexpected response status %s: %s", resp.Status, message)
	}
	return nil
}

type config struct {
	address          *url.URL
	healthPath       string
	token            string
	rootPassword     string
	timeout          time.Duration
	transport        http.RoundTripper
	usernameProducer template.StringTemplate
}

func parseConfig(raw map[string]interface{}) (config, error) {
	addressString, err := strutil.GetString(raw, "address")
	if err != nil {
		return config{}, fmt.Errorf("invalid address: %w", err)
	}
	addressString = strings.TrimSpace(addressString)
	if addressString == "" {
		return config{}, errors.New("address is required")
	}

	address, err := url.Parse(addressString)
	if err != nil {
		return config{}, fmt.Errorf("invalid address: %w", err)
	}
	if address.Scheme != "http" && address.Scheme != "https" {
		return config{}, errors.New("address must use http or https")
	}
	if address.Host == "" {
		return config{}, errors.New("address must include a host")
	}
	if address.User != nil {
		return config{}, errors.New("address must not contain credentials")
	}
	if address.RawQuery != "" || address.Fragment != "" {
		return config{}, errors.New("address must not contain a query or fragment")
	}

	token, err := strutil.GetString(raw, "token")
	if err != nil {
		return config{}, fmt.Errorf("invalid token: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return config{}, errors.New("token is required")
	}
	if strings.ContainsAny(token, "\r\n") {
		return config{}, errors.New("token must not contain newlines")
	}

	rootPassword, err := strutil.GetString(raw, "password")
	if err != nil {
		return config{}, fmt.Errorf("invalid password: %w", err)
	}

	healthPath, err := strutil.GetString(raw, "health_path")
	if err != nil {
		return config{}, fmt.Errorf("invalid health_path: %w", err)
	}
	if healthPath == "" {
		healthPath = defaultHealthPath
	}
	if !strings.HasPrefix(healthPath, "/") {
		return config{}, errors.New("health_path must start with /")
	}
	if strings.ContainsAny(healthPath, "?#") {
		return config{}, errors.New("health_path must not contain a query or fragment")
	}
	healthPath = path.Clean(healthPath)

	timeout := defaultTimeout
	if rawTimeout, ok := raw["timeout"]; ok {
		timeout, err = parseutil.ParseDurationSecond(rawTimeout)
		if err != nil {
			return config{}, fmt.Errorf("invalid timeout: %w", err)
		}
		if timeout <= 0 {
			return config{}, errors.New("timeout must be greater than zero")
		}
	}

	rawUsernameTemplate, err := strutil.GetString(raw, "username_template")
	if err != nil {
		return config{}, fmt.Errorf("invalid username_template: %w", err)
	}
	if rawUsernameTemplate == "" {
		rawUsernameTemplate = defaultUsernameTemplate
	}
	usernameProducer, err := template.NewTemplate(template.Template(rawUsernameTemplate))
	if err != nil {
		return config{}, fmt.Errorf("invalid username_template: %w", err)
	}
	if _, err := usernameProducer.Generate(dbplugin.UsernameMetadata{}); err != nil {
		return config{}, fmt.Errorf("invalid username_template: %w", err)
	}

	transport, err := buildTransport(raw)
	if err != nil {
		return config{}, err
	}

	return config{
		address:          address,
		healthPath:       healthPath,
		token:            token,
		rootPassword:     rootPassword,
		timeout:          timeout,
		transport:        transport,
		usernameProducer: usernameProducer,
	}, nil
}

func buildTransport(raw map[string]interface{}) (http.RoundTripper, error) {
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport, nil
	}
	transport := baseTransport.Clone()

	caCert, err := strutil.GetString(raw, "ca_cert")
	if err != nil {
		return nil, fmt.Errorf("invalid ca_cert: %w", err)
	}
	serverName, err := strutil.GetString(raw, "tls_server_name")
	if err != nil {
		return nil, fmt.Errorf("invalid tls_server_name: %w", err)
	}
	if caCert == "" && serverName == "" {
		return transport, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if caCert != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caCert)) {
			return nil, errors.New("invalid ca_cert: no PEM certificates found")
		}
		tlsConfig.RootCAs = pool
	}
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

func formatExpiration(expiration time.Time) string {
	if expiration.IsZero() {
		return ""
	}
	return expiration.UTC().Format(time.RFC3339Nano)
}
