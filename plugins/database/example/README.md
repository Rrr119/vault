# Example database plugin

This directory is a reference implementation of a database secrets engine
plugin for a database that exposes an HTTP administration API. It shows how an
in-house database can use Vault's dynamic credential lifecycle without adding
database-specific code to Vault core.

The plugin implements `dbplugin.Plugin` from
`sdk/database/dbplugin/v5`. Vault continues to own the lease, TTL, password
generation, and revocation. The plugin only translates Vault operations into
calls to the database's user management API.

## API contract

The example expects a Bearer token and JSON over HTTP:

| Operation | Request |
| --- | --- |
| Connection check | `GET /health` |
| Create user | `POST /v1/users` |
| Update user | `PATCH /v1/users/{username}` |
| Delete user | `DELETE /v1/users/{username}` |

Create requests contain:

```json
{
  "username": "v-readonly-...",
  "password": "...",
  "expires_at": "2026-11-19T10:00:00Z",
  "statements": ["policy=readonly"]
}
```

Update requests contain `password`, `password_statements`, `expires_at`, and/or
`expiration_statements`. Delete requests return success for `204`, or `404` when
the user is already gone. A successful health check is any `2xx` response.

The `statements` fields are passed through unchanged from the Vault role. An
in-house API can use them for policy names or other database-specific
provisioning instructions. If your API has different routes or payloads, change
the request functions in `example.go`; Vault does not need to change.

## Configuration

| Field | Required | Description |
| --- | --- | --- |
| `address` | yes | Base HTTP(S) URL of the administration API. |
| `token` | yes | Bearer token used for administration requests. |
| `timeout` | no | Request timeout, for example `10s` or `30`. Defaults to `10s`. |
| `health_path` | no | Health endpoint path. Defaults to `/health`. |
| `username_template` | no | Vault username template. |
| `ca_cert` | no | PEM CA certificate used to verify an HTTPS endpoint. |
| `tls_server_name` | no | TLS server name override. |
| `username` / `password` | no | Root account fields used by `rotate-root` and included in error redaction. |

The plugin reports password credentials as its only supported credential type.

## Build and register

Build the binary and place it in Vault's configured plugin directory:

```shell-session
$ make example-database-plugin
$ cp bin/example-database-plugin /path/to/vault/plugins/
$ sha256sum /path/to/vault/plugins/example-database-plugin
```

Register the plugin and mount the database secrets engine:

```shell-session
$ vault write sys/plugins/catalog/database/example-database-plugin \
    sha256="<sha256>" \
    command="example-database-plugin"

$ vault secrets enable database
```

Configure the in-house database:

```shell-session
$ vault write database/config/inhouse \
    plugin_name=example-database-plugin \
    address="https://db-admin.internal.example" \
    token="..." \
    username="vault-root" \
    password="..." \
    allowed_roles="readonly"
```

Create a role. `creation_statements` are optional for this example, but are
forwarded to the create API when supplied:

```shell-session
$ vault write database/roles/readonly \
    db_name=inhouse \
    creation_statements="policy=readonly" \
    default_ttl=1h \
    max_ttl=24h

$ vault read database/creds/readonly
```

Vault revokes the generated account through `DELETE /v1/users/{username}` when
the lease expires or is revoked explicitly.

## Adapting for production

Treat this package as a template rather than a production integration:

- Replace the routes and JSON schema with your database's actual administration API.
- Keep all credentials in Vault connection configuration and never log request bodies.
- Make create and delete idempotent on the server side.
- Enforce expiration in the database as well as in Vault, so credentials stop working if Vault is unavailable.
- Restrict the administration token to user-management operations and rotate it independently.
- Add integration tests against a disposable instance of the target database.

The plugin process serves the same gRPC interface as the built-in database
plugins. No Vault core changes are required when replacing this example with a
real in-house implementation.
