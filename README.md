# jmap-mcp

A small, read-only [MCP](https://modelcontextprotocol.io/) server that lets
ChatGPT connectors (developer mode) and claude.ai custom connectors read one
person's mailbox over [JMAP](https://jmap.io/) (RFC 8620/8621), e.g. on Stalwart.

It is an OAuth 2.1 **resource server only**. Users sign in at the
authorization server (Kanidm); this server validates the resulting access
tokens and talks to JMAP with its own fixed, read-only App Password.

## Tools

All tools are annotated `readOnlyHint: true`, `destructiveHint: false`,
`openWorldHint: false`.

| Tool | Purpose |
| --- | --- |
| `search` | ChatGPT connector contract: `query` → `{results: [{id, title, url}]}` |
| `fetch` | ChatGPT connector contract: `id` → `{id, title, text, url, metadata}` |
| `list_mailboxes` | Mailboxes with id, name, role, counts |
| `search_emails` | `text`, `mailbox` (id, name or role), `from`, `to`, `subject`, `after`, `before`, `limit` (default 20, max 100) |
| `get_email` | `id`, `max_chars` (default 20000, max 100000) |
| `get_thread` | `thread_id`, `limit` (default 50, max 100) → email summaries |

`url` is an RFC 2392 `mid:` URL built from the Message-ID (empty if there is
none); a mailbox item has no public web URL.

## Security model

- **Read-only by construction.** The JMAP client only issues `Mailbox/get`,
  `Email/query`, `Email/get` and `Thread/get`; any other method name is refused
  before a request is made. A test greps the source for `/set`, `/copy`,
  `/import`, `EmailSubmission` and blob transfer endpoints. Give the App
  Password read-only permissions as a second line of defence.
- **Tokens must be issued for this server.** Every request to the MCP endpoint
  needs `Authorization: Bearer <token>`. The token must be a JWS with header
  `typ: at+jwt` (rejects ID tokens), signed ES256 (or RS256) by a key from the
  issuer's JWKS (cached; refetched on an unknown `kid`, rate limited), with
  `iss` equal to `OAUTH_ISSUER`, `aud` containing `OAUTH_AUDIENCE`, valid
  `exp`/`nbf`/`iat` (30 s leeway), scope `mail_read`, and the subject claim
  equal to `OAUTH_ALLOWED_SUBJECT`. Optionally the token is checked at the
  introspection endpoint to catch revoked sessions (cached for a minute).
  - Kanidm sets `aud` to the OAuth2 client name, not the MCP URL, and ignores
    the RFC 8707 `resource` parameter; per-client issuers and the audience pin
    together make sure the token was minted for this client.
  - Kanidm access tokens carry no username or email; `sub` is the account UUID.
- **No token passthrough.** The client's token is never sent to JMAP (which
  uses Basic auth with the App Password) and only ever leaves the process
  towards the introspection endpoint of the issuing server.
- **Challenges.** `401` responses carry
  `WWW-Authenticate: Bearer resource_metadata="…", scope="mail_read"` (plus
  `error="invalid_token"` when a token was sent); a token without the scope
  gets `403` with `error="insufficient_scope"`. Rejection reasons are logged,
  not returned.
- **Email content is untrusted.** Bodies are returned as plain text (HTML is
  crudely stripped; `textBody` is preferred), capped, and wrapped in
  `<<<BEGIN/END UNTRUSTED EMAIL CONTENT nonce>>>` markers with a per-call random
  nonce so a message cannot fake the end marker. Results carry a notice telling
  the model to treat message-derived fields as data. Nothing in a message is
  ever fetched or followed.
- **Logs** contain method, path, status, duration and rejection reasons; never
  tokens, passwords or message content.

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `LISTEN_ADDR` | no | Listen address, default `:8080` |
| `PUBLIC_URL` | yes | Public URL of the MCP endpoint, e.g. `https://mail-mcp.gaato.net/mcp`. Used as the RFC 9728 `resource`; its path is the MCP route. |
| `OAUTH_ISSUER` | yes | Exact `iss`, e.g. `https://id.home.gaato.net/oauth2/openid/mcp_jmap` (Kanidm issuers are per client) |
| `OAUTH_AUDIENCE` | yes | Required `aud` value; for Kanidm the client name, e.g. `mcp_jmap` |
| `OAUTH_JWKS_URL` | no | Default `$OAUTH_ISSUER/public_key.jwk` |
| `OAUTH_ALLOWED_SUBJECT` | yes | The only user allowed in (Kanidm: the person's UUID) |
| `OAUTH_SUBJECT_CLAIM` | no | Claim compared with `OAUTH_ALLOWED_SUBJECT`, default `sub` |
| `OAUTH_INTROSPECTION_URL` | no | e.g. `https://id.home.gaato.net/oauth2/token/introspect` (no client auth needed with Kanidm) |
| `JMAP_SESSION_URL` | yes | e.g. `https://mail.example.net/.well-known/jmap` (redirects are followed; the primary mail account is used) |
| `JMAP_USERNAME` | yes | JMAP login |
| `JMAP_PASSWORD_FILE` | yes | File containing the App Password (trailing newline ignored) |

The server refuses to start if anything required is missing or malformed.

Endpoints: `PUBLIC_URL`'s path (MCP Streamable HTTP, stateless),
`/.well-known/oauth-protected-resource` and
`/.well-known/oauth-protected-resource/<mcp path>` (RFC 9728), `/healthz`.

## Registering the Kanidm client

Kanidm scope names must match `^[0-9a-zA-Z_]+$`, hence `mail_read`. Leave out
`openid`: no ID token is needed, only the access token.

```fish
kanidm group create mcp_jmap_users
kanidm group add-members mcp_jmap_users gaato
kanidm system oauth2 create mcp_jmap "Mail (MCP)" https://mail-mcp.gaato.net
kanidm system oauth2 update-scope-map mcp_jmap mcp_jmap_users mail_read offline_access
# Redirect URLs: use exactly what each connector's OAuth settings show, e.g.
kanidm system oauth2 add-redirect-url mcp_jmap https://claude.ai/api/mcp/auth_callback
kanidm system oauth2 add-redirect-url mcp_jmap https://chatgpt.com/connector_platform_oauth_redirect
kanidm system oauth2 show-basic-secret mcp_jmap   # client secret for the connector
kanidm person get gaato                           # uuid -> OAUTH_ALLOWED_SUBJECT
```

Keep PKCE and ES256 (the defaults; do not enable legacy crypto unless needed,
RS256 is still accepted). Kanidm does not support dynamic client registration,
so enter the client ID (`mcp_jmap`) and secret in the connector's advanced
OAuth settings. Clients discover Kanidm from the protected resource metadata;
Kanidm serves both `/.well-known/oauth-authorization-server/oauth2/openid/mcp_jmap`
and `<issuer>/.well-known/openid-configuration`.

## Build and run

```fish
mise exec -- go test ./...
podman build --platform linux/amd64,linux/arm64 --manifest localhost/jmap-mcp .
```

The image is a static (`CGO_ENABLED=0`) binary on `distroless/static`,
running as UID 65532.

### Quadlet example

`/etc/containers/systemd/jmap-mcp.container`, behind a TLS reverse proxy for
`mail-mcp.gaato.net`:

```ini
[Unit]
Description=Read-only JMAP MCP server
After=network-online.target

[Container]
Image=localhost/jmap-mcp:latest
PublishPort=127.0.0.1:8787:8080
Environment=PUBLIC_URL=https://mail-mcp.gaato.net/mcp
Environment=OAUTH_ISSUER=https://id.home.gaato.net/oauth2/openid/mcp_jmap
Environment=OAUTH_AUDIENCE=mcp_jmap
Environment=OAUTH_ALLOWED_SUBJECT=00000000-0000-0000-0000-000000000000
Environment=OAUTH_INTROSPECTION_URL=https://id.home.gaato.net/oauth2/token/introspect
Environment=JMAP_SESSION_URL=https://mail.example.net/.well-known/jmap
Environment=JMAP_USERNAME=you@example.net
Environment=JMAP_PASSWORD_FILE=/run/secrets/jmap-app-password
# podman secret create jmap-app-password ./app-password
Secret=jmap-app-password,type=mount,target=jmap-app-password,uid=65532,mode=0400
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL

[Service]
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

The SDK's DNS-rebinding guard is disabled because it rejects proxied requests
arriving on a loopback listener; every MCP request needs a valid bearer token
anyway.
