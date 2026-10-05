# jmap-mcp

A small, read-only [MCP](https://modelcontextprotocol.io/) server that lets
ChatGPT connectors (developer mode) and claude.ai custom connectors read one
person's mailbox over [JMAP](https://jmap.io/) (RFC 8620/8621), e.g. on Stalwart.

It is an OAuth 2.1 **resource server only**. Users sign in at the
authorization server (Kanidm); this server validates the resulting access
tokens and talks to JMAP with its own fixed, read-only App Password.

## Connectors

Each MCP client application (a *connector*, e.g. Claude and ChatGPT) gets its
own OAuth client at Kanidm, because one OAuth client must not be shared
between applications. Kanidm issuers are per client, and Claude only uses the
first `authorization_servers` entry, so every connector also gets its own MCP
endpoint and its own protected resource metadata (RFC 9728):

| Connector | MCP endpoint | Metadata | Kanidm client |
| --- | --- | --- | --- |
| `claude` | `https://mail-mcp.gaato.net/claude/mcp` | `/.well-known/oauth-protected-resource/claude/mcp` | `mcp-jmap-claude` |
| `chatgpt` | `https://mail-mcp.gaato.net/chatgpt/mcp` | `/.well-known/oauth-protected-resource/chatgpt/mcp` | `mcp-jmap-chatgpt` |

An endpoint accepts only tokens issued by its own client (`iss` and `aud`
pinned), so a Claude token is rejected on the ChatGPT endpoint and vice versa.
All connectors share one JMAP client and the same allowed user.

The bare `/.well-known/oauth-protected-resource` is deliberately **not**
served (404): there is no single right issuer, and a client that guessed the
bare document would be sent to the wrong authorization server.

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
- **Tokens must be issued for this endpoint.** Every request to an MCP endpoint
  needs `Authorization: Bearer <token>`. The token must be a JWS with header
  `typ: at+jwt` (rejects ID tokens), signed ES256 (or RS256) by a key from the
  connector's JWKS, and carry the RFC 9068 claims `iss` (equal to the
  connector's issuer), `aud` (containing the connector's audience), `sub`,
  `client_id`, `iat`, `jti` and `exp` (`nbf` optional; 30 s leeway). `sub` must
  equal `OAUTH_ALLOWED_SUBJECT` exactly; `client_id` must equal the audience
  (Kanidm sets both to the client name). Scope `mail_read` is required.
- **Revocation.** Every token is also checked at Kanidm's introspection
  endpoint. Answers are cached per token (SHA-256 of the token, bounded
  cache): "active" for at most 60 s, so a revoked session stops working
  within a minute, and "inactive" for up to 5 minutes, so replaying a stolen
  revoked token does not turn into one introspection call per request.
  Concurrent checks of the same token share one call.
- **Signing keys.** JWKS is cached per connector and refetched after an hour
  or when an unknown `kid` shows up. Refetches are throttled to one per 30 s
  (also while no keys are cached), shared between concurrent requests and
  detached from the client's request. If refreshing fails, cached keys stay
  usable for a 10 minute grace period and then verification fails closed.
  JWKS and introspection requests never follow redirects. When the key server
  or introspection endpoint is unavailable the MCP endpoint answers `503`.
- **Kanidm conformance exception (RFC 8707).** The MCP authorization spec asks
  for tokens bound to the resource via RFC 8707 `resource`. Kanidm ignores
  `resource` and sets `aud` to the OAuth2 client name, so binding relies on the
  per-client issuer plus the audience pin instead. This only works if each
  OAuth2 client is used by exactly one connector of exactly one deployment:
  create one Kanidm client per connector per environment and never reuse a
  client elsewhere (another deployment accepting the same client's tokens
  would accept tokens minted for this one, and vice versa).
- Kanidm access tokens carry no username or email; `sub` is the account UUID.
- **No token passthrough.** The client's token is never sent to JMAP (which
  uses Basic auth with the App Password) and only ever leaves the process
  towards the introspection endpoint of the issuing server.
- **TLS only.** Every configured URL must be `https`; plain `http` is accepted
  only for loopback hosts (`127.0.0.0/8`, `::1`, `localhost`). URLs with
  credentials or fragments are rejected.
- **JMAP origin pinning.** The App Password is only ever sent to the origin of
  `JMAP_SESSION_URL` (plus `JMAP_ALLOWED_ORIGIN`, if set). Every redirect hop
  and the session's `apiUrl` must be on an allowed origin and pass the TLS
  rule, so a redirect or a tampered session document cannot send the
  credentials elsewhere or over plain http.
- **Secret file.** `JMAP_PASSWORD_FILE` must be a regular file (not a
  symlink) with no group/other permissions (e.g. `0400`).
- **Challenges.** `401` responses carry
  `WWW-Authenticate: Bearer resource_metadata="…", scope="mail_read"` (plus
  `error="invalid_token"` when a token was sent); a token without the scope
  gets `403` with `error="insufficient_scope"`. Rejection reasons are logged,
  not returned.
- **Email content is untrusted.**
  - Bodies are plain text: `textBody` is preferred; HTML is converted with the
    HTML5 parser (`golang.org/x/net/html`), keeping only visible text. Scripts,
    styles, `head`, `template`, `noscript`, `title`, `svg`, `textarea`,
    `iframe`, `object` and elements marked `hidden`, `aria-hidden="true"` or
    hidden by inline style (`display:none`, `visibility:hidden`,
    `font-size:0`, zero width/height, …; best effort) are dropped. Link
    targets are never shown, resolved or fetched.
  - Bodies are capped and wrapped in
    `<<<BEGIN/END UNTRUSTED EMAIL CONTENT nonce>>>` markers with a per-call
    random nonce; `<<<` and `>>>` inside the content are replaced with
    `‹‹‹`/`›››` (after entity decoding), so a message cannot fake a marker.
  - Invisible characters (Unicode format characters such as zero-width and
    bidi controls, tag characters, variation selectors, fillers,
    noncharacters; ZWJ is kept for emoji) and control characters are removed
    from bodies and from every field outside the markers.
  - Address lists are capped at 10 entries / about 1000 characters each
    (`(and N more)`); subjects, names and previews are length-capped.
  - Results carry a notice, and every tool description says which fields are
    untrusted third-party data. `search` results follow the ChatGPT contract
    exactly (`results: [{id, title, url}]`, no room for an extra field), so
    their titles start with `[untrusted email]` instead.
- **Logs** contain method, path, status, duration and rejection reasons, and
  for JMAP failures only the method, error type and HTTP status; never
  tokens, passwords, message content or upstream error descriptions.

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `LISTEN_ADDR` | no | Listen address, default `:8080` |
| `PUBLIC_BASE_URL` | yes | Public origin without path, e.g. `https://mail-mcp.gaato.net`. Connector `<name>` is served at `<base>/<name>/mcp`, which is also its RFC 9728 `resource`. |
| `CONNECTORS` | yes | Comma-separated connector names (`[a-z0-9][a-z0-9_-]*`), e.g. `claude,chatgpt` |
| `CONNECTOR_<NAME>_ISSUER` | yes | Exact `iss` for that connector, e.g. `https://id.home.gaato.net/oauth2/openid/mcp-jmap-claude`. `<NAME>` is the name upper-cased with `-` → `_`. |
| `CONNECTOR_<NAME>_AUDIENCE` | yes | Required `aud`; for Kanidm the client name, e.g. `mcp-jmap-claude` |
| `CONNECTOR_<NAME>_JWKS_URL` | no | Default `<issuer>/public_key.jwk` |
| `OAUTH_ALLOWED_SUBJECT` | yes | The only user allowed in, for all connectors: the Kanidm account UUID, lowercase with hyphens, compared exactly with `sub` |
| `OAUTH_INTROSPECTION_URL` | yes | e.g. `https://id.home.gaato.net/oauth2/token/introspect` (shared; no client auth needed with Kanidm) |
| `JMAP_SESSION_URL` | yes | e.g. `https://mail.example.net/.well-known/jmap` (redirects are followed; the primary mail account is used) |
| `JMAP_ALLOWED_ORIGIN` | no | A second origin (`https://host[:port]`) that redirects and the session's `apiUrl` may use, e.g. when `/.well-known/jmap` on the mail domain redirects to the JMAP host |
| `JMAP_USERNAME` | yes | JMAP login |
| `JMAP_PASSWORD_FILE` | yes | File containing the App Password (trailing newline ignored); regular file, mode `0400`/`0600` |

All URLs must be `https` (or `http` to a loopback host). The server refuses
to start if anything required is missing or malformed, if
a connector is listed twice (including names that map to the same variable
prefix, like `a-b` and `a_b`), or if two connectors share an issuer or an
audience.

Endpoints: `/<name>/mcp` (MCP Streamable HTTP, stateless) and
`/.well-known/oauth-protected-resource/<name>/mcp` for each connector, and
`/healthz`. Everything else, including the bare metadata path, is 404.

## Registering the Kanidm clients

One OAuth2 client per connector. Kanidm scope names must match
`^[0-9a-zA-Z_]+$`, hence `mail_read`. Leave out `openid`: no ID token is
needed, only the access token. Keep PKCE and ES256 (the defaults; RS256 via
legacy crypto is also accepted).

```fish
kanidm group create mcp_jmap_users
kanidm group add-members mcp_jmap_users gaato
kanidm person get gaato    # uuid -> OAUTH_ALLOWED_SUBJECT

# Claude
kanidm system oauth2 create mcp-jmap-claude "Mail for Claude" https://mail-mcp.gaato.net
kanidm system oauth2 update-scope-map mcp-jmap-claude mcp_jmap_users mail_read offline_access
kanidm system oauth2 add-redirect-url mcp-jmap-claude https://claude.ai/api/mcp/auth_callback
kanidm system oauth2 show-basic-secret mcp-jmap-claude

# ChatGPT
kanidm system oauth2 create mcp-jmap-chatgpt "Mail for ChatGPT" https://mail-mcp.gaato.net
kanidm system oauth2 update-scope-map mcp-jmap-chatgpt mcp_jmap_users mail_read offline_access
kanidm system oauth2 show-basic-secret mcp-jmap-chatgpt
# After creating the ChatGPT connector, add the callback URL its OAuth
# settings show (currently https://chatgpt.com/connector_platform_oauth_redirect):
kanidm system oauth2 add-redirect-url mcp-jmap-chatgpt https://chatgpt.com/connector_platform_oauth_redirect
```

Kanidm does not support dynamic client registration, so enter each client's
ID and secret in the matching connector's advanced OAuth settings, with the
matching endpoint URL (`…/claude/mcp` for Claude, `…/chatgpt/mcp` for
ChatGPT). Clients find Kanidm through the endpoint's protected resource
metadata; Kanidm serves both
`/.well-known/oauth-authorization-server/oauth2/openid/<client>` and
`<issuer>/.well-known/openid-configuration`.

## Build and run

```fish
mise exec -- go test ./...
podman build --platform linux/amd64,linux/arm64 --manifest localhost/jmap-mcp .
```

The image is a static (`CGO_ENABLED=0`) binary on `distroless/static`,
running as UID 65532. Both base images are pinned by digest in the
`Containerfile`; refresh them with `skopeo inspect --format '{{.Digest}}'`.

The HTTP server uses a 30 s read timeout, 90 s write timeout (above the 30 s
JMAP timeout; stateless responses end with their tool call), 64 KiB header
limit and 256 KiB MCP request body limit.

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
Environment=PUBLIC_BASE_URL=https://mail-mcp.gaato.net
Environment=CONNECTORS=claude,chatgpt
Environment=CONNECTOR_CLAUDE_ISSUER=https://id.home.gaato.net/oauth2/openid/mcp-jmap-claude
Environment=CONNECTOR_CLAUDE_AUDIENCE=mcp-jmap-claude
Environment=CONNECTOR_CHATGPT_ISSUER=https://id.home.gaato.net/oauth2/openid/mcp-jmap-chatgpt
Environment=CONNECTOR_CHATGPT_AUDIENCE=mcp-jmap-chatgpt
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
