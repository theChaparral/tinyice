# TinyIce Auth Overhaul: Passkeys, OIDC, and Onboarding

**Date:** 2026-03-15
**Status:** Draft

## Summary

Add three auth capabilities to TinyIce:
1. **First-run onboarding wizard** — web-based setup replacing auto-generated passwords
2. **WebAuthn/Passkey** support for passwordless login
3. **Multi-provider OIDC** (Google, GitHub, generic) with open registration and admin approval

## 1. First-Run Onboarding Wizard

### Current Behavior
When `tinyice.json` doesn't exist, the server generates random passwords, prints them to the console, and starts normally. No UI for initial setup.

### New Behavior
When no config exists, the server starts in **setup mode**:
- Only `/setup` is accessible; all other routes redirect to it
- A single-use setup token is printed to the console (prevents network attackers from claiming the instance)
- The wizard walks the admin through:
  1. **Enter setup token** (from console output)
  2. **Set admin credentials** — choose username and password
  3. **Register passkey** (optional) — browser WebAuthn ceremony
  4. **Configure OIDC providers** (optional) — add Google, GitHub, or generic OIDC
  5. **Configure SMTP** (optional) — for email notifications on pending user requests
  6. **Done** — config is written, server transitions to normal mode without restart

### Security
- Setup token: 32-byte random hex, printed to stdout, required to access `/setup`
- Token is single-use; once setup completes, the `/setup` endpoint returns 404 permanently
- Setup state tracked via `setup_complete` boolean in config

### Endpoints
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/setup` | Serve setup wizard page |
| POST | `/setup/verify-token` | Validate setup token |
| POST | `/setup/complete` | Finalize setup, write config |

## 2. WebAuthn / Passkeys

### Library
`github.com/go-webauthn/webauthn` — mature, well-maintained Go WebAuthn library.

### Credential Storage
Passkey credentials stored per-user in `tinyice.json`:

```json
{
  "users": {
    "admin": {
      "username": "admin",
      "password": "$2a$12$...",
      "role": "superadmin",
      "passkeys": [
        {
          "id": "base64-credential-id",
          "public_key": "base64-public-key",
          "aaguid": "device-identifier",
          "name": "MacBook Pro",
          "created_at": "2026-03-15T10:00:00Z",
          "last_used": "2026-03-15T10:00:00Z",
          "sign_count": 0
        }
      ]
    }
  }
}
```

### Registration Flow
1. Client calls `POST /api/passkey/register/begin` (requires active session)
2. Server generates challenge, stores in session (60s expiry), returns `PublicKeyCredentialCreationOptions`
3. Browser executes `navigator.credentials.create()` — user touches biometric/security key
4. Client sends attestation to `POST /api/passkey/register/finish`
5. Server validates, stores credential in user record, saves config

### Login Flow
1. Client calls `POST /api/passkey/login/begin` (no session required)
2. Server generates challenge, stores server-side (60s expiry), returns `PublicKeyCredentialRequestOptions` with `allowCredentials: []` (discoverable credentials)
3. Browser executes `navigator.credentials.get()` — user selects passkey
4. Client sends assertion to `POST /api/passkey/login/finish`
5. Server validates signature against stored public key, creates session

### Where Passkeys Are Registered
- **Admin:** During onboarding wizard (step 3)
- **All users:** Self-service from profile/settings page

### Endpoints
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/passkey/register/begin` | Start registration ceremony (authed) |
| POST | `/api/passkey/register/finish` | Complete registration (authed) |
| POST | `/api/passkey/login/begin` | Start login ceremony (unauthed) |
| POST | `/api/passkey/login/finish` | Complete login ceremony (unauthed) |
| DELETE | `/api/passkey/{id}` | Remove a passkey (authed) |

## 3. Multi-Provider OIDC

### Libraries
- `github.com/coreos/go-oidc/v3` — OIDC discovery and ID token verification
- `golang.org/x/oauth2` — OAuth2 flow

### Provider Configuration
Stored in `tinyice.json`:

```json
{
  "oidc_providers": [
    {
      "id": "google",
      "name": "Google",
      "client_id": "123456.apps.googleusercontent.com",
      "client_secret": "GOCSPX-...",
      "discovery_url": "https://accounts.google.com/.well-known/openid-configuration",
      "icon": "google",
      "enabled": true
    },
    {
      "id": "github",
      "name": "GitHub",
      "client_id": "...",
      "client_secret": "...",
      "discovery_url": "https://token.actions.githubusercontent.com/.well-known/openid-configuration",
      "icon": "github",
      "enabled": true
    },
    {
      "id": "corporate-sso",
      "name": "Corporate SSO",
      "client_id": "...",
      "client_secret": "...",
      "discovery_url": "https://sso.company.com/.well-known/openid-configuration",
      "icon": "key",
      "enabled": true
    }
  ]
}
```

Ships with well-known presets for Google and GitHub. Admin can add any OIDC-compliant provider via discovery URL.

### Login Flow
1. User clicks provider button on login page
2. `GET /auth/{provider-id}` — server generates state (HMAC-signed, 10min expiry), redirects to provider's authorization endpoint
3. User authenticates with provider
4. Provider redirects to `GET /auth/{provider-id}/callback` with authorization code
5. Server exchanges code for ID token, extracts email and name
6. **Email matches existing user's `linked_emails`:** Create session, log in
7. **Email not linked to any user:** Create pending registration request

### GitHub Note
GitHub is not a standard OIDC provider. Implementation will use GitHub's OAuth2 API (`https://github.com/login/oauth/authorize`) with a `/user` API call to get email, wrapped to present the same interface as OIDC providers.

### Endpoints
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/auth/{provider}` | Initiate OIDC redirect |
| GET | `/auth/{provider}/callback` | Handle OIDC callback |
| GET | `/api/oidc/providers` | List configured providers (public — for login page) |
| POST | `/api/oidc/providers` | Add/update provider (admin) |
| DELETE | `/api/oidc/providers/{id}` | Remove provider (admin) |

## 4. Pending User Approval

### Flow
1. Unknown email authenticates via OIDC
2. Server creates pending request:
   ```json
   {
     "id": "random-uuid",
     "email": "newuser@gmail.com",
     "name": "Jane Doe",
     "provider": "google",
     "requested_at": "2026-03-15T10:00:00Z",
     "status": "pending"
   }
   ```
3. If SMTP configured, email notification sent to admin
4. Admin sees pending requests in dashboard (notification badge)
5. Admin approves (assigns username + role) or denies
6. On approval: user record created with linked email, user can log in via OIDC

### Storage
Pending users stored in `tinyice.json` under `pending_users` array. On approval, moved to `users` map. On denial, removed.

### Email Notification
Optional SMTP configuration:
```json
{
  "smtp": {
    "enabled": false,
    "host": "smtp.gmail.com",
    "port": 587,
    "from": "tinyice@mystation.com",
    "username": "...",
    "password": "..."
  }
}
```

When a new request comes in and SMTP is enabled, sends a simple text email to all superadmin users (if they have a linked email).

### Admin Endpoints
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/pending-users` | List pending requests |
| POST | `/api/pending-users/{id}/approve` | Approve with role assignment |
| POST | `/api/pending-users/{id}/deny` | Deny request |

## 5. Login Page UI

### Layout (Unified, top-to-bottom)
1. **Passkey button** — "Sign in with Passkey" (only shown if WebAuthn is supported by browser)
2. **OIDC provider buttons** — dynamically rendered from configured providers (only shown if any configured)
3. **Divider** — "or"
4. **Username/password form** — existing form, always shown as fallback
5. **"Request Access" link** — if OIDC providers are configured, link to a page explaining how to request access

### Data Injection
Login page receives available auth methods via `window.__TINYICE__`:
```json
{
  "passkeys_enabled": true,
  "oidc_providers": [
    { "id": "google", "name": "Google", "icon": "google" },
    { "id": "github", "name": "GitHub", "icon": "github" }
  ]
}
```

## 6. Config Schema Changes

Full updated `tinyice.json` structure (new fields marked with `// NEW`):

```json
{
  "setup_complete": true,                    // NEW
  "server_name": "My Station",
  "admin_user": "admin",
  "admin_password": "$2a$12$...",
  "default_source_password": "$2a$12$...",
  "users": {
    "admin": {
      "username": "admin",
      "password": "$2a$12$...",
      "role": "superadmin",
      "passkeys": [],                        // NEW
      "linked_emails": ["admin@gmail.com"]   // NEW
    }
  },
  "oidc_providers": [],                      // NEW
  "pending_users": [],                       // NEW
  "smtp": {                                  // NEW
    "enabled": false,
    "host": "",
    "port": 587,
    "from": "",
    "username": "",
    "password": ""
  },
  "webauthn": {                              // NEW
    "rp_id": "localhost",
    "rp_name": "TinyIce",
    "rp_origins": ["https://localhost:8443"]
  },
  "mounts": { ... }
}
```

## 7. Security Considerations

| Concern | Mitigation |
|---------|------------|
| Setup endpoint hijacking | Single-use token printed to console, required to access `/setup` |
| WebAuthn requires secure context | HTTPS or localhost only (browser-enforced) |
| OIDC CSRF | State parameter with HMAC signature and 10min expiry |
| Passkey replay | Server-side challenge with 60s expiry, sign count verification |
| Pending user spam | Rate limit OIDC callback per IP, admin can bulk-deny |
| SMTP credential storage | Config file is mode 0600 (owner-only read) |
| Session fixation | New session ID generated on every successful login |

## 8. New Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/go-webauthn/webauthn` | WebAuthn/passkey ceremonies |
| `github.com/coreos/go-oidc/v3` | OIDC discovery and token verification |
| `golang.org/x/oauth2` | OAuth2 authorization flow |
| `net/smtp` (stdlib) | Email notifications |
| `github.com/google/uuid` | Pending user request IDs |

## 9. Files to Create/Modify

### New Files
| File | Purpose |
|------|---------|
| `server/auth_passkey.go` | WebAuthn registration and login handlers |
| `server/auth_oidc.go` | OIDC provider management and auth flow |
| `server/handlers_setup.go` | First-run onboarding wizard endpoints |
| `server/handlers_pending_users.go` | Pending user approval endpoints |
| `server/email.go` | SMTP notification helpers |
| `server/frontend/src/pages/Setup.tsx` | Onboarding wizard UI |
| `server/frontend/src/entries/setup.tsx` | Setup page entry point |
| `server/frontend/src/entries/setup.html` | Setup page HTML shell |
| `server/frontend/src/components/PasskeyButton.tsx` | Passkey login/register button |
| `server/frontend/src/components/OIDCButtons.tsx` | OIDC provider login buttons |
| `server/frontend/src/pages/admin/PendingUsers.tsx` | Admin pending users management |

### Modified Files
| File | Change |
|------|--------|
| `main.go` | Replace auto-password generation with setup mode detection |
| `config/config.go` | Add new fields: passkeys, linked_emails, oidc_providers, pending_users, smtp, webauthn |
| `server/auth.go` | Integrate passkey and OIDC session creation, setup mode redirect |
| `server/server.go` | Register new routes |
| `server/shell.go` | Inject auth method data into `window.__TINYICE__` |
| `server/frontend/src/pages/Login.tsx` | Add passkey button, OIDC buttons, new layout |
| `server/frontend/src/pages/admin/Admin.tsx` | Add pending users section, OIDC config |
| `server/frontend/vite.config.ts` | Add setup entry point |
