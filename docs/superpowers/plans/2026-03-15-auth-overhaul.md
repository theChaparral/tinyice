# Auth Overhaul Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add passkey (WebAuthn), multi-provider OIDC, first-run onboarding wizard, and pending user approval to TinyIce.

**Architecture:** Layered on the existing session-based auth system. New Go handlers for WebAuthn ceremonies, OIDC flows, setup wizard, and pending user management. Frontend gets a new Setup page and enhanced Login page. Config schema extended with new fields, backward-compatible with existing deployments.

**Tech Stack:** Go 1.25 (go-webauthn, go-oidc, go-mail), Preact + TypeScript + Tailwind CSS, SQLite (existing), JSON config file.

**Spec:** `docs/superpowers/specs/2026-03-15-auth-overhaul-design.md`

---

## File Structure

### New Go Files
| File | Responsibility |
|------|---------------|
| `server/auth_passkey.go` | WebAuthn registration/login ceremony handlers, passkey CRUD |
| `server/auth_oidc.go` | OIDC provider management, OAuth2 redirect/callback, account linking |
| `server/handlers_setup.go` | First-run onboarding wizard endpoints (token verify, setup complete) |
| `server/handlers_pending_users.go` | Pending user list/approve/deny API endpoints |
| `server/email.go` | SMTP email notification helper (go-mail wrapper) |

### New Frontend Files
| File | Responsibility |
|------|---------------|
| `server/frontend/src/pages/Setup.tsx` | Onboarding wizard multi-step UI |
| `server/frontend/src/entries/setup.tsx` | Setup page Preact entry point |
| `server/frontend/src/entries/setup.html` | Setup page HTML shell |
| `server/frontend/src/components/PasskeyButton.tsx` | Reusable passkey register/login button |
| `server/frontend/src/components/OIDCButtons.tsx` | Reusable OIDC provider login buttons |
| `server/frontend/src/pages/admin/PendingUsers.tsx` | Admin pending users management page |

### Modified Files
| File | Changes |
|------|---------|
| `config/config.go` | Add `Passkey`, `OIDCProvider`, `PendingUser`, `SMTPConfig`, `WebAuthnConfig` structs; new fields on `User` and `Config`; atomic `SaveConfig` with mutex |
| `main.go` | Replace `ensureConfigExists()` with setup mode detection; print setup token |
| `server/server.go` | Add `configMu sync.Mutex`, `setupToken string`, `webAuthn *webauthn.WebAuthn` to Server struct; register new routes; add setup mode middleware |
| `server/auth.go` | Add `createSession()` helper (extracted from `handleLogin`); setup mode redirect check |
| `server/shell.go` | Inject `passkeys_enabled` and `oidc_providers` into `BasePageData` |
| `server/frontend/src/pages/Login.tsx` | Add passkey button, OIDC provider buttons, new unified layout |
| `server/frontend/src/pages/admin/AdminLayout.tsx` | Add PendingUsers route |
| `server/frontend/src/components/Sidebar.tsx` | Add pending users nav item with badge |
| `server/frontend/vite.config.ts` | Add `setup` entry point |
| `go.mod` / `go.sum` | Add new dependencies |

---

## Chunk 1: Config Schema & Dependencies

### Task 1: Add New Dependencies

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add Go dependencies**

Run:
```bash
cd /Users/dev/dev/tinyice
go get github.com/go-webauthn/webauthn/webauthn
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2
go get github.com/wneessen/go-mail
go get github.com/google/uuid
```

- [ ] **Step 2: Verify go.mod updated**

Run: `grep -E "(go-webauthn|go-oidc|oauth2|go-mail)" go.mod`
Expected: All four packages listed.

- [ ] **Step 3: Add frontend dependency for WebAuthn**

Run:
```bash
cd /Users/dev/dev/tinyice/server/frontend
npm install @simplewebauthn/browser@^11
```

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum server/frontend/package.json server/frontend/package-lock.json
git commit -m "deps: add webauthn, oidc, oauth2, go-mail, simplewebauthn"
```

---

### Task 2: Extend Config Schema

**Files:**
- Modify: `config/config.go:15-127`

- [ ] **Step 1: Add new types and constants**

Add after line 12 (after `RoleAdmin = "admin"`):

```go
const RoleDJ = "dj"
```

Add after the `User` struct (after line 20):

```go
type PasskeyCredential struct {
	ID            string `json:"id"`             // base64url credential ID
	RawCredential string `json:"raw_credential"` // full webauthn.Credential as base64 JSON
	Name          string `json:"name"`           // human-readable name e.g. "MacBook Pro"
	CreatedAt     string `json:"created_at"`
	LastUsed      string `json:"last_used"`
}

type OIDCProvider struct {
	ID           string `json:"id"`            // e.g. "google", "github", "corporate-sso"
	Name         string `json:"name"`          // Display name
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	DiscoveryURL string `json:"discovery_url"` // empty for GitHub (special-cased)
	Icon         string `json:"icon"`          // "google", "github", "key"
	Enabled      bool   `json:"enabled"`
}

type PendingUser struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Provider    string `json:"provider"`     // which OIDC provider they used
	RequestedAt string `json:"requested_at"`
	DeniedAt    string `json:"denied_at,omitempty"` // set if previously denied
}

type SMTPConfig struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	From     string `json:"from"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type WebAuthnConfig struct {
	RPID      string   `json:"rp_id"`
	RPName    string   `json:"rp_name"`
	RPOrigins []string `json:"rp_origins"`
}
```

- [ ] **Step 2: Extend User struct**

Change the `User` struct to:

```go
type User struct {
	Username     string              `json:"username"`
	Password     string              `json:"password"`
	Role         string              `json:"role"`
	Mounts       map[string]string   `json:"mounts"`
	Passkeys     []*PasskeyCredential `json:"passkeys,omitempty"`
	LinkedEmails []string            `json:"linked_emails,omitempty"`
}
```

- [ ] **Step 3: Extend Config struct**

Add these fields to the `Config` struct, after the `Users` field (line 126):

```go
	// Auth: Setup & Onboarding
	SetupComplete bool `json:"setup_complete"`

	// Auth: OIDC
	OIDCProviders []*OIDCProvider `json:"oidc_providers,omitempty"`
	PendingUsers  []*PendingUser  `json:"pending_users,omitempty"`

	// Auth: WebAuthn
	WebAuthn *WebAuthnConfig `json:"webauthn,omitempty"`

	// Auth: Email Notifications
	SMTP *SMTPConfig `json:"smtp,omitempty"`
```

- [ ] **Step 4: Update setDefaults for migration compatibility**

Add to `initMapsAndArrays()` (after line 285):

```go
	if config.OIDCProviders == nil {
		config.OIDCProviders = make([]*OIDCProvider, 0)
	}
	if config.PendingUsers == nil {
		config.PendingUsers = make([]*PendingUser, 0)
	}
```

Add to `setBasicDefaults()` (after line 246):

```go
	// Existing configs are already set up
	if config.AdminPassword != "" && !config.SetupComplete {
		config.SetupComplete = true
	}
```

- [ ] **Step 5: Add atomic SaveConfig with mutex**

Replace the existing `SaveConfig` method:

```go
func (c *Config) SaveConfig() error {
	data, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	tmpPath := c.ConfigPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, c.ConfigPath)
}
```

- [ ] **Step 6: Verify it compiles**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: No errors.

- [ ] **Step 7: Commit**

```bash
git add config/config.go
git commit -m "feat(config): add passkey, OIDC, pending user, SMTP, and WebAuthn schema"
```

---

## Chunk 2: Session Helpers & Setup Mode Infrastructure

### Task 3: Extract Session Creation Helper

**Files:**
- Modify: `server/auth.go:296-349`

- [ ] **Step 1: Add createSession helper**

Add this new method before `handleLogin` (before line 296):

```go
// createSession generates a new session for the given user and sets the sid cookie.
// Returns the CSRF token for the new session.
func (s *Server) createSession(w http.ResponseWriter, r *http.Request, user *config.User) string {
	b := make([]byte, 32)
	rand.Read(b)
	sid := hex.EncodeToString(b)

	cb := make([]byte, 32)
	rand.Read(cb)
	csrf := hex.EncodeToString(cb)

	s.sessionsMu.Lock()
	s.sessions[sid] = &session{User: user, CSRFToken: csrf}
	s.sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7,
	})

	return csrf
}
```

- [ ] **Step 2: Refactor handleLogin to use createSession and support JSON errors**

Replace lines 320-341 in `handleLogin` (the session creation block) with:

```go
		s.recordAuthSuccess(host)
		s.createSession(w, r, user)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
```

Also update the error responses in `handleLogin` to return JSON when the request accepts it (fetch-based login from the Preact frontend). Replace the two error blocks that call `s.shell.Render(w, "login", ...)` with a helper check:

```go
		// Check if request is from fetch (Accept: application/json or X-Requested-With)
		if r.Header.Get("Accept") == "application/json" || r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
			jsonError(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		// Otherwise render HTML login page with error
		pageData := s.BasePageData("")
		pageData["error"] = "Invalid username or password"
		s.shell.Render(w, "login", "Login — "+s.Config.PageTitle, pageData)
		return
```

And update the Login.tsx fetch to send `Accept: application/json`:

```tsx
const res = await fetch('/login', {
  method: 'POST',
  body: formData,
  headers: { 'Accept': 'application/json' },
})
```

- [ ] **Step 3: Verify it compiles and login still works**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: No errors.

- [ ] **Step 4: Commit**

```bash
git add server/auth.go
git commit -m "refactor(auth): extract createSession helper for reuse by passkey/OIDC"
```

---

### Task 4: Setup Mode Infrastructure

**Files:**
- Modify: `server/server.go:52-113`
- Modify: `main.go:392-447`
- Create: `server/handlers_setup.go`

- [ ] **Step 1: Add setup fields to Server struct**

Add to the `Server` struct (after `done chan struct{}` on line 79):

```go
	configMu   sync.Mutex // protects config writes
	setupToken string     // single-use token for first-run setup (empty = setup complete)
```

- [ ] **Step 2: Modify main.go ensureConfigExists**

Replace the entire `ensureConfigExists()` function with:

```go
func ensureConfigExists() string {
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		logger.L.Info("Config file not found — starting in setup mode...")

		// Generate setup token
		setupToken := generateRandomString(32)

		// Create minimal config with setup_complete = false
		defaultCfg := config.Config{
			BindHost:     *bindHost,
			Port:         "8000",
			HostName:     "localhost",
			Location:     "Earth",
			AdminEmail:   "admin@localhost",
			PageTitle:    "TinyIce",
			PageSubtitle: "Live streaming network powered by Go",
			UseHTTPS:     false,
			HTTPSPort:    "443",
		}

		data, _ := json.MarshalIndent(defaultCfg, "", "    ")
		if err := os.WriteFile(*configPath, data, 0600); err != nil {
			logger.L.Fatalf("Failed to create config: %v", err)
		}

		fmt.Println("**************************************************")
		fmt.Println("  FIRST RUN: SETUP MODE")
		fmt.Println("")
		fmt.Printf("  Open your browser and navigate to:\n")
		fmt.Printf("    http://localhost:8000/setup\n")
		fmt.Println("")
		fmt.Printf("  Setup Token: %s\n", setupToken)
		fmt.Println("")
		fmt.Println("  You will need this token to complete setup.")
		fmt.Println("**************************************************")

		return setupToken
	}

	logger.L.Infow("Starting TinyIce with existing configuration", "path", *configPath)
	return ""
}
```

Update the call site in `main()` (around line 108):

```go
	setupToken := ensureConfigExists()
```

And pass it to the server (modify the `NewServer` call around line 142):

```go
	srv := server.NewServer(cfg, authLogger, Version, Commit, setupToken)
```

- [ ] **Step 3: Update NewServer signature**

In `server/server.go`, update `NewServer` to accept the setup token:

```go
func NewServer(cfg *config.Config, authLog *zap.SugaredLogger, version, commit, setupToken string) *Server {
```

And set it in the returned struct:

```go
		setupToken:   setupToken,
```

- [ ] **Step 4: Add setup mode middleware and register setup routes**

Register setup routes alongside all other routes. Use a middleware wrapper around the entire mux that checks `SetupComplete` on every request (not at route-registration time), so that after setup completes the server transitions to normal mode without a restart.

Add setup routes in `setupRoutes()` alongside the existing routes (after the login/logout routes):

```go
	// Setup wizard endpoints
	mux.HandleFunc("/setup", s.handleSetup)
	mux.HandleFunc("/setup/verify-token", s.handleSetupVerifyToken)
	mux.HandleFunc("/setup/complete", s.handleSetupComplete)
```

Then, in `Start()`, wrap the mux with a setup-mode middleware. Change the line `mux := s.setupRoutes()` to:

```go
	mux := s.setupRoutes()
	handler := s.withSetupGuard(mux)
```

And use `handler` instead of `mux` in the `http.Server{Handler: ...}` and `s.startHTTPS(handler, addr)` calls.

Add this method to `server/server.go`:

```go
// withSetupGuard wraps a handler to enforce setup mode.
// When setup is not complete, only /setup*, /assets/ are accessible; everything else redirects to /setup.
// This check runs per-request so the server transitions to normal mode immediately after setup completes.
func (s *Server) withSetupGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Config.SetupComplete {
			path := r.URL.Path
			if path == "/setup" || strings.HasPrefix(path, "/setup/") || strings.HasPrefix(path, "/assets/") {
				next.ServeHTTP(w, r)
				return
			}
			http.Redirect(w, r, "/setup", http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

This ensures that once `handleSetupComplete` sets `SetupComplete = true`, subsequent requests immediately pass through to the normal routes without a server restart.

- [ ] **Step 5: Create handlers_setup.go with stub handlers**

Create `server/handlers_setup.go`:

```go
package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
)

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.Config.SetupComplete {
		http.NotFound(w, r)
		return
	}
	pageData := s.BasePageData("")
	s.shell.Render(w, "setup", "Setup — "+s.Config.PageTitle, pageData)
}

func (s *Server) handleSetupVerifyToken(w http.ResponseWriter, r *http.Request) {
	if s.Config.SetupComplete || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.setupToken)) != 1 {
		jsonError(w, "Invalid setup token", http.StatusForbidden)
		return
	}

	jsonResponse(w, map[string]bool{"valid": true})
}

func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if s.Config.SetupComplete || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	var req struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify token again
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.setupToken)) != 1 {
		jsonError(w, "Invalid setup token", http.StatusForbidden)
		return
	}

	if req.Username == "" || req.Password == "" {
		jsonError(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashed, err := config.HashPassword(req.Password)
	if err != nil {
		jsonError(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Create admin user and finalize config
	s.configMu.Lock()
	defer s.configMu.Unlock()

	s.Config.AdminUser = req.Username
	s.Config.AdminPassword = hashed
	s.Config.SetupComplete = true
	s.Config.Users[req.Username] = &config.User{
		Username: req.Username,
		Password: hashed,
		Role:     config.RoleSuperAdmin,
		Mounts:   make(map[string]string),
	}

	// Generate default source passwords
	defaultSourcePass := generateRandomString(12)
	liveMountPass := generateRandomString(12)
	hDefaultSource, _ := config.HashPassword(defaultSourcePass)
	hLiveMount, _ := config.HashPassword(liveMountPass)
	s.Config.DefaultSourcePassword = hDefaultSource
	s.Config.Mounts["/live"] = hLiveMount

	if err := s.Config.SaveConfig(); err != nil {
		jsonError(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	// Clear setup token
	s.setupToken = ""

	logger.L.Infow("Setup completed", "admin_user", req.Username, "time", time.Now().Format(time.RFC3339))

	// Create session for the new admin
	s.createSession(w, r, s.Config.Users[req.Username])

	jsonResponse(w, map[string]any{
		"success":             true,
		"default_source_pass": defaultSourcePass,
		"live_mount_pass":     liveMountPass,
	})
}

// generateRandomString generates a hex string of n random bytes.
// Duplicated from main.go since we need it in the server package.
func generateRandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "insecure_fallback"
	}
	return hex.EncodeToString(b)
}
```

Note: Add `"crypto/rand"` and `"encoding/hex"` to the imports.

- [ ] **Step 6: Verify it compiles**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: No errors.

- [ ] **Step 7: Commit**

```bash
git add main.go server/server.go server/handlers_setup.go server/auth.go
git commit -m "feat(setup): add first-run setup mode with token verification"
```

---

## Chunk 3: WebAuthn / Passkeys

### Task 5: WebAuthn Server-Side Handlers

**Files:**
- Create: `server/auth_passkey.go`
- Modify: `server/server.go` (routes + webAuthn init)

- [ ] **Step 1: Add webauthn instance to Server struct**

In `server/server.go`, add to imports:

```go
	"github.com/go-webauthn/webauthn/webauthn"
```

Add to the `Server` struct:

```go
	webAuthn         *webauthn.WebAuthn
	webauthnSessions map[string]*webauthn.SessionData // keyed by session ID or challenge
	webauthnMu       sync.Mutex
```

In `NewServer`, initialize webAuthn:

```go
	// Initialize WebAuthn
	var wa *webauthn.WebAuthn
	if cfg.SetupComplete || cfg.WebAuthn != nil {
		rpID := "localhost"
		rpName := "TinyIce"
		rpOrigins := []string{"http://localhost:8000"}
		if cfg.WebAuthn != nil {
			if cfg.WebAuthn.RPID != "" {
				rpID = cfg.WebAuthn.RPID
			}
			if cfg.WebAuthn.RPName != "" {
				rpName = cfg.WebAuthn.RPName
			}
			if len(cfg.WebAuthn.RPOrigins) > 0 {
				rpOrigins = cfg.WebAuthn.RPOrigins
			}
		} else if cfg.BaseURL != "" {
			// Derive from base_url
			if u, err := url.Parse(cfg.BaseURL); err == nil {
				rpID = u.Hostname()
				rpOrigins = []string{cfg.BaseURL}
			}
		}
		wa, _ = webauthn.New(&webauthn.Config{
			RPID:                  rpID,
			RPDisplayName:         rpName,
			RPOrigins:             rpOrigins,
			AttestationPreference: protocol.PreferNoAttestation,
		})
	}
```

Add to the returned struct:

```go
		webAuthn:         wa,
		webauthnSessions: make(map[string]*webauthn.SessionData),
```

Add `"net/url"` and `"github.com/go-webauthn/webauthn/protocol"` to imports.

- [ ] **Step 2: Create auth_passkey.go — WebAuthn user adapter**

Create `server/auth_passkey.go`:

```go
package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
	"github.com/go-webauthn/webauthn/webauthn"
)

// webAuthnUser adapts config.User to the webauthn.User interface.
type webAuthnUser struct {
	user *config.User
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return []byte(u.user.Username)
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.user.Username
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	return u.user.Username
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	var creds []webauthn.Credential
	for _, pk := range u.user.Passkeys {
		raw, err := base64.StdEncoding.DecodeString(pk.RawCredential)
		if err != nil {
			continue
		}
		var cred webauthn.Credential
		if err := json.Unmarshal(raw, &cred); err != nil {
			continue
		}
		creds = append(creds, cred)
	}
	return creds
}

// Note: WebAuthnIcon() was removed from the webauthn.User interface in go-webauthn v2.
// Do not implement it.
```

- [ ] **Step 3: Add registration handlers to auth_passkey.go**

Append to `server/auth_passkey.go`:

```go
func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if s.webAuthn == nil {
		jsonError(w, "WebAuthn not configured", http.StatusServiceUnavailable)
		return
	}

	wUser := &webAuthnUser{user: user}
	options, sessionData, err := s.webAuthn.BeginRegistration(wUser)
	if err != nil {
		jsonError(w, "Failed to begin registration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store session data keyed by user ID (one active registration per user)
	s.webauthnMu.Lock()
	s.webauthnSessions["reg:"+user.Username] = sessionData
	s.webauthnMu.Unlock()

	// Clean up after 60 seconds
	go func() {
		time.Sleep(60 * time.Second)
		s.webauthnMu.Lock()
		delete(s.webauthnSessions, "reg:"+user.Username)
		s.webauthnMu.Unlock()
	}()

	jsonResponse(w, options)
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Find session data for this user
	sessionKey := "reg:" + user.Username
	s.webauthnMu.Lock()
	sessionData, ok2 := s.webauthnSessions[sessionKey]
	if ok2 {
		delete(s.webauthnSessions, sessionKey)
	}
	s.webauthnMu.Unlock()

	if !ok2 || sessionData == nil {
		jsonError(w, "No active registration session", http.StatusBadRequest)
		return
	}

	wUser := &webAuthnUser{user: user}
	credential, err := s.webAuthn.FinishRegistration(wUser, *sessionData, r)
	if err != nil {
		jsonError(w, "Registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Serialize credential for storage
	credJSON, _ := json.Marshal(credential)
	credB64 := base64.StdEncoding.EncodeToString(credJSON)

	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Passkey"
	}

	pk := &config.PasskeyCredential{
		ID:            base64.RawURLEncoding.EncodeToString(credential.ID),
		RawCredential: credB64,
		Name:          name,
		CreatedAt:     time.Now().Format(time.RFC3339),
		LastUsed:      time.Now().Format(time.RFC3339),
	}

	s.configMu.Lock()
	user.Passkeys = append(user.Passkeys, pk)
	s.Config.SaveConfig()
	s.configMu.Unlock()

	logger.L.Infow("Passkey registered", "user", user.Username, "name", name)
	jsonResponse(w, map[string]any{"success": true, "name": name})
}
```

- [ ] **Step 4: Add login handlers to auth_passkey.go**

Append:

```go
func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.webAuthn == nil {
		jsonError(w, "WebAuthn not configured", http.StatusServiceUnavailable)
		return
	}

	// Discoverable credential login — no allowCredentials
	options, sessionData, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		jsonError(w, "Failed to begin login: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Key login sessions by challenge so concurrent logins don't collide
	challengeKey := "login:" + base64.RawURLEncoding.EncodeToString(sessionData.Challenge)
	s.webauthnMu.Lock()
	s.webauthnSessions[challengeKey] = sessionData
	s.webauthnMu.Unlock()

	go func() {
		time.Sleep(60 * time.Second)
		s.webauthnMu.Lock()
		delete(s.webauthnSessions, challengeKey)
		s.webauthnMu.Unlock()
	}()

	// Include the challenge key in the response so the client can send it back
	jsonResponse(w, map[string]any{
		"publicKey":    options.Response,
		"challengeKey": challengeKey,
	})
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request to extract challengeKey
	var loginReq struct {
		ChallengeKey string          `json:"challengeKey"`
		Response     json.RawMessage `json:"response"`
	}
	// The client sends challengeKey alongside the WebAuthn response
	// For simplicity, we use the challenge from the query param
	challengeKey := r.URL.Query().Get("challengeKey")

	// Find the user by credential ID (discoverable login callback)
	findUser := func(rawID, userHandle []byte) (webauthn.User, error) {
		username := string(userHandle)
		user, exists := s.Config.Users[username]
		if !exists {
			return nil, fmt.Errorf("user not found")
		}
		return &webAuthnUser{user: user}, nil
	}

	// Find matching session by challenge key
	s.webauthnMu.Lock()
	sessionData, ok := s.webauthnSessions[challengeKey]
	if ok {
		delete(s.webauthnSessions, challengeKey)
	}
	s.webauthnMu.Unlock()

	if !ok || sessionData == nil {
		jsonError(w, "No active login session", http.StatusBadRequest)
		return
	}

	_ = loginReq // suppress unused warning
	credential, err := s.webAuthn.FinishDiscoverableLogin(findUser, *sessionData, r)
	if err != nil {
		jsonError(w, "Login failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Find the user who owns this credential
	var loginUser *config.User
	for _, user := range s.Config.Users {
		for _, pk := range user.Passkeys {
			if pk.ID == base64.RawURLEncoding.EncodeToString(credential.ID) {
				loginUser = user
				// Update last used
				s.configMu.Lock()
				pk.LastUsed = time.Now().Format(time.RFC3339)
				s.Config.SaveConfig()
				s.configMu.Unlock()
				break
			}
		}
		if loginUser != nil {
			break
		}
	}

	if loginUser == nil {
		jsonError(w, "User not found for credential", http.StatusUnauthorized)
		return
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.recordAuthSuccess(host)
	s.createSession(w, r, loginUser)
	logger.L.Infow("Passkey login successful", "user", loginUser.Username, "ip", host)

	jsonResponse(w, map[string]any{"success": true, "redirect": "/admin"})
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	passkeyID := r.URL.Query().Get("id")
	if passkeyID == "" {
		jsonError(w, "Missing passkey ID", http.StatusBadRequest)
		return
	}

	s.configMu.Lock()
	defer s.configMu.Unlock()

	found := false
	for i, pk := range user.Passkeys {
		if pk.ID == passkeyID {
			user.Passkeys = append(user.Passkeys[:i], user.Passkeys[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		jsonError(w, "Passkey not found", http.StatusNotFound)
		return
	}

	s.Config.SaveConfig()
	logger.L.Infow("Passkey deleted", "user", user.Username, "passkey_id", passkeyID)
	jsonResponse(w, map[string]bool{"success": true})
}
```

Add `"fmt"` and `"net"` to the imports.

- [ ] **Step 5: Register passkey routes in setupRoutes**

In `server/server.go` `setupRoutes()`, add after the login/logout routes (after line 176):

```go
	// Passkey (WebAuthn) endpoints
	mux.HandleFunc("/api/passkey/register/begin", s.handlePasskeyRegisterBegin)
	mux.HandleFunc("/api/passkey/register/finish", s.handlePasskeyRegisterFinish)
	mux.HandleFunc("/api/passkey/login/begin", s.handlePasskeyLoginBegin)
	mux.HandleFunc("/api/passkey/login/finish", s.handlePasskeyLoginFinish)
	mux.HandleFunc("/api/passkey", s.handlePasskeyDelete)
```

- [ ] **Step 6: Verify it compiles**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: No errors.

- [ ] **Step 7: Commit**

```bash
git add server/auth_passkey.go server/server.go
git commit -m "feat(passkey): add WebAuthn registration and login handlers"
```

---

## Chunk 4: OIDC / OAuth2

### Task 6: OIDC Provider Auth Flow

**Files:**
- Create: `server/auth_oidc.go`
- Modify: `server/server.go` (routes)

- [ ] **Step 1: Create auth_oidc.go — provider management and auth flow**

Create `server/auth_oidc.go`:

```go
package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	githubOAuth "golang.org/x/oauth2/github"
)

// stateHMACKey is derived from the setup token or a random key.
var stateHMACKey []byte

func init() {
	stateHMACKey = make([]byte, 32)
	rand.Read(stateHMACKey)
}

func (s *Server) getOIDCProvider(id string) *config.OIDCProvider {
	for _, p := range s.Config.OIDCProviders {
		if p.ID == id && p.Enabled {
			return p
		}
	}
	return nil
}

func (s *Server) buildOAuth2Config(provider *config.OIDCProvider, r *http.Request) (*oauth2.Config, *oidc.Provider, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	redirectURL := fmt.Sprintf("%s://%s/auth/%s/callback", scheme, r.Host, provider.ID)

	if provider.ID == "github" {
		// GitHub uses OAuth2, not OIDC
		return &oauth2.Config{
			ClientID:     provider.ClientID,
			ClientSecret: provider.ClientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"user:email"},
			Endpoint:     githubOAuth.Endpoint,
		}, nil, nil
	}

	ctx := context.Background()
	oidcProvider, err := oidc.NewProvider(ctx, provider.DiscoveryURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to discover OIDC provider: %w", err)
	}

	return &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		Endpoint:     oidcProvider.Endpoint(),
	}, oidcProvider, nil
}

func generateState(providerID string) string {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	expiry := time.Now().Add(10 * time.Minute).Unix()
	payload := fmt.Sprintf("%s:%d:%s", providerID, expiry, base64.RawURLEncoding.EncodeToString(nonce))
	mac := hmac.New(sha256.New, stateHMACKey)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + ":" + sig
}

func verifyState(state string) (providerID string, ok bool) {
	parts := strings.SplitN(state, ":", 4)
	if len(parts) != 4 {
		return "", false
	}
	payload := parts[0] + ":" + parts[1] + ":" + parts[2]
	mac := hmac.New(sha256.New, stateHMACKey)
	mac.Write([]byte(payload))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[3]), []byte(expectedSig)) {
		return "", false
	}
	var expiry int64
	fmt.Sscanf(parts[1], "%d", &expiry)
	if time.Now().Unix() > expiry {
		return "", false
	}
	return parts[0], true
}

func (s *Server) handleOIDCRedirect(w http.ResponseWriter, r *http.Request) {
	// Extract provider ID from path: /auth/{provider}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/auth/"), "/")
	providerID := parts[0]

	provider := s.getOIDCProvider(providerID)
	if provider == nil {
		http.NotFound(w, r)
		return
	}

	oauthConfig, _, err := s.buildOAuth2Config(provider, r)
	if err != nil {
		jsonError(w, "Provider configuration error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	state := generateState(providerID)

	// Use PKCE
	verifier := oauth2.GenerateVerifier()
	http.SetCookie(w, &http.Cookie{
		Name:     "pkce_verifier",
		Value:    verifier,
		Path:     "/auth/" + providerID,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	url := oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	// Extract provider ID from path: /auth/{provider}/callback
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/auth/"), "/")
	if len(pathParts) < 2 {
		http.NotFound(w, r)
		return
	}
	providerID := pathParts[0]

	// Verify state
	state := r.URL.Query().Get("state")
	verifiedProvider, ok := verifyState(state)
	if !ok || verifiedProvider != providerID {
		http.Error(w, "Invalid state parameter", http.StatusForbidden)
		return
	}

	provider := s.getOIDCProvider(providerID)
	if provider == nil {
		http.NotFound(w, r)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Get PKCE verifier from cookie
	verifierCookie, err := r.Cookie("pkce_verifier")
	if err != nil {
		http.Error(w, "Missing PKCE verifier", http.StatusBadRequest)
		return
	}

	// Clear PKCE cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "pkce_verifier",
		Value:  "",
		Path:   "/auth/" + providerID,
		MaxAge: -1,
	})

	oauthConfig, oidcProvider, err := s.buildOAuth2Config(provider, r)
	if err != nil {
		http.Error(w, "Provider configuration error", http.StatusInternalServerError)
		return
	}

	ctx := context.Background()
	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(verifierCookie.Value))
	if err != nil {
		logger.L.Warnw("OIDC token exchange failed", "provider", providerID, "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	var email, name string

	if providerID == "github" {
		// GitHub: fetch user info from API
		email, name, err = s.fetchGitHubUserInfo(ctx, token)
		if err != nil {
			http.Error(w, "Failed to get user info from GitHub", http.StatusInternalServerError)
			return
		}
	} else {
		// Standard OIDC: verify ID token
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "Missing ID token", http.StatusInternalServerError)
			return
		}
		verifier := oidcProvider.Verifier(&oidc.Config{ClientID: provider.ClientID})
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Invalid ID token", http.StatusUnauthorized)
			return
		}
		var claims struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		idToken.Claims(&claims)
		email = claims.Email
		name = claims.Name
	}

	if email == "" {
		http.Error(w, "No email returned by provider", http.StatusBadRequest)
		return
	}

	// Check if email matches an existing user's linked_emails
	for _, user := range s.Config.Users {
		for _, linkedEmail := range user.LinkedEmails {
			if strings.EqualFold(linkedEmail, email) {
				// Login success
				host, _, _ := net.SplitHostPort(r.RemoteAddr)
				s.recordAuthSuccess(host)
				s.createSession(w, r, user)
				logger.L.Infow("OIDC login successful", "user", user.Username, "provider", providerID, "email", email)
				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}
		}
	}

	// Email not linked — create pending user request
	s.configMu.Lock()

	// Deduplicate: check if pending request already exists for this email
	for _, pu := range s.Config.PendingUsers {
		if strings.EqualFold(pu.Email, email) {
			if pu.DeniedAt != "" {
				// Previously denied — check 24h cooldown
				deniedTime, _ := time.Parse(time.RFC3339, pu.DeniedAt)
				if time.Since(deniedTime) < 24*time.Hour {
					s.configMu.Unlock()
					s.renderAccessDenied(w, r, "Your access request was denied. You can try again later.")
					return
				}
				// Cooldown passed — allow new request, remove old denied entry
				pu.DeniedAt = ""
				pu.RequestedAt = time.Now().Format(time.RFC3339)
				s.Config.SaveConfig()
				s.configMu.Unlock()
				s.renderAccessPending(w, r)
				return
			}
			// Already pending — just update timestamp
			pu.RequestedAt = time.Now().Format(time.RFC3339)
			s.Config.SaveConfig()
			s.configMu.Unlock()
			s.renderAccessPending(w, r)
			return
		}
	}

	// Create new pending request
	pending := &config.PendingUser{
		ID:          uuid.New().String(),
		Email:       email,
		Name:        name,
		Provider:    providerID,
		RequestedAt: time.Now().Format(time.RFC3339),
	}
	s.Config.PendingUsers = append(s.Config.PendingUsers, pending)
	s.Config.SaveConfig()
	s.configMu.Unlock()

	logger.L.Infow("New pending user request", "email", email, "provider", providerID)

	// Send email notification to admins (non-blocking)
	go s.notifyAdminsNewPendingUser(pending)

	s.renderAccessPending(w, r)
}

func (s *Server) fetchGitHubUserInfo(ctx context.Context, token *oauth2.Token) (email, name string, err error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	// Fetch user profile
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var profile struct {
		Name  string `json:"name"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	json.NewDecoder(resp.Body).Decode(&profile)
	name = profile.Name
	if name == "" {
		name = profile.Login
	}
	email = profile.Email

	// If no public email, fetch from emails API
	if email == "" {
		resp2, err := client.Get("https://api.github.com/user/emails")
		if err == nil {
			defer resp2.Body.Close()
			var emails []struct {
				Email   string `json:"email"`
				Primary bool   `json:"primary"`
			}
			json.NewDecoder(resp2.Body).Decode(&emails)
			for _, e := range emails {
				if e.Primary {
					email = e.Email
					break
				}
			}
		}
	}

	return email, name, nil
}

func (s *Server) renderAccessPending(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html>
<html><head><title>Access Requested</title></head>
<body style="background:#111;color:#eee;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center;max-width:400px">
<h2>Access Requested</h2>
<p>Your request has been submitted to the station administrator. You'll be able to log in once approved.</p>
<a href="/login" style="color:#ff6600">Back to Login</a>
</div></body></html>`))
}

func (s *Server) renderAccessDenied(w http.ResponseWriter, r *http.Request, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Access Denied</title></head>
<body style="background:#111;color:#eee;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center;max-width:400px">
<h2>Access Denied</h2>
<p>%s</p>
<a href="/login" style="color:#ff6600">Back to Login</a>
</div></body></html>`, msg)))
}

// handleOIDCProvidersList returns the list of enabled providers (public, for login page)
func (s *Server) handleOIDCProvidersList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type publicProvider struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Icon string `json:"icon"`
	}
	var providers []publicProvider
	for _, p := range s.Config.OIDCProviders {
		if p.Enabled {
			providers = append(providers, publicProvider{ID: p.ID, Name: p.Name, Icon: p.Icon})
		}
	}
	if providers == nil {
		providers = []publicProvider{}
	}
	jsonResponse(w, providers)
}
```

Add `"crypto/rand"` and `"net"` to the imports.

- [ ] **Step 2: Register OIDC routes in setupRoutes**

In `server/server.go` `setupRoutes()`, add after the passkey routes:

```go
	// OIDC / OAuth2 endpoints
	mux.HandleFunc("/auth/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/auth/")
		if strings.HasSuffix(path, "/callback") {
			s.handleOIDCCallback(w, r)
		} else {
			s.handleOIDCRedirect(w, r)
		}
	})
	mux.HandleFunc("/api/oidc/providers", s.handleOIDCProvidersList)
```

Add `"strings"` to imports if not already there.

- [ ] **Step 3: Verify it compiles**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: No errors.

- [ ] **Step 4: Commit**

```bash
git add server/auth_oidc.go server/server.go
git commit -m "feat(oidc): add multi-provider OIDC/OAuth2 login with PKCE"
```

---

### Task 7: Pending User Approval & Email Notifications

**Files:**
- Create: `server/handlers_pending_users.go`
- Create: `server/email.go`
- Modify: `server/server.go` (routes)

- [ ] **Step 1: Create handlers_pending_users.go**

```go
package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
)

func (s *Server) handleGetPendingUsers(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	pending := s.Config.PendingUsers
	if pending == nil {
		pending = []*config.PendingUser{}
	}

	// Filter out denied users
	var active []*config.PendingUser
	for _, p := range pending {
		if p.DeniedAt == "" {
			active = append(active, p)
		}
	}
	if active == nil {
		active = []*config.PendingUser{}
	}
	jsonResponse(w, active)
}

func (s *Server) handleApprovePendingUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		jsonError(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Default role to DJ
	role := req.Role
	if role == "" {
		role = config.RoleDJ
	}
	if role != config.RoleSuperAdmin && role != config.RoleAdmin && role != config.RoleDJ {
		jsonError(w, "Invalid role", http.StatusBadRequest)
		return
	}

	s.configMu.Lock()
	defer s.configMu.Unlock()

	// Find pending user
	var pending *config.PendingUser
	var pendingIdx int
	for i, p := range s.Config.PendingUsers {
		if p.ID == req.ID {
			pending = p
			pendingIdx = i
			break
		}
	}

	if pending == nil {
		jsonError(w, "Pending user not found", http.StatusNotFound)
		return
	}

	// Check username not taken
	if _, exists := s.Config.Users[req.Username]; exists {
		jsonError(w, "Username already taken", http.StatusConflict)
		return
	}

	// Create user
	newUser := &config.User{
		Username:     req.Username,
		Password:     "", // No password — they log in via OIDC
		Role:         role,
		Mounts:       make(map[string]string),
		LinkedEmails: []string{pending.Email},
	}
	s.Config.Users[req.Username] = newUser

	// Remove from pending
	s.Config.PendingUsers = append(s.Config.PendingUsers[:pendingIdx], s.Config.PendingUsers[pendingIdx+1:]...)
	s.Config.SaveConfig()

	logger.L.Infow("Pending user approved", "email", pending.Email, "username", req.Username, "role", role, "approved_by", user.Username)
	jsonResponse(w, map[string]any{"success": true, "username": req.Username})
}

func (s *Server) handleDenyPendingUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	s.configMu.Lock()
	defer s.configMu.Unlock()

	for _, p := range s.Config.PendingUsers {
		if p.ID == req.ID {
			p.DeniedAt = time.Now().Format(time.RFC3339)
			s.Config.SaveConfig()
			logger.L.Infow("Pending user denied", "email", p.Email, "denied_by", user.Username)
			jsonResponse(w, map[string]bool{"success": true})
			return
		}
	}

	jsonError(w, "Pending user not found", http.StatusNotFound)
}
```

Add `"time"` to imports.

- [ ] **Step 2: Create email.go**

```go
package server

import (
	"fmt"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
	mail "github.com/wneessen/go-mail"
)

func (s *Server) notifyAdminsNewPendingUser(pending *config.PendingUser) {
	if s.Config.SMTP == nil || !s.Config.SMTP.Enabled {
		return
	}

	// Find admin emails
	var adminEmails []string
	for _, user := range s.Config.Users {
		if user.Role == config.RoleSuperAdmin && len(user.LinkedEmails) > 0 {
			adminEmails = append(adminEmails, user.LinkedEmails[0])
		}
	}

	if len(adminEmails) == 0 {
		return
	}

	subject := fmt.Sprintf("[TinyIce] New access request from %s", pending.Email)
	body := fmt.Sprintf("A new user has requested access to your TinyIce server.\n\n"+
		"Name: %s\n"+
		"Email: %s\n"+
		"Provider: %s\n"+
		"Requested: %s\n\n"+
		"Log in to your admin panel to approve or deny this request.",
		pending.Name, pending.Email, pending.Provider, pending.RequestedAt)

	for _, to := range adminEmails {
		if err := s.sendEmail(to, subject, body); err != nil {
			logger.L.Warnw("Failed to send notification email", "to", to, "error", err)
		}
	}
}

func (s *Server) sendEmail(to, subject, body string) error {
	smtp := s.Config.SMTP
	if smtp == nil || !smtp.Enabled {
		return fmt.Errorf("SMTP not configured")
	}

	m := mail.NewMsg()
	if err := m.From(smtp.From); err != nil {
		return err
	}
	if err := m.To(to); err != nil {
		return err
	}
	m.Subject(subject)
	m.SetBodyString(mail.TypeTextPlain, body)

	port := smtp.Port
	if port == 0 {
		port = 587
	}

	c, err := mail.NewClient(smtp.Host,
		mail.WithPort(port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(smtp.Username),
		mail.WithPassword(smtp.Password),
		mail.WithTLSPortPolicy(mail.TLSMandatory),
	)
	if err != nil {
		return err
	}

	return c.DialAndSend(m)
}
```

- [ ] **Step 3: Register pending user routes**

In `server/server.go` `setupRoutes()`, add after the OIDC routes:

```go
	// Pending user management
	mux.HandleFunc("/api/pending-users", s.handleGetPendingUsers)
	mux.HandleFunc("/api/pending-users/approve", s.handleApprovePendingUser)
	mux.HandleFunc("/api/pending-users/deny", s.handleDenyPendingUser)
```

- [ ] **Step 4: Verify it compiles**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add server/handlers_pending_users.go server/email.go server/server.go
git commit -m "feat(pending-users): add approval workflow and email notifications"
```

---

## Chunk 5: Frontend — Login Page Enhancement

### Task 8: Inject Auth Methods Into Page Data

**Files:**
- Modify: `server/shell.go:108-116`
- Modify: `server/auth.go` (handleLogin)

- [ ] **Step 1: Update BasePageData to include auth methods**

In `server/shell.go`, update `BasePageData`:

```go
func (s *Server) BasePageData(csrfToken string) map[string]any {
	// Build public OIDC provider list
	var oidcProviders []map[string]string
	for _, p := range s.Config.OIDCProviders {
		if p.Enabled {
			oidcProviders = append(oidcProviders, map[string]string{
				"id": p.ID, "name": p.Name, "icon": p.Icon,
			})
		}
	}

	// Check if any user has passkeys registered
	passkeysEnabled := s.webAuthn != nil

	return map[string]any{
		"csrfToken":       csrfToken,
		"version":         s.Version,
		"pageTitle":       s.Config.PageTitle,
		"pageSubtitle":    s.Config.PageSubtitle,
		"branding":        s.BrandingData(),
		"passkeysEnabled": passkeysEnabled,
		"oidcProviders":   oidcProviders,
	}
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /Users/dev/dev/tinyice && go build ./...`

- [ ] **Step 3: Commit**

```bash
git add server/shell.go
git commit -m "feat(shell): inject passkeys_enabled and oidc_providers into page data"
```

---

### Task 9: Add PasskeyButton Component

**Files:**
- Create: `server/frontend/src/components/PasskeyButton.tsx`

- [ ] **Step 1: Install simplewebauthn browser package (if not done in Task 1)**

Verify: `ls server/frontend/node_modules/@simplewebauthn/browser`

- [ ] **Step 2: Create PasskeyButton.tsx**

```tsx
import { signal } from '@preact/signals'
import { startAuthentication } from '@simplewebauthn/browser'

const loading = signal(false)
const error = signal('')

export function PasskeyButton() {
  async function handleLogin() {
    loading.value = true
    error.value = ''

    try {
      // Get options from server
      const beginRes = await fetch('/api/passkey/login/begin', { method: 'POST' })
      if (!beginRes.ok) {
        throw new Error('Failed to start passkey login')
      }
      const options = await beginRes.json()

      // Trigger browser WebAuthn ceremony
      const credential = await startAuthentication(options)

      // Send to server
      const finishRes = await fetch('/api/passkey/login/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credential),
      })

      if (!finishRes.ok) {
        const err = await finishRes.json()
        throw new Error(err.error || 'Passkey login failed')
      }

      const result = await finishRes.json()
      window.location.href = result.redirect || '/admin'
    } catch (e: any) {
      if (e.name === 'NotAllowedError') {
        error.value = 'Passkey authentication was cancelled'
      } else {
        error.value = e.message || 'Passkey login failed'
      }
    } finally {
      loading.value = false
    }
  }

  return (
    <div>
      <button
        type="button"
        onClick={handleLogin}
        disabled={loading.value}
        class="w-full flex items-center justify-center gap-2 bg-[rgba(255,255,255,0.05)] border border-border rounded-lg py-3 px-4 text-text-primary font-mono text-sm hover:bg-[rgba(255,255,255,0.08)] transition-colors disabled:opacity-50"
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z" />
          <circle cx="16.5" cy="7.5" r=".5" fill="currentColor" />
        </svg>
        {loading.value ? 'Authenticating...' : 'Sign in with Passkey'}
      </button>
      {error.value && <p class="text-danger text-xs mt-2 text-center">{error.value}</p>}
    </div>
  )
}
```

- [ ] **Step 3: Commit**

```bash
git add server/frontend/src/components/PasskeyButton.tsx
git commit -m "feat(frontend): add PasskeyButton component for WebAuthn login"
```

---

### Task 10: Add OIDCButtons Component

**Files:**
- Create: `server/frontend/src/components/OIDCButtons.tsx`

- [ ] **Step 1: Create OIDCButtons.tsx**

```tsx
interface OIDCProvider {
  id: string
  name: string
  icon: string
}

const iconPaths: Record<string, string> = {
  google: 'M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18A10.96 10.96 0 0 0 1 12c0 1.77.43 3.45 1.18 4.93l3.66-2.84z M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z',
  github: 'M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0 0 22 12.017C22 6.484 17.522 2 12 2z',
  key: 'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
}

export function OIDCButtons({ providers }: { providers: OIDCProvider[] }) {
  if (!providers || providers.length === 0) return null

  return (
    <div class="flex flex-col gap-2">
      {providers.map((p) => (
        <a
          key={p.id}
          href={`/auth/${p.id}`}
          class="w-full flex items-center justify-center gap-2 bg-[rgba(255,255,255,0.05)] border border-border rounded-lg py-3 px-4 text-text-primary font-mono text-sm hover:bg-[rgba(255,255,255,0.08)] transition-colors no-underline"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d={iconPaths[p.icon] || iconPaths.key} />
          </svg>
          Continue with {p.name}
        </a>
      ))}
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add server/frontend/src/components/OIDCButtons.tsx
git commit -m "feat(frontend): add OIDCButtons component for social login"
```

---

### Task 11: Update Login Page

**Files:**
- Modify: `server/frontend/src/pages/Login.tsx`

- [ ] **Step 1: Rewrite Login.tsx with unified layout**

```tsx
import { signal } from '@preact/signals'
import { PasskeyButton } from '@/components/PasskeyButton'
import { OIDCButtons } from '@/components/OIDCButtons'

const error = signal('')
const loading = signal(false)

declare global {
  interface Window {
    __TINYICE__: {
      passkeysEnabled?: boolean
      oidcProviders?: Array<{ id: string; name: string; icon: string }>
      [key: string]: any
    }
  }
}

const pageData = window.__TINYICE__ || {}

export function Login() {
  const hasPasskeys = pageData.passkeysEnabled && typeof PublicKeyCredential !== 'undefined'
  const hasOIDC = pageData.oidcProviders && pageData.oidcProviders.length > 0
  const hasAlternateAuth = hasPasskeys || hasOIDC

  async function handleSubmit(e: Event) {
    e.preventDefault()
    error.value = ''
    loading.value = true

    const form = e.target as HTMLFormElement
    const formData = new FormData(form)

    try {
      const res = await fetch('/login', {
        method: 'POST',
        body: formData,
      })

      if (res.ok || res.redirected) {
        window.location.href = '/admin'
      } else {
        const text = await res.text()
        error.value = text || 'Invalid credentials'
      }
    } catch {
      error.value = 'Network error. Please try again.'
    } finally {
      loading.value = false
    }
  }

  return (
    <div class="min-h-screen bg-surface-base flex items-center justify-center px-4">
      <div class="w-full max-w-sm">
        {/* Logo */}
        <div class="flex items-center justify-center gap-3 mb-8">
          <div class="h-8 w-8 rounded bg-accent flex items-center justify-center">
            <span class="font-mono text-xs font-bold text-surface-base leading-none">Ti</span>
          </div>
          <span class="font-mono text-sm font-bold tracking-widest text-text-primary">TINYICE</span>
        </div>

        {/* Card */}
        <div class="bg-surface-raised border border-border rounded-xl p-8 w-full max-w-sm">
          <div class="flex flex-col gap-4">
            {/* Passkey button */}
            {hasPasskeys && <PasskeyButton />}

            {/* OIDC provider buttons */}
            {hasOIDC && <OIDCButtons providers={pageData.oidcProviders!} />}

            {/* Divider (only if there are alternate auth methods) */}
            {hasAlternateAuth && (
              <div class="flex items-center gap-3 my-1">
                <div class="flex-1 h-px bg-border" />
                <span class="text-text-tertiary text-xs font-mono">or</span>
                <div class="flex-1 h-px bg-border" />
              </div>
            )}

            {/* Username/Password form */}
            <form onSubmit={handleSubmit} class="flex flex-col gap-4">
              <input
                type="text"
                name="username"
                placeholder="Username"
                required
                autocomplete="username"
                class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-3 text-text-primary font-mono text-sm placeholder:text-text-tertiary focus:outline-none focus:border-accent/40 transition-colors"
              />
              <input
                type="password"
                name="password"
                placeholder="Password"
                required
                autocomplete="current-password"
                class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-3 text-text-primary font-mono text-sm placeholder:text-text-tertiary focus:outline-none focus:border-accent/40 transition-colors"
              />
              <button
                type="submit"
                disabled={loading.value}
                class="bg-accent text-surface-base font-mono font-bold tracking-[1px] rounded-lg py-3 w-full text-sm hover:bg-accent/90 transition-colors disabled:opacity-50"
              >
                {loading.value ? 'SIGNING IN...' : 'SIGN IN'}
              </button>
            </form>

            {error.value && (
              <p class="text-danger text-sm text-center">{error.value}</p>
            )}

            {/* Request Access hint */}
            {hasOIDC && (
              <p class="text-text-tertiary text-xs text-center mt-2">
                Don't have an account? Sign in with a provider above to request access.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add server/frontend/src/pages/Login.tsx
git commit -m "feat(login): unified login page with passkey, OIDC, and password"
```

---

## Chunk 6: Frontend — Setup Wizard & Admin Pending Users

### Task 12: Create Setup Wizard Page

**Files:**
- Create: `server/frontend/src/pages/Setup.tsx`
- Create: `server/frontend/src/entries/setup.tsx`
- Create: `server/frontend/src/entries/setup.html`
- Modify: `server/frontend/vite.config.ts`

- [ ] **Step 1: Create setup.html**

```html
<!DOCTYPE html>
<html lang="en" style="color-scheme:dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>TinyIce</title>
</head>
<body>
  <div id="app"></div>
  <script type="module" src="./setup.tsx"></script>
</body>
</html>
```

- [ ] **Step 2: Create setup.tsx entry**

```tsx
import '../globals.css'
import { render } from 'preact'
import { Setup } from '@/pages/Setup'

render(<Setup />, document.getElementById('app')!)
```

- [ ] **Step 3: Create Setup.tsx page**

```tsx
import { signal, computed } from '@preact/signals'
import { startRegistration } from '@simplewebauthn/browser'

const step = signal(0)
const token = signal('')
const username = signal('admin')
const password = signal('')
const confirmPassword = signal('')
const error = signal('')
const loading = signal(false)
const tokenVerified = signal(false)
const setupResult = signal<any>(null)
const passkeyRegistered = signal(false)

const passwordsMatch = computed(() => password.value === confirmPassword.value)

export function Setup() {
  async function verifyToken() {
    loading.value = true
    error.value = ''
    try {
      const res = await fetch('/setup/verify-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token.value }),
      })
      const data = await res.json()
      if (data.valid) {
        tokenVerified.value = true
        step.value = 1
      } else {
        error.value = data.error || 'Invalid token'
      }
    } catch {
      error.value = 'Network error'
    } finally {
      loading.value = false
    }
  }

  async function completeSetup() {
    if (!passwordsMatch.value) {
      error.value = 'Passwords do not match'
      return
    }
    if (password.value.length < 8) {
      error.value = 'Password must be at least 8 characters'
      return
    }

    loading.value = true
    error.value = ''
    try {
      const res = await fetch('/setup/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: token.value,
          username: username.value,
          password: password.value,
        }),
      })
      const data = await res.json()
      if (data.success) {
        setupResult.value = data
        step.value = 2
      } else {
        error.value = data.error || 'Setup failed'
      }
    } catch {
      error.value = 'Network error'
    } finally {
      loading.value = false
    }
  }

  async function registerPasskey() {
    loading.value = true
    error.value = ''
    try {
      const beginRes = await fetch('/api/passkey/register/begin', { method: 'POST' })
      if (!beginRes.ok) throw new Error('Failed to start registration')
      const options = await beginRes.json()

      const credential = await startRegistration(options)

      const finishRes = await fetch('/api/passkey/register/finish?name=Setup+Passkey', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credential),
      })

      if (finishRes.ok) {
        passkeyRegistered.value = true
      } else {
        const err = await finishRes.json()
        throw new Error(err.error || 'Registration failed')
      }
    } catch (e: any) {
      if (e.name !== 'NotAllowedError') {
        error.value = e.message
      }
    } finally {
      loading.value = false
    }
  }

  const inputClass = "bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-3 text-text-primary font-mono text-sm placeholder:text-text-tertiary focus:outline-none focus:border-accent/40 transition-colors w-full"
  const btnClass = "bg-accent text-surface-base font-mono font-bold tracking-[1px] rounded-lg py-3 w-full text-sm hover:bg-accent/90 transition-colors disabled:opacity-50"
  const btnSecondary = "bg-[rgba(255,255,255,0.05)] border border-border text-text-primary font-mono text-sm rounded-lg py-3 w-full hover:bg-[rgba(255,255,255,0.08)] transition-colors"

  return (
    <div class="min-h-screen bg-surface-base flex items-center justify-center px-4">
      <div class="w-full max-w-md">
        {/* Logo */}
        <div class="flex items-center justify-center gap-3 mb-8">
          <div class="h-8 w-8 rounded bg-accent flex items-center justify-center">
            <span class="font-mono text-xs font-bold text-surface-base leading-none">Ti</span>
          </div>
          <span class="font-mono text-sm font-bold tracking-widest text-text-primary">TINYICE SETUP</span>
        </div>

        <div class="bg-surface-raised border border-border rounded-xl p-8">
          {/* Step 0: Token */}
          {step.value === 0 && (
            <div class="flex flex-col gap-4">
              <h2 class="text-text-primary font-mono text-lg font-bold">Welcome to TinyIce</h2>
              <p class="text-text-secondary text-sm">Enter the setup token from your terminal to begin.</p>
              <input
                type="text"
                value={token.value}
                onInput={(e) => token.value = (e.target as HTMLInputElement).value}
                placeholder="Setup Token"
                class={inputClass}
                autoFocus
              />
              <button onClick={verifyToken} disabled={loading.value || !token.value} class={btnClass}>
                {loading.value ? 'Verifying...' : 'Continue'}
              </button>
            </div>
          )}

          {/* Step 1: Credentials */}
          {step.value === 1 && (
            <div class="flex flex-col gap-4">
              <h2 class="text-text-primary font-mono text-lg font-bold">Set Admin Credentials</h2>
              <p class="text-text-secondary text-sm">Choose your admin username and password.</p>
              <input
                type="text"
                value={username.value}
                onInput={(e) => username.value = (e.target as HTMLInputElement).value}
                placeholder="Username"
                autocomplete="username"
                class={inputClass}
              />
              <input
                type="password"
                value={password.value}
                onInput={(e) => password.value = (e.target as HTMLInputElement).value}
                placeholder="Password (min 8 characters)"
                autocomplete="new-password"
                class={inputClass}
              />
              <input
                type="password"
                value={confirmPassword.value}
                onInput={(e) => confirmPassword.value = (e.target as HTMLInputElement).value}
                placeholder="Confirm Password"
                autocomplete="new-password"
                class={`${inputClass} ${confirmPassword.value && !passwordsMatch.value ? 'border-danger' : ''}`}
              />
              <button onClick={completeSetup} disabled={loading.value || !username.value || !password.value || !passwordsMatch.value} class={btnClass}>
                {loading.value ? 'Creating...' : 'Create Admin Account'}
              </button>
            </div>
          )}

          {/* Step 2: Passkey (optional) */}
          {step.value === 2 && (
            <div class="flex flex-col gap-4">
              <h2 class="text-text-primary font-mono text-lg font-bold">
                {passkeyRegistered.value ? 'Passkey Registered!' : 'Register a Passkey'}
              </h2>

              {setupResult.value && (
                <div class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg p-4 text-sm font-mono">
                  <p class="text-text-secondary mb-2">Source passwords (save these):</p>
                  <p class="text-text-primary">Default: <span class="text-accent">{setupResult.value.default_source_pass}</span></p>
                  <p class="text-text-primary">Mount /live: <span class="text-accent">{setupResult.value.live_mount_pass}</span></p>
                </div>
              )}

              {!passkeyRegistered.value && typeof PublicKeyCredential !== 'undefined' && (
                <>
                  <p class="text-text-secondary text-sm">Add a passkey for quick, passwordless login. You can skip this and add one later.</p>
                  <button onClick={registerPasskey} disabled={loading.value} class={btnSecondary}>
                    {loading.value ? 'Registering...' : 'Register Passkey'}
                  </button>
                </>
              )}

              {passkeyRegistered.value && (
                <p class="text-green-400 text-sm">Your passkey has been registered successfully.</p>
              )}

              <a href="/admin" class={btnClass + ' text-center no-underline block'}>
                {passkeyRegistered.value ? 'Go to Dashboard' : 'Skip & Go to Dashboard'}
              </a>
            </div>
          )}

          {error.value && (
            <p class="text-danger text-sm mt-3 text-center">{error.value}</p>
          )}

          {/* Progress dots */}
          <div class="flex justify-center gap-2 mt-6">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                class={`w-2 h-2 rounded-full ${step.value >= i ? 'bg-accent' : 'bg-border'}`}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
```

- [ ] **Step 4: Add setup entry to vite.config.ts**

Add `setup` to the rollupOptions input:

```ts
setup: resolve(__dirname, 'src/entries/setup.html'),
```

- [ ] **Step 5: Build frontend**

Run:
```bash
cd /Users/dev/dev/tinyice/server/frontend
npm run build
```

Expected: Build succeeds with no errors.

- [ ] **Step 6: Commit**

```bash
git add server/frontend/src/pages/Setup.tsx server/frontend/src/entries/setup.tsx server/frontend/src/entries/setup.html server/frontend/vite.config.ts
git commit -m "feat(setup): add onboarding wizard frontend with passkey registration"
```

---

### Task 13: Admin Pending Users Page

**Files:**
- Create: `server/frontend/src/pages/admin/PendingUsers.tsx`
- Modify: `server/frontend/src/pages/admin/AdminLayout.tsx`

- [ ] **Step 1: Create PendingUsers.tsx**

```tsx
import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'

declare global {
  interface Window {
    __TINYICE__: { csrfToken: string; [key: string]: any }
  }
}

interface PendingUserData {
  id: string
  email: string
  name: string
  provider: string
  requested_at: string
}

const pendingUsers = signal<PendingUserData[]>([])
const loading = signal(true)
const approveModal = signal<PendingUserData | null>(null)
const approveUsername = signal('')
const approveRole = signal('dj')

async function fetchPending() {
  try {
    const res = await fetch('/api/pending-users')
    if (res.ok) {
      pendingUsers.value = await res.json()
    }
  } finally {
    loading.value = false
  }
}

async function approve(user: PendingUserData) {
  const csrf = window.__TINYICE__?.csrfToken
  const res = await fetch('/api/pending-users/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: JSON.stringify({ id: user.id, username: approveUsername.value, role: approveRole.value }),
  })
  if (res.ok) {
    approveModal.value = null
    approveUsername.value = ''
    fetchPending()
  }
}

async function deny(id: string) {
  const csrf = window.__TINYICE__?.csrfToken
  await fetch('/api/pending-users/deny', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: JSON.stringify({ id }),
  })
  fetchPending()
}

export function PendingUsers() {
  useEffect(() => { fetchPending() }, [])

  return (
    <div class="p-6 max-w-4xl">
      <h1 class="text-text-primary font-mono text-xl font-bold mb-6">Pending Access Requests</h1>

      {loading.value && <p class="text-text-secondary">Loading...</p>}

      {!loading.value && pendingUsers.value.length === 0 && (
        <p class="text-text-tertiary">No pending requests.</p>
      )}

      {pendingUsers.value.length > 0 && (
        <div class="flex flex-col gap-3">
          {pendingUsers.value.map((user) => (
            <div key={user.id} class="bg-surface-raised border border-border rounded-lg p-4 flex items-center justify-between">
              <div>
                <p class="text-text-primary font-mono text-sm font-bold">{user.name || user.email}</p>
                <p class="text-text-secondary text-xs">{user.email} via {user.provider}</p>
                <p class="text-text-tertiary text-xs">{new Date(user.requested_at).toLocaleString()}</p>
              </div>
              <div class="flex gap-2">
                <button
                  onClick={() => { approveModal.value = user; approveUsername.value = user.email.split('@')[0] }}
                  class="bg-green-600 text-white font-mono text-xs px-3 py-1.5 rounded hover:bg-green-500 transition-colors"
                >
                  Approve
                </button>
                <button
                  onClick={() => deny(user.id)}
                  class="bg-red-600 text-white font-mono text-xs px-3 py-1.5 rounded hover:bg-red-500 transition-colors"
                >
                  Deny
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Approve Modal */}
      {approveModal.value && (
        <div class="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div class="bg-surface-raised border border-border rounded-xl p-6 w-full max-w-sm">
            <h2 class="text-text-primary font-mono text-lg font-bold mb-4">Approve User</h2>
            <p class="text-text-secondary text-sm mb-4">Approving {approveModal.value.email}</p>
            <div class="flex flex-col gap-3">
              <input
                type="text"
                value={approveUsername.value}
                onInput={(e) => approveUsername.value = (e.target as HTMLInputElement).value}
                placeholder="Username"
                class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2 text-text-primary font-mono text-sm"
              />
              <select
                value={approveRole.value}
                onChange={(e) => approveRole.value = (e.target as HTMLSelectElement).value}
                class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2 text-text-primary font-mono text-sm"
              >
                <option value="dj">DJ (stream only)</option>
                <option value="admin">Admin</option>
                <option value="superadmin">Super Admin</option>
              </select>
              <div class="flex gap-2 mt-2">
                <button
                  onClick={() => approve(approveModal.value!)}
                  class="flex-1 bg-green-600 text-white font-mono text-sm py-2 rounded hover:bg-green-500"
                >
                  Approve
                </button>
                <button
                  onClick={() => approveModal.value = null}
                  class="flex-1 bg-[rgba(255,255,255,0.05)] text-text-primary font-mono text-sm py-2 rounded hover:bg-[rgba(255,255,255,0.08)]"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 2: Add PendingUsers route to AdminLayout.tsx**

Add import:
```tsx
import { PendingUsers } from './PendingUsers'
```

Add route (after the Settings route):
```tsx
<Route path="/admin/pending" component={PendingUsers} />
```

- [ ] **Step 3: Add nav item to Sidebar**

Read the Sidebar component, then add a "Pending" nav item with a badge showing the count. The exact implementation depends on the existing Sidebar structure — add it after the Users nav item.

- [ ] **Step 4: Build frontend**

Run:
```bash
cd /Users/dev/dev/tinyice/server/frontend
npm run build
```

- [ ] **Step 5: Commit**

```bash
git add server/frontend/src/pages/admin/PendingUsers.tsx server/frontend/src/pages/admin/AdminLayout.tsx server/frontend/src/components/Sidebar.tsx
git commit -m "feat(admin): add pending users management page with approve/deny"
```

---

## Chunk 7: Build, Integration & Verification

### Task 14: Full Build and Smoke Test

**Files:**
- All modified files

- [ ] **Step 1: Build frontend**

```bash
cd /Users/dev/dev/tinyice/server/frontend
npm run build
```

Expected: No errors.

- [ ] **Step 2: Build Go binary**

```bash
cd /Users/dev/dev/tinyice
go build -o tinyice .
```

Expected: No errors.

- [ ] **Step 3: Test setup mode**

```bash
# Remove any existing config to trigger setup mode
mv tinyice.json tinyice.json.bak 2>/dev/null || true
./tinyice &
# Verify output shows setup token and setup URL
# Visit http://localhost:8000/setup in browser
# Kill the server
kill %1
mv tinyice.json.bak tinyice.json 2>/dev/null || true
```

Expected: Server starts in setup mode, shows setup token, all routes redirect to `/setup`.

- [ ] **Step 4: Test normal mode with existing config**

```bash
./tinyice &
# Verify login page loads with passkey and OIDC sections (hidden if not configured)
# Verify admin panel loads
kill %1
```

- [ ] **Step 5: Commit dist files**

```bash
git add server/frontend/dist/
git commit -m "build: rebuild frontend dist with auth overhaul"
```

- [ ] **Step 6: Final integration commit**

```bash
git add -A
git commit -m "feat: complete auth overhaul — passkeys, OIDC, onboarding, pending users"
```

---

## Deferred Features (Not in This Plan)

The following spec features are intentionally deferred to a follow-up plan to keep this implementation focused:

1. **Account linking endpoints** (`POST /api/account/link/{provider}`, `DELETE /api/account/link/{email}`) — Users can link OIDC emails to existing accounts. Admin can set them via the existing user management API in the meantime.
2. **OIDC provider admin CRUD endpoints** (`POST /api/oidc/providers`, `DELETE /api/oidc/providers/{id}`) — Admin can add/remove providers at runtime. For now, configure via `tinyice.json` directly.
3. **OIDC nonce validation** — Nonce in authorization request verified in ID token. PKCE and state provide sufficient protection for the initial release.
4. **Admin passkey management** (`DELETE /api/users/{username}/passkeys`) — Admin removing another user's passkeys. Users can self-service delete their own.
5. **Setup wizard steps 4-5** (OIDC provider and SMTP configuration during onboarding) — These can be configured via admin panel after setup.

## Deviations From Spec

- **Pending user endpoint paths**: `POST /api/pending-users/approve` (ID in JSON body) instead of `POST /api/pending-users/{id}/approve` — `http.ServeMux` doesn't support path parameters cleanly.
- **Passkey delete endpoint**: `DELETE /api/passkey?id=...` instead of `DELETE /api/passkey/{id}` — same reason.
- **Pending user status**: Uses `denied_at` field (empty = pending) instead of explicit `status` field — functionally equivalent, simpler.
