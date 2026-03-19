# API Token (Bearer Auth) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow users to create, manage, and revoke API access tokens that authenticate via `Authorization: Bearer <token>` header, with a full admin UI for token lifecycle management.

**Architecture:** Tokens are stored in the config JSON alongside users. Each token has a SHA-256 hash (raw token shown once at creation), links to a user, has an optional name/description, and tracks last-used timestamp and IP. The `checkAuth` function is extended to check Bearer tokens before falling through to session/basic auth. A new admin page provides CRUD for tokens.

**Tech Stack:** Go stdlib (crypto/sha256, crypto/rand), Preact + Signals frontend, existing config.json persistence

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `config/config.go` | Modify | Add `APIToken` struct, add `APITokens` field to `Config` |
| `server/auth.go` | Modify | Extend `checkAuth` to check Bearer tokens, add token CRUD helpers |
| `server/handlers_api_v2.go` | Modify | Add token CRUD API endpoints |
| `server/server.go` | Modify | Register `/api/tokens` routes |
| `server/openapi.yaml` | Modify | Document token endpoints |
| `server/frontend/src/pages/admin/APITokens.tsx` | Create | Token management UI page |
| `server/frontend/src/pages/admin/AdminLayout.tsx` | Modify | Add route for `/admin/tokens` |
| `server/frontend/src/components/Sidebar.tsx` | Modify | Add "API Tokens" nav item |

---

### Task 1: Add APIToken model to config

**Files:**
- Modify: `config/config.go`

- [ ] **Step 1: Add the APIToken struct and Config field**

Add after the `User` struct (around line 65):

```go
type APIToken struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	TokenHash   string `json:"token_hash"`   // SHA-256 hash of the raw token
	Username    string `json:"username"`      // Owner user
	Role        string `json:"role"`          // Permission level (inherits from user or override)
	CreatedAt   string `json:"created_at"`    // RFC3339
	LastUsedAt  string `json:"last_used_at"`  // RFC3339, empty if never used
	LastUsedIP  string `json:"last_used_ip"`  // IP of last use
	ExpiresAt   string `json:"expires_at"`    // RFC3339, empty = never expires
}
```

Add to the `Config` struct (after `Users` field, around line 189):

```go
	APITokens []*APIToken `json:"api_tokens,omitempty"`
```

- [ ] **Step 2: Verify Go compiles**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: Clean build

- [ ] **Step 3: Commit**

```bash
git add config/config.go
git commit -m "feat: add APIToken model to config"
```

---

### Task 2: Implement Bearer auth in checkAuth

**Files:**
- Modify: `server/auth.go`

- [ ] **Step 1: Add token helper functions**

Add these functions to `server/auth.go`:

```go
import (
	"crypto/sha256"
	// ... existing imports
)

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ti_" + hex.EncodeToString(b), nil
}
```

- [ ] **Step 2: Extend checkAuth to support Bearer tokens**

Modify `checkAuth` in `server/auth.go` (around line 132). Add Bearer token check BEFORE the session cookie check:

```go
func (s *Server) checkAuth(r *http.Request) (*config.User, bool) {
	// Check Bearer token first
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		raw := strings.TrimPrefix(auth, "Bearer ")
		hash := hashToken(raw)
		for _, tok := range s.Config.APITokens {
			if tok.TokenHash == hash {
				user, exists := s.Config.Users[tok.Username]
				if !exists {
					return nil, false
				}
				// Update last-used tracking
				tok.LastUsedAt = time.Now().Format(time.RFC3339)
				host, _, _ := net.SplitHostPort(r.RemoteAddr)
				tok.LastUsedIP = host
				// Check expiry
				if tok.ExpiresAt != "" {
					if exp, err := time.Parse(time.RFC3339, tok.ExpiresAt); err == nil && time.Now().After(exp) {
						return nil, false
					}
				}
				return user, true
			}
		}
		return nil, false
	}

	// Existing session cookie check...
	if cookie, err := r.Cookie("sid"); err == nil {
		// ... rest of existing code unchanged
```

- [ ] **Step 3: Verify Go compiles**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: Clean build

- [ ] **Step 4: Commit**

```bash
git add server/auth.go
git commit -m "feat: extend checkAuth with Bearer token support"
```

---

### Task 3: Add token CRUD API endpoints

**Files:**
- Modify: `server/handlers_api_v2.go`
- Modify: `server/server.go`

- [ ] **Step 1: Add token handlers to handlers_api_v2.go**

Add before the `// Settings` section (around line 1559):

```go
// ---------------------------------------------------------------------------
// API Tokens
// ---------------------------------------------------------------------------

func (s *Server) apiGetTokens(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	type tokenInfo struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Username   string `json:"username"`
		CreatedAt  string `json:"created_at"`
		LastUsedAt string `json:"last_used_at"`
		LastUsedIP string `json:"last_used_ip"`
		ExpiresAt  string `json:"expires_at"`
		Prefix     string `json:"prefix"` // First 8 chars for identification
	}

	var result []tokenInfo
	for _, tok := range s.Config.APITokens {
		// Superadmins see all tokens, others see only their own
		if user.Role != config.RoleSuperAdmin && tok.Username != user.Username {
			continue
		}
		prefix := tok.ID[:8] // Token IDs are hex strings
		result = append(result, tokenInfo{
			ID:         tok.ID,
			Name:       tok.Name,
			Username:   tok.Username,
			CreatedAt:  tok.CreatedAt,
			LastUsedAt: tok.LastUsedAt,
			LastUsedIP: tok.LastUsedIP,
			ExpiresAt:  tok.ExpiresAt,
			Prefix:     "ti_" + prefix + "...",
		})
	}
	if result == nil {
		result = []tokenInfo{}
	}
	jsonResponse(w, result)
}

func (s *Server) apiCreateToken(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Name      string `json:"name"`
		ExpiresAt string `json:"expires_at"` // RFC3339, optional
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Name == "" {
		jsonError(w, "Name is required", http.StatusBadRequest)
		return
	}

	raw, err := generateToken()
	if err != nil {
		jsonError(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	tok := &config.APIToken{
		ID:        hex.EncodeToString([]byte(raw[3:19])), // Use part of raw token as ID
		Name:      body.Name,
		TokenHash: hashToken(raw),
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: time.Now().Format(time.RFC3339),
		ExpiresAt: body.ExpiresAt,
	}

	s.Config.APITokens = append(s.Config.APITokens, tok)
	s.Config.SaveConfig()

	// Return raw token ONCE — it cannot be retrieved later
	jsonResponse(w, map[string]string{
		"id":    tok.ID,
		"token": raw,
		"name":  tok.Name,
	})
}

func (s *Server) apiDeleteToken(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		jsonError(w, "Token ID is required", http.StatusBadRequest)
		return
	}

	newTokens := []*config.APIToken{}
	found := false
	for _, tok := range s.Config.APITokens {
		if tok.ID == id {
			// Only superadmins can delete other users' tokens
			if user.Role != config.RoleSuperAdmin && tok.Username != user.Username {
				jsonError(w, "Forbidden", http.StatusForbidden)
				return
			}
			found = true
		} else {
			newTokens = append(newTokens, tok)
		}
	}
	if !found {
		jsonError(w, "Token not found", http.StatusNotFound)
		return
	}
	s.Config.APITokens = newTokens
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "deleted"})
}
```

- [ ] **Step 2: Register routes in server.go**

Add after the `/api/stats` route (around line 578):

```go
	mux.HandleFunc("/api/tokens", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetTokens(w, r)
		case http.MethodPost:
			s.apiCreateToken(w, r)
		case http.MethodDelete:
			s.apiDeleteToken(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
```

- [ ] **Step 3: Verify Go compiles**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: Clean build

- [ ] **Step 4: Commit**

```bash
git add server/handlers_api_v2.go server/server.go
git commit -m "feat: add API token CRUD endpoints"
```

---

### Task 4: Build API Tokens admin page

**Files:**
- Create: `server/frontend/src/pages/admin/APITokens.tsx`

- [ ] **Step 1: Create the APITokens page component**

Create `server/frontend/src/pages/admin/APITokens.tsx` with:
- List of existing tokens showing: name, prefix (ti_abc123...), created date, last used date/IP, expiry
- "Create Token" button that opens a modal (name field, optional expiry dropdown: never/30d/90d/1y)
- On create: show the raw token ONCE in a modal with a copy button and warning "This won't be shown again"
- Delete button per token with confirmation
- Use the `api` helper from `@/lib/api` for all requests
- Endpoints: `GET /api/tokens`, `POST /api/tokens`, `DELETE /api/tokens?id=X`
- Relative time formatting for "last used" (e.g. "2 hours ago", "never")
- Match existing admin UI style (font-mono, text-text-primary, bg-surface-raised, border-border, etc.)

- [ ] **Step 2: Build to verify TypeScript compiles**

Run: `cd /Users/dev/dev/tinyice/server/frontend && npm run build`
Expected: Clean build

- [ ] **Step 3: Commit**

```bash
git add server/frontend/src/pages/admin/APITokens.tsx
git commit -m "feat: add API tokens admin page"
```

---

### Task 5: Wire up routing and navigation

**Files:**
- Modify: `server/frontend/src/pages/admin/AdminLayout.tsx`
- Modify: `server/frontend/src/components/Sidebar.tsx`

- [ ] **Step 1: Add route to AdminLayout**

Import the new component and add a route:

```tsx
import { APITokens } from './APITokens'
// ...
<Route path="/admin/tokens" component={APITokens} />
```

- [ ] **Step 2: Add sidebar nav item**

In `Sidebar.tsx`, add to `BOTTOM_ITEMS` array (after "Security", before "Settings"):

```tsx
{ id: 'tokens', label: 'API Keys', href: '/admin/tokens',
  icon: '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />' },
```

- [ ] **Step 3: Build frontend**

Run: `cd /Users/dev/dev/tinyice/server/frontend && npm run build`
Expected: Clean build

- [ ] **Step 4: Commit**

```bash
git add server/frontend/src/pages/admin/AdminLayout.tsx server/frontend/src/components/Sidebar.tsx
git commit -m "feat: add API tokens to admin navigation"
```

---

### Task 6: Update OpenAPI spec

**Files:**
- Modify: `server/openapi.yaml`

- [ ] **Step 1: Add Bearer auth scheme and token endpoints**

Add to `components.securitySchemes`:
```yaml
    bearer:
      type: http
      scheme: bearer
      description: API token obtained from the admin panel (format: ti_...)
```

Add to `paths`:
```yaml
  /api/tokens:
    get:
      tags: [Auth]
      summary: List API tokens
      description: Superadmins see all tokens; other users see only their own.
      security: [session: [], bearer: []]
      responses:
        "200":
          description: Array of token metadata (never includes the raw token)
    post:
      tags: [Auth]
      summary: Create API token
      description: |
        Creates a new API token. The raw token is returned ONCE in the response
        and cannot be retrieved later. Store it securely.
      security: [session: [], bearer: []]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name:
                  type: string
                  example: CI/CD Pipeline
                expires_at:
                  type: string
                  format: date-time
                  description: Optional expiry (RFC3339). Empty = never expires.
      responses:
        "200":
          description: Token created — raw token included (shown only once)
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: string
                  token:
                    type: string
                    description: Raw token (ti_...) — save this, it won't be shown again
                  name:
                    type: string
    delete:
      tags: [Auth]
      summary: Revoke API token
      security: [session: [], bearer: []]
      parameters:
        - name: id
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: Token revoked
```

Update the top-level description to mention Bearer auth.

Update all existing endpoint `security` fields to also accept bearer: change `security: [session: []]` to `security: [{session: []}, {bearer: []}]` (means either auth method works).

- [ ] **Step 2: Verify Go still builds (openapi.yaml is embedded)**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: Clean build

- [ ] **Step 3: Commit**

```bash
git add server/openapi.yaml
git commit -m "docs: add Bearer auth and token endpoints to OpenAPI spec"
```

---

### Task 7: Periodic save of last-used tracking

**Files:**
- Modify: `server/auth.go`

- [ ] **Step 1: Add debounced save for token usage tracking**

The `checkAuth` function updates `LastUsedAt` and `LastUsedIP` on every request, but calling `SaveConfig()` on every API call would be expensive. Add a debounced save that writes at most once per 60 seconds:

In `server/auth.go`, add a field and helper:

```go
// Add to the Bearer token check in checkAuth, replace direct field updates with:
func (s *Server) touchToken(tok *config.APIToken, ip string) {
	tok.LastUsedAt = time.Now().Format(time.RFC3339)
	host, _, _ := net.SplitHostPort(ip)
	tok.LastUsedIP = host
	// Persist periodically — not on every request
	s.tokenSaveMu.Lock()
	if s.tokenSaveTimer == nil {
		s.tokenSaveTimer = time.AfterFunc(60*time.Second, func() {
			s.Config.SaveConfig()
			s.tokenSaveMu.Lock()
			s.tokenSaveTimer = nil
			s.tokenSaveMu.Unlock()
		})
	}
	s.tokenSaveMu.Unlock()
}
```

Add to Server struct in `server/server.go`:
```go
	tokenSaveTimer *time.Timer
	tokenSaveMu   sync.Mutex
```

- [ ] **Step 2: Verify Go compiles**

Run: `cd /Users/dev/dev/tinyice && go build ./...`
Expected: Clean build

- [ ] **Step 3: Commit**

```bash
git add server/auth.go server/server.go
git commit -m "feat: debounced save for token last-used tracking"
```
