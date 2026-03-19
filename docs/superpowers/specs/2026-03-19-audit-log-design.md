# Audit Log System — Design Spec

## Goal

Add a structured audit log that records all structural admin actions (create, delete, update) with user attribution, timestamps, and IP tracking. Stored in SQLite via GORM (with future DB provider flexibility). Viewable in the admin Security page with filtering and pagination.

## Audited Actions

Only structural changes — no transport/playback actions.

| Category | Actions |
|----------|---------|
| Auth | `login`, `logout`, `login_failed`, `token_created`, `token_revoked` |
| Streams | `mount_created`, `mount_deleted` |
| AutoDJ | `autodj_created`, `autodj_deleted` |
| Relays | `relay_created`, `relay_deleted` |
| Transcoders | `transcoder_created`, `transcoder_deleted` |
| Users | `user_created`, `user_updated`, `user_deleted`, `pending_approved`, `pending_denied` |
| Security | `ip_banned`, `ip_unbanned`, `ip_whitelisted`, `ip_unwhitelisted` |
| Settings | `settings_updated`, `branding_updated`, `logo_uploaded` |

## Data Model

```go
type AuditEntry struct {
    ID           uint      `gorm:"primaryKey" json:"id"`
    Timestamp    time.Time `gorm:"index" json:"timestamp"`
    Username     string    `gorm:"index" json:"username"`
    Action       string    `gorm:"index" json:"action"`
    ResourceType string    `json:"resource_type"` // stream, autodj, relay, transcoder, user, security, settings, auth
    ResourceID   string    `json:"resource_id"`   // mount name, username, IP, etc.
    Detail       string    `json:"detail"`        // JSON blob with action-specific info
    IP           string    `json:"ip"`
}
```

Stored in the existing SQLite database managed by `relay.HistoryManager`. The `HistoryManager.db` field (GORM `*gorm.DB`) is used directly — just add `AuditEntry` to the `AutoMigrate` call.

## Backend

### Audit helper

On the `Server` struct, add:

```go
func (s *Server) Audit(user, action, resourceType, resourceID, detail, ip string) {
    if !s.Config.AuditEnabled {
        return
    }
    s.HistoryM.RecordAudit(user, action, resourceType, resourceID, detail, ip)
}
```

On `HistoryManager`:

```go
func (hm *HistoryManager) RecordAudit(user, action, resourceType, resourceID, detail, ip string) {
    hm.db.Create(&AuditEntry{
        Timestamp:    time.Now(),
        Username:     user,
        Action:       action,
        ResourceType: resourceType,
        ResourceID:   resourceID,
        Detail:       detail,
        IP:           ip,
    })
}

func (hm *HistoryManager) GetAuditLog(page, limit int, action string) ([]AuditEntry, int64) {
    var entries []AuditEntry
    var total int64
    q := hm.db.Model(&AuditEntry{})
    if action != "" {
        q = q.Where("action LIKE ?", action+"%")
    }
    q.Count(&total)
    q.Order("timestamp DESC").Offset((page - 1) * limit).Limit(limit).Find(&entries)
    return entries, total
}
```

### API endpoint

`GET /api/security/audit` — requires superadmin.

Query params:
- `page` (default 1)
- `limit` (default 25, max 100)
- `category` (optional filter: auth, streams, autodj, relays, transcoders, users, security, settings)

Response:
```json
{
    "entries": [...],
    "total": 142,
    "page": 1,
    "limit": 25
}
```

Category filtering maps to action prefix matching (e.g. category=auth matches login, logout, login_failed, token_created, token_revoked).

### Instrumentation

Add `s.Audit(...)` calls to these existing handlers:

- `apiCreateStream` — after success
- `apiDeleteStream` — after success
- `apiCreateAutoDJ` — after success
- `apiDeleteAutoDJ` — after success
- `apiCreateRelay` — after success
- `apiDeleteRelay` — after success
- `apiCreateTranscoder` — after success
- `apiDeleteTranscoder` — after success
- `apiCreateUser` — after success
- `apiUpdateUser` — after success
- `apiDeleteUser` — after success
- `handleApprovePendingUser` — after success
- `handleDenyPendingUser` — after success
- `apiAddBan` — after success
- `apiRemoveBan` — after success
- `apiAddWhitelist` — after success
- `apiRemoveWhitelist` — after success
- `apiUpdateSettings` — after success
- `apiUpdateBranding` — after success
- `apiUploadLogo` — after success
- `apiCreateToken` — after success
- `apiDeleteToken` — after success
- `handleLogin` (success) — after session created
- `handleLogin` (failure) — after auth failed
- `handleLogout` — before session destroyed

## Config

Add to `Config` struct:

```go
AuditEnabled bool `json:"audit_enabled"`
```

Default: `true` (set in `LoadConfig` defaults).

Exposed in `apiGetSettings` / `apiUpdateSettings` responses.

## Frontend

### Security page changes

Add a tab bar to the Security page: **Bans & Whitelist** | **Audit Log**

The Audit Log tab shows:

1. **Filter bar**: Category dropdown (All, Auth, Streams, AutoDJ, Relays, Transcoders, Users, Security, Settings)
2. **Table**: Time (relative + tooltip with absolute), User, Action (styled badge), Resource, IP
3. **Detail row**: Clicking a row expands it to show the detail JSON formatted nicely
4. **Pagination**: "Showing 1-25 of 142" with Prev/Next buttons
5. **Empty state**: "No audit log entries" or "Audit logging is disabled" with link to Settings

### Settings page changes

Add "AUDIT LOGGING" toggle in the Server tab, with description "Record all admin actions (create, edit, delete) for security review."

## OpenAPI

Add `GET /api/security/audit` to the spec under the Security tag.
Add `audit_enabled` to the Settings schema.
