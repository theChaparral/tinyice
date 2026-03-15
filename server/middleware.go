package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/DatanoiseTV/tinyice/relay"
)

// contextKey is a private type for context keys to prevent collisions.
type contextKey string

const tenantContextKey contextKey = "tenant"

// TenantFromContext retrieves the tenant from the request context.
func TenantFromContext(ctx context.Context) *relay.Tenant {
	t, _ := ctx.Value(tenantContextKey).(*relay.Tenant)
	return t
}

// resolveTenant determines the tenant for a request using these strategies (in order):
// 1. Custom domain mapping
// 2. X-Tenant-ID header
// 3. Default tenant (single-tenant mode)
func (s *Server) resolveTenant(r *http.Request) *relay.Tenant {
	if s.TenantM == nil {
		return nil
	}

	// 1. Custom domain mapping
	host := r.Host
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}
	if t := s.TenantM.GetTenantByDomain(host); t != nil {
		return t
	}

	// 2. X-Tenant-ID header (for API access)
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		if t := s.TenantM.GetTenant(tenantID); t != nil {
			return t
		}
	}

	// 3. Default tenant
	return s.TenantM.GetOrCreateDefaultTenant()
}

// withTenant wraps an http.Handler to inject tenant into request context.
func (s *Server) withTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Config.MultiTenant != nil && s.Config.MultiTenant.Enabled {
			tenant := s.resolveTenant(r)
			if tenant != nil {
				ctx := context.WithValue(r.Context(), tenantContextKey, tenant)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}
