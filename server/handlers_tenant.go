package server

import (
	"encoding/json"
	"net/http"
)

// TenantUsageResponse is the API response for tenant usage.
type TenantUsageResponse struct {
	TenantID         string `json:"tenant_id"`
	Plan             string `json:"plan"`
	BytesIn          int64  `json:"bytes_in"`
	BytesOut         int64  `json:"bytes_out"`
	CurrentListeners int32  `json:"current_listeners"`
	PeakListeners    int32  `json:"peak_listeners"`
	StreamMinutes    int64  `json:"stream_minutes"`
	StreamCount      int    `json:"stream_count"`
	BandwidthLimitMB int64  `json:"bandwidth_limit_mb"`
	OverLimit        bool   `json:"over_limit"`
}

func (s *Server) handleTenantUsage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = "default"
	}

	tenant := s.TenantM.GetTenant(tenantID)
	if tenant == nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	stats := tenant.GetStats()
	resp := TenantUsageResponse{
		TenantID:         tenant.ID,
		Plan:             tenant.Plan,
		BytesIn:          stats.BytesIn,
		BytesOut:         stats.BytesOut,
		CurrentListeners: stats.CurrentListeners,
		PeakListeners:    stats.PeakListeners,
		StreamMinutes:    stats.StreamMinutes,
		StreamCount:      tenant.StreamCount(),
		BandwidthLimitMB: tenant.Limits.BandwidthLimitMB,
		OverLimit:        tenant.CheckBandwidthLimit(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	type TenantInfo struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Plan string `json:"plan"`
	}

	ids := s.TenantM.ListTenants()
	tenants := make([]TenantInfo, 0, len(ids))
	for _, id := range ids {
		t := s.TenantM.GetTenant(id)
		if t != nil {
			tenants = append(tenants, TenantInfo{
				ID:   t.ID,
				Name: t.Name,
				Plan: t.Plan,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenants)
}
