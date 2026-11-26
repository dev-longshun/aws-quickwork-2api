package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"quickwork-openai/internal/outbound"
	"quickwork-openai/internal/store"
)

func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	proxies, err := s.store.ProxyInfos(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not list proxies")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proxies": proxies})
}

func (s *Server) handleProxyImport(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Proxies       string `json:"proxies"`
		DefaultScheme string `json:"default_scheme"`
	}
	if !decodeJSON(w, r, &input, 1<<20) {
		return
	}
	parsed, err := outbound.ParseListWithDefault(input.Proxies, input.DefaultScheme)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_proxy_list", err.Error())
		return
	}
	imported, err := s.store.ImportProxiesWithDefault(r.Context(), input.Proxies, input.DefaultScheme)
	input.Proxies = ""
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not import proxies")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": imported, "parsed": len(parsed)})
}

func (s *Server) handleProxyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || id == "direct" {
		writeError(w, http.StatusBadRequest, "invalid_proxy", "Select a stored proxy")
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if id == s.cfg.ProxyID || id == s.saved.ProxyID {
		writeError(w, http.StatusConflict, "proxy_in_use", "Change the default proxy before deleting it")
		return
	}
	removed, err := s.store.DeleteProxy(r.Context(), id)
	if errors.Is(err, store.ErrProxyInUse) {
		writeError(w, http.StatusConflict, "proxy_in_use", "Unbind accounts before deleting this proxy")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not delete proxy")
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "proxy_not_found", "Proxy not found")
		return
	}
	s.cfg.Proxies.CloseIdleConnections()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleProxyRename(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Label string `json:"label"`
	}
	if !decodeJSON(w, r, &input, 4<<10) {
		return
	}
	label := strings.TrimSpace(input.Label)
	if label == "" || len(label) > 120 {
		writeError(w, http.StatusBadRequest, "invalid_label", "Name must be 1-120 characters")
		return
	}
	ok, err := s.store.RenameProxy(r.Context(), r.PathValue("id"), label)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not rename proxy")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "proxy_not_found", "Proxy not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleProxyCheck fetches the exit IP through one proxy ("direct" tests the
// server's own network).
func (s *Server) handleProxyCheck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.cfg.Proxies.Has(id) {
		writeError(w, http.StatusNotFound, "proxy_not_found", "Proxy not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	client, err := s.cfg.Proxies.Client(ctx, id, 15*time.Second)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	started := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,query", nil)
	resp, err := client.Do(req)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		message := err.Error()
		if i := strings.LastIndex(message, ": "); i >= 0 && len(message)-i < 120 {
			message = message[i+2:]
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": message, "latency_ms": latency})
		return
	}
	defer resp.Body.Close()
	var info struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		Region      string `json:"regionName"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		IP          string `json:"query"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&info); err != nil || info.IP == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": fmt.Sprintf("unexpected response (HTTP %d)", resp.StatusCode), "latency_ms": latency})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "ip": info.IP, "country": info.Country, "country_code": info.CountryCode,
		"region": info.Region, "city": info.City, "isp": info.ISP, "latency_ms": latency,
	})
}
