package admin

// Remote authorization links ("tickets").
//
// The administrator generates /authorize/<token> links and sends them to
// whoever holds the upstream accounts. The link page is public: the random
// token is the credential, and holding it only lets someone sign one account
// into this proxy. It never exposes accounts, settings, or other tickets.
//
// The public page drives the same two-step browser sign-in as the console
// (discovery callback, then authorization callback), so no callback port has
// to be reachable from the colleague's browser.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"quickwork-openai/internal/oauth"
	"quickwork-openai/internal/store"
)

const (
	maxTicketBatch          = 50
	maxOpenTickets          = 500
	maxActiveTicketLogins   = 64
	defaultTicketTTLHours   = 24 * 7
	maxTicketTTLHours       = 24 * 30
	defaultTicketActivation = 10
	maxTicketActivation     = 50
)

type ticketLogin struct {
	flow *oauth.BrowserLogin
}

func activeStage(stage string) bool {
	return stage == "discovery" || stage == "authorize"
}

func newTicketID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// validTicketToken accepts only the URL-safe base64 tokens randomToken makes.
func validTicketToken(token string) bool {
	if len(token) < 32 || len(token) > 64 {
		return false
	}
	for _, r := range token {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func maskEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		if email == "" {
			return ""
		}
		return "***"
	}
	local := email[:at]
	keep := 2
	if len(local) <= 2 {
		keep = 1
	}
	return local[:keep] + "***" + email[at:]
}

// ---- Administrator API -------------------------------------------------

type ticketView struct {
	store.AuthTicket
	Path        string `json:"path"`
	FlowStage   string `json:"flow_stage,omitempty"`
	Activations int64  `json:"activations_left"`
}

func (s *Server) ticketView(t store.AuthTicket, now time.Time) ticketView {
	t.Status = t.EffectiveStatus(now)
	view := ticketView{AuthTicket: t, Path: "/authorize/" + t.Token}
	view.Activations = max(t.MaxActivations-t.ActivationCount, 0)
	s.mu.Lock()
	if entry, ok := s.ticketLogins[t.ID]; ok {
		if stage := entry.flow.Status().Stage; activeStage(stage) {
			view.FlowStage = stage
		}
	}
	s.mu.Unlock()
	// A sign-in that timed out or was lost on restart leaves the ticket
	// reusable; show it as not opened until someone starts again.
	if view.Status == store.TicketAuthorizing && view.FlowStage == "" {
		view.Status = store.TicketPending
	}
	return view
}

func (s *Server) handleTickets(w http.ResponseWriter, r *http.Request) {
	tickets, err := s.store.Tickets(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not load authorization links")
		return
	}
	now := time.Now()
	views := make([]ticketView, 0, len(tickets))
	for _, t := range tickets {
		views = append(views, s.ticketView(t, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tickets": views})
}

func (s *Server) handleTicketCreate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Count          int    `json:"count"`
		Label          string `json:"label"`
		Provider       string `json:"provider"`
		Stage          string `json:"stage"`
		Region         string `json:"region"`
		ProxyID        string `json:"proxy_id"`
		TTLHours       int    `json:"ttl_hours"`
		MaxActivations int    `json:"max_activations"`
	}
	if !decodeJSON(w, r, &input, 4<<10) {
		return
	}
	if input.Count == 0 {
		input.Count = 1
	}
	if input.Count < 1 || input.Count > maxTicketBatch {
		writeError(w, http.StatusBadRequest, "invalid_count", "Generate between 1 and 50 links at a time")
		return
	}
	if input.TTLHours == 0 {
		input.TTLHours = defaultTicketTTLHours
	}
	if input.TTLHours < 1 || input.TTLHours > maxTicketTTLHours {
		writeError(w, http.StatusBadRequest, "invalid_ttl", "Link lifetime must be between 1 hour and 30 days")
		return
	}
	if input.MaxActivations == 0 {
		input.MaxActivations = defaultTicketActivation
	}
	if input.MaxActivations < 1 || input.MaxActivations > maxTicketActivation {
		writeError(w, http.StatusBadRequest, "invalid_activations", "Sign-in attempts per link must be between 1 and 50")
		return
	}
	input.Label = strings.TrimSpace(input.Label)
	if len(input.Label) > 120 {
		writeError(w, http.StatusBadRequest, "invalid_label", "Label is too long")
		return
	}
	if input.Provider == "" {
		input.Provider = s.cfg.OAuth.Provider
	}
	if input.Stage == "" {
		input.Stage = s.cfg.OAuth.BuildStage
	}
	if input.Region == "" {
		input.Region = s.cfg.OAuth.Region
	}
	input.Provider = strings.ToLower(strings.TrimSpace(input.Provider))
	input.Stage = strings.ToLower(strings.TrimSpace(input.Stage))
	input.Region = strings.ToLower(strings.TrimSpace(input.Region))
	switch input.Provider {
	case "social", "enterprise", "gateway", "social_gateway":
	default:
		writeError(w, http.StatusBadRequest, "invalid_provider", "Unknown OAuth provider")
		return
	}
	switch input.Stage {
	case "prod", "beta", "integ", "dev":
	default:
		writeError(w, http.StatusBadRequest, "invalid_stage", "Unknown OAuth build stage")
		return
	}
	if len(input.Region) > 64 || strings.Trim(input.Region, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		writeError(w, http.StatusBadRequest, "invalid_region", "Region may only contain lowercase letters, digits and hyphens")
		return
	}
	if !s.cfg.Proxies.Has(input.ProxyID) {
		writeError(w, http.StatusBadRequest, "invalid_proxy", "Select an available proxy")
		return
	}
	now := time.Now()
	open, err := s.store.CountOpenTickets(r.Context(), now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not create authorization links")
		return
	}
	if open+int64(input.Count) > maxOpenTickets {
		writeError(w, http.StatusTooManyRequests, "ticket_limit", "Too many open authorization links; delete unused ones first")
		return
	}
	tickets := make([]store.AuthTicket, 0, input.Count)
	for i := 0; i < input.Count; i++ {
		id, err := newTicketID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "ticket_failed", "Could not create authorization links")
			return
		}
		token, err := randomToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "ticket_failed", "Could not create authorization links")
			return
		}
		tickets = append(tickets, store.AuthTicket{
			ID: id, Token: token, Label: input.Label,
			Provider: input.Provider, Stage: input.Stage, Region: input.Region, ProxyID: input.ProxyID,
			Status: store.TicketPending, MaxActivations: int64(input.MaxActivations),
			CreatedAt: now.Unix(), ExpiresAt: now.Add(time.Duration(input.TTLHours) * time.Hour).Unix(),
		})
	}
	if err := s.store.CreateTickets(r.Context(), tickets); err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not create authorization links")
		return
	}
	for _, t := range tickets {
		ev := s.newTicketEvent(r, t.ID, "create")
		ev.ok(fmt.Sprintf("link created (%s, valid %dh, %d attempts)", t.Provider, input.TTLHours, input.MaxActivations))
		ev.save()
	}
	views := make([]ticketView, 0, len(tickets))
	for _, t := range tickets {
		views = append(views, s.ticketView(t, now))
	}
	writeJSON(w, http.StatusCreated, map[string]any{"tickets": views})
}

func (s *Server) cancelTicketLogin(id string) {
	s.mu.Lock()
	entry, ok := s.ticketLogins[id]
	delete(s.ticketLogins, id)
	s.mu.Unlock()
	if ok {
		entry.flow.Cancel()
	}
}

func (s *Server) handleTicketDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.cancelTicketLogin(id)
	ok, err := s.store.DeleteTicket(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not delete the authorization link")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "ticket_not_found", "Authorization link not found")
		return
	}
	ev := s.newTicketEvent(r, id, "delete")
	ev.ok("link deleted")
	ev.save()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handleTicketPurge(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	tickets, err := s.store.Tickets(r.Context())
	if err == nil {
		for _, t := range tickets {
			if status := t.EffectiveStatus(now); status != store.TicketPending && status != store.TicketAuthorizing {
				s.cancelTicketLogin(t.ID)
			}
		}
	}
	n, err := s.store.PurgeClosedTickets(r.Context(), now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not clean up authorization links")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

// handleTicketAdminCallback lets the administrator paste a callback URL that
// the recipient sent over chat, for a link that is mid sign-in.
func (s *Server) handleTicketAdminCallback(w http.ResponseWriter, r *http.Request) {
	ticket, err := s.store.TicketByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not load the authorization link")
		return
	}
	if ticket == nil {
		writeError(w, http.StatusNotFound, "ticket_not_found", "Authorization link not found")
		return
	}
	t, entry, err := s.loadTicket(r.Context(), ticket.Token)
	if err != nil || t == nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not load the authorization link")
		return
	}
	s.handleTicketCallback(w, r, t, entry)
}

// ---- Public authorization page -----------------------------------------

type publicTicketStatus struct {
	Status          string `json:"status"`
	Label           string `json:"label,omitempty"`
	Provider        string `json:"provider"`
	ExpiresAt       int64  `json:"expires_at"`
	ActivationsLeft int64  `json:"activations_left"`
	FlowStage       string `json:"flow_stage,omitempty"`
	FlowURL         string `json:"flow_url,omitempty"`
	FlowExpiresAt   int64  `json:"flow_expires_at,omitempty"`
	Account         string `json:"account,omitempty"`
}

// loadTicket fetches a ticket and reconciles it with its in-memory sign-in:
// a sign-in that expired or was cancelled returns the ticket to pending, and
// an expired ticket loses its sign-in.
func (s *Server) loadTicket(ctx context.Context, token string) (*store.AuthTicket, *ticketLogin, error) {
	t, err := s.store.TicketByToken(ctx, token)
	if err != nil || t == nil {
		return nil, nil, err
	}
	now := time.Now()
	t.Status = t.EffectiveStatus(now)
	s.mu.Lock()
	entry, ok := s.ticketLogins[t.ID]
	if ok && (!activeStage(entry.flow.Status().Stage) || t.Status != store.TicketAuthorizing) {
		delete(s.ticketLogins, t.ID)
		entry.flow.Cancel()
		entry, ok = nil, false
	}
	s.mu.Unlock()
	if !ok && t.Status == store.TicketAuthorizing {
		if err := s.store.ResetTicket(ctx, t.ID); err != nil {
			return nil, nil, err
		}
		t.Status = store.TicketPending
	}
	return t, entry, nil
}

func publicStatus(t *store.AuthTicket, entry *ticketLogin) publicTicketStatus {
	out := publicTicketStatus{
		Status: t.Status, Label: t.Label, Provider: t.Provider, ExpiresAt: t.ExpiresAt,
		ActivationsLeft: max(t.MaxActivations-t.ActivationCount, 0),
	}
	if entry != nil {
		flow := entry.flow.Status()
		if activeStage(flow.Stage) {
			out.FlowStage, out.FlowURL, out.FlowExpiresAt = flow.Stage, flow.URL, flow.ExpiresAt
		}
	}
	if t.Status == store.TicketCompleted {
		out.Account = maskEmail(t.AccountEmail)
	}
	return out
}

func (s *Server) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/authorize/")
	token, action, _ := strings.Cut(rest, "/")
	if !validTicketToken(token) {
		http.NotFound(w, r)
		return
	}
	switch action {
	case "":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, "GET")
			return
		}
		if r.Method == http.MethodGet {
			if t, err := s.store.TicketByToken(r.Context(), token); err == nil && t != nil {
				ev := s.newTicketEvent(r, t.ID, "open")
				ev.ok("link page opened, status " + t.EffectiveStatus(time.Now()))
				ev.save()
			}
		}
		s.serveAsset(w, r, "static/authorize.html", "text/html; charset=utf-8")
		return
	case "status":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
	case "start", "callback":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "invalid_origin", "Cross-origin requests are not allowed")
			return
		}
	default:
		http.NotFound(w, r)
		return
	}

	t, entry, err := s.loadTicket(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Service is temporarily unavailable")
		return
	}
	if t == nil {
		writeError(w, http.StatusNotFound, "ticket_not_found", "This authorization link does not exist or was deleted")
		return
	}
	switch action {
	case "status":
		writeJSON(w, http.StatusOK, publicStatus(t, entry))
	case "start":
		s.handleTicketStart(w, r, t, entry)
	case "callback":
		s.handleTicketCallback(w, r, t, entry)
	}
}

func (s *Server) handleTicketStart(w http.ResponseWriter, r *http.Request, t *store.AuthTicket, entry *ticketLogin) {
	ev := s.newTicketEvent(r, t.ID, "start")
	defer ev.save()
	writeError := ev.writeError
	var input struct{}
	if !decodeJSON(w, r, &input, 1<<10) {
		return
	}
	switch t.Status {
	case store.TicketCompleted:
		writeError(w, http.StatusConflict, "ticket_completed", "This link has already been used to authorize an account")
		return
	case store.TicketExpired:
		writeError(w, http.StatusGone, "ticket_expired", "This authorization link has expired")
		return
	}
	if entry != nil {
		ev.ok("reused sign-in already in progress, stage " + entry.flow.Status().Stage)
		writeJSON(w, http.StatusOK, publicStatus(t, entry))
		return
	}
	if t.ActivationCount >= t.MaxActivations {
		writeError(w, http.StatusConflict, "ticket_exhausted", "This link has no sign-in attempts left; ask for a new link")
		return
	}
	if !s.cfg.Proxies.Has(t.ProxyID) {
		writeError(w, http.StatusConflict, "invalid_proxy", "The outbound proxy for this link is no longer available; ask for a new link")
		return
	}
	timeout := s.cfg.OAuth.Timeout.Duration()
	if remaining := time.Until(time.Unix(t.ExpiresAt, 0)); remaining < timeout {
		timeout = remaining
	}
	flow, err := oauth.NewBrowserLogin(oauth.LoginOptions{
		Provider: t.Provider, Stage: t.Stage, Region: t.Region,
		ProxyID: t.ProxyID, Proxies: s.cfg.Proxies,
		Port: s.cfg.OAuth.CallbackPort, Timeout: timeout, AppVersion: s.cfg.AppVersion,
	}, s.store)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login_failed", "Could not start sign-in")
		return
	}

	s.mu.Lock()
	if existing, ok := s.ticketLogins[t.ID]; ok && activeStage(existing.flow.Status().Stage) {
		// Another request started a sign-in concurrently; reuse it.
		s.mu.Unlock()
		flow.Cancel()
		ev.ok("reused concurrent sign-in")
		writeJSON(w, http.StatusOK, publicStatus(t, existing))
		return
	}
	active := 0
	for id, e := range s.ticketLogins {
		if activeStage(e.flow.Status().Stage) {
			active++
		} else {
			delete(s.ticketLogins, id)
		}
	}
	if active >= maxActiveTicketLogins {
		s.mu.Unlock()
		flow.Cancel()
		writeError(w, http.StatusTooManyRequests, "login_limit", "Too many sign-ins in progress; try again in a few minutes")
		return
	}
	ok, err := s.store.ActivateTicket(r.Context(), t.ID, time.Now())
	if err != nil || !ok {
		s.mu.Unlock()
		flow.Cancel()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database_error", "Service is temporarily unavailable")
		} else {
			writeError(w, http.StatusConflict, "ticket_exhausted", "This link can no longer start a sign-in; ask for a new link")
		}
		return
	}
	entry = &ticketLogin{flow: flow}
	s.ticketLogins[t.ID] = entry
	s.mu.Unlock()

	t.Status = store.TicketAuthorizing
	t.ActivationCount++
	ev.ok(fmt.Sprintf("sign-in started (attempt %d/%d), waiting for step 1 address", t.ActivationCount, t.MaxActivations))
	writeJSON(w, http.StatusCreated, publicStatus(t, entry))
}

func (s *Server) handleTicketCallback(w http.ResponseWriter, r *http.Request, t *store.AuthTicket, entry *ticketLogin) {
	ev := s.newTicketEvent(r, t.ID, "callback")
	defer ev.save()
	writeError := ev.writeError
	var input struct {
		URL string `json:"url"`
	}
	if !decodeJSON(w, r, &input, 128<<10) {
		ev.fail("invalid request body")
		return
	}
	ev.Input = callbackKind(input.URL)
	if entry == nil || t.Status != store.TicketAuthorizing {
		writeError(w, http.StatusConflict, "login_not_found", "No sign-in is in progress; click Start sign-in first")
		return
	}
	before := entry.flow.Status().Stage
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout.Duration())
	defer cancel()
	status, err := entry.flow.Submit(ctx, input.URL)
	input.URL = ""
	if err != nil {
		writeError(w, http.StatusBadRequest, "callback_failed", err.Error())
		ev.fail("rejected at stage " + before + ": " + err.Error())
		if cause := oauth.ErrorDetail(err); cause != "" {
			ev.Detail += " | upstream: " + cause
		}
		return
	}
	if status.Stage == "complete" {
		email := ""
		if account, err := s.store.Get(r.Context(), status.AccountID); err == nil && account != nil {
			email = account.Email
			if email == "" {
				email = account.DisplayName
			}
		}
		if err := s.store.CompleteTicket(r.Context(), t.ID, status.AccountID, email, time.Now()); err != nil {
			writeError(w, http.StatusInternalServerError, "database_error", "The account was saved, but the link status could not be updated")
			return
		}
		s.mu.Lock()
		delete(s.ticketLogins, t.ID)
		s.mu.Unlock()
		t.Status, t.AccountID, t.AccountEmail = store.TicketCompleted, status.AccountID, email
		ev.ok(fmt.Sprintf("authorized: account #%d %s", status.AccountID, email))
		writeJSON(w, http.StatusOK, publicStatus(t, nil))
		return
	}
	switch {
	case before == "authorize" && status.Stage == "authorize":
		ev.ok("step 1 address submitted AGAIN; still waiting for the final 127.0.0.1:18080/?code= address")
	case status.Stage == "authorize":
		ev.ok("step 1 accepted; waiting for the final 127.0.0.1:18080/?code= address")
	default:
		ev.ok("stage " + before + " -> " + status.Stage)
	}
	writeJSON(w, http.StatusOK, publicStatus(t, entry))
}

// ---- Audit log ---------------------------------------------------------

type ticketEvent struct {
	store.TicketEvent
	s     *Server
	saved bool
}

func clientIP(r *http.Request) string {
	// The container only listens on loopback behind nginx, which sets X-Real-IP.
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) newTicketEvent(r *http.Request, ticketID, action string) *ticketEvent {
	actor := "public"
	if _, ok := r.Context().Value(sessionContextKey{}).([32]byte); ok {
		actor = "admin"
	}
	return &ticketEvent{s: s, TicketEvent: store.TicketEvent{
		TicketID: ticketID, At: time.Now().Unix(), IP: clientIP(r), Actor: actor, Action: action, Result: "error",
	}}
}

func (e *ticketEvent) ok(detail string)   { e.Result, e.Detail = "ok", detail }
func (e *ticketEvent) fail(detail string) { e.Result, e.Detail = "error", detail }

// writeError records the failure on the event before answering.
func (e *ticketEvent) writeError(w http.ResponseWriter, status int, code, message string) {
	e.fail(code + ": " + message)
	writeError(w, status, code, message)
}

func (e *ticketEvent) save() {
	if e.saved {
		return
	}
	e.saved = true
	if e.Detail == "" {
		e.Detail = "no response recorded"
	}
	log.Printf("ticket=%s actor=%s ip=%s action=%s input=%s result=%s detail=%q",
		e.TicketID, e.Actor, e.IP, e.Action, e.Input, e.Result, e.Detail)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.s.store.AddTicketEvent(ctx, e.TicketEvent); err != nil {
		log.Printf("ticket=%s audit write failed: %v", e.TicketID, err)
	}
}

// callbackKind describes a pasted URL without keeping its secrets.
func callbackKind(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "empty"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "unparsable"
	}
	q := u.Query()
	if u.Fragment != "" {
		if f, err := url.ParseQuery(u.Fragment); err == nil {
			for k, v := range f {
				if q.Get(k) == "" {
					q[k] = v
				}
			}
		}
	}
	switch {
	case q.Get("code") != "":
		return "code_url"
	case q.Get("error") != "":
		return "error_url"
	case q.Get("nonce") != "":
		return "step1_url"
	case q.Get("client_id") != "":
		return "authorize_page"
	case q.Get("qwSurface") != "":
		return "login_page"
	default:
		return "unknown"
	}
}

func (s *Server) handleTicketEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.TicketEvents(r.Context(), r.URL.Query().Get("ticket"), 500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error", "Could not load the log")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}
