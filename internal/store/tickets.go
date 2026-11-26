package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Ticket statuses. A ticket is open while pending or authorizing.
const (
	TicketPending     = "pending"
	TicketAuthorizing = "authorizing"
	TicketCompleted   = "completed"
	TicketExpired     = "expired"
)

// AuthTicket is a public authorization link. Whoever holds the token can sign
// one upstream account into this proxy without the administrator password;
// they cannot read any data.
type AuthTicket struct {
	ID              string `json:"id"`
	Token           string `json:"token"`
	Label           string `json:"label"`
	Provider        string `json:"provider"`
	Stage           string `json:"stage"`
	Region          string `json:"region"`
	ProxyID         string `json:"proxy_id"`
	Status          string `json:"status"`
	MaxActivations  int64  `json:"max_activations"`
	ActivationCount int64  `json:"activation_count"`
	AccountID       int64  `json:"account_id,omitempty"`
	AccountEmail    string `json:"account_email,omitempty"`
	CreatedAt       int64  `json:"created_at"`
	ExpiresAt       int64  `json:"expires_at"`
	CompletedAt     int64  `json:"completed_at,omitempty"`
}

// EffectiveStatus folds ticket expiry into the stored status.
func (t *AuthTicket) EffectiveStatus(now time.Time) string {
	if (t.Status == TicketPending || t.Status == TicketAuthorizing) && now.Unix() >= t.ExpiresAt {
		return TicketExpired
	}
	return t.Status
}

func (s *Store) migrateTickets() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS auth_tickets (
	id               TEXT PRIMARY KEY,
	token            TEXT NOT NULL UNIQUE,
	label            TEXT NOT NULL DEFAULT '',
	provider         TEXT NOT NULL DEFAULT 'social',
	stage            TEXT NOT NULL DEFAULT 'prod',
	region           TEXT NOT NULL DEFAULT '',
	proxy_id         TEXT NOT NULL DEFAULT '',
	status           TEXT NOT NULL DEFAULT 'pending',
	max_activations  INTEGER NOT NULL DEFAULT 20,
	activation_count INTEGER NOT NULL DEFAULT 0,
	account_id       INTEGER NOT NULL DEFAULT 0,
	account_email    TEXT NOT NULL DEFAULT '',
	created_at       INTEGER NOT NULL DEFAULT 0,
	expires_at       INTEGER NOT NULL DEFAULT 0,
	completed_at     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_auth_tickets_created ON auth_tickets(created_at);
`)
	return err
}

const ticketColumns = `id, token, label, provider, stage, region, proxy_id, status,
	max_activations, activation_count, account_id, account_email,
	created_at, expires_at, completed_at`

func scanTicket(row scanner) (*AuthTicket, error) {
	var t AuthTicket
	err := row.Scan(&t.ID, &t.Token, &t.Label, &t.Provider, &t.Stage, &t.Region, &t.ProxyID, &t.Status,
		&t.MaxActivations, &t.ActivationCount, &t.AccountID, &t.AccountEmail,
		&t.CreatedAt, &t.ExpiresAt, &t.CompletedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// CreateTickets inserts all tickets in one transaction.
func (s *Store) CreateTickets(ctx context.Context, tickets []AuthTicket) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range tickets {
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_tickets (`+ticketColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			t.ID, t.Token, t.Label, t.Provider, t.Stage, t.Region, t.ProxyID, t.Status,
			t.MaxActivations, t.ActivationCount, t.AccountID, t.AccountEmail,
			t.CreatedAt, t.ExpiresAt, t.CompletedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Tickets lists tickets newest first.
func (s *Store) Tickets(ctx context.Context) ([]AuthTicket, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ticketColumns+` FROM auth_tickets ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthTicket
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// TicketByToken returns nil, nil when the token is unknown.
func (s *Store) TicketByToken(ctx context.Context, token string) (*AuthTicket, error) {
	t, err := scanTicket(s.db.QueryRowContext(ctx, `SELECT `+ticketColumns+` FROM auth_tickets WHERE token=?`, token))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// TicketByID returns nil, nil when the id is unknown.
func (s *Store) TicketByID(ctx context.Context, id string) (*AuthTicket, error) {
	t, err := scanTicket(s.db.QueryRowContext(ctx, `SELECT `+ticketColumns+` FROM auth_tickets WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// CountOpenTickets counts tickets that can still be used.
func (s *Store) CountOpenTickets(ctx context.Context, now time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_tickets
		WHERE status IN ('pending', 'authorizing') AND expires_at > ?`, now.Unix()).Scan(&n)
	return n, err
}

// ActivateTicket marks an open ticket as authorizing and consumes one
// activation. It returns false when the ticket is closed, expired, or out of
// activations.
func (s *Store) ActivateTicket(ctx context.Context, id string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE auth_tickets
		SET status='authorizing', activation_count=activation_count+1
		WHERE id=? AND status IN ('pending', 'authorizing') AND expires_at > ? AND activation_count < max_activations`,
		id, now.Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ResetTicket returns an authorizing ticket to pending after its sign-in
// session ended without completing.
func (s *Store) ResetTicket(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE auth_tickets SET status='pending' WHERE id=? AND status='authorizing'`, id)
	return err
}

// CompleteTicket records the account the ticket produced.
func (s *Store) CompleteTicket(ctx context.Context, id string, accountID int64, email string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE auth_tickets
		SET status='completed', account_id=?, account_email=?, completed_at=?
		WHERE id=?`, accountID, truncate(email, 256), now.Unix(), id)
	return err
}

// DeleteTicket removes one ticket.
func (s *Store) DeleteTicket(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_tickets WHERE id=?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// PurgeClosedTickets removes completed and expired tickets.
func (s *Store) PurgeClosedTickets(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_tickets
		WHERE status NOT IN ('pending', 'authorizing') OR expires_at <= ?`, now.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
