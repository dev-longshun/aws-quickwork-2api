package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"quickwork-openai/internal/outbound"
)

var ErrProxyInUse = errors.New("proxy is bound to an account")

func (s *Store) ImportProxies(ctx context.Context, text string) (int64, error) {
	return s.ImportProxiesWithDefault(ctx, text, "http")
}

func (s *Store) ImportProxiesWithDefault(ctx context.Context, text, defaultScheme string) (int64, error) {
	proxies, err := outbound.ParseListWithDefault(text, defaultScheme)
	if err != nil {
		return 0, err
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer transaction.Rollback()
	// Unnamed proxies get kiro-rs style names: Proxy-<next number>.
	next := 1
	rows, err := transaction.QueryContext(ctx, `SELECT label FROM proxies WHERE label LIKE 'Proxy-%'`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var label string
		if err := rows.Scan(&label); err != nil {
			rows.Close()
			return 0, err
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(label, "Proxy-")); err == nil && n >= next {
			next = n + 1
		}
	}
	rows.Close()
	var imported int64
	for _, proxy := range proxies {
		label := proxy.Label
		if parsed, err := url.Parse(proxy.URL); err == nil && label == parsed.Scheme+"://"+parsed.Host {
			label = "Proxy-" + strconv.Itoa(next)
		}
		result, err := transaction.ExecContext(ctx, `INSERT INTO proxies (id, url, label, created_at) VALUES (?,?,?,?) ON CONFLICT(id) DO NOTHING`, proxy.ID, proxy.URL, label, time.Now().Unix())
		if err != nil {
			return 0, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if count > 0 && label != proxy.Label {
			next++
		}
		imported += count
	}
	return imported, transaction.Commit()
}

func (s *Store) Proxies(ctx context.Context) ([]outbound.Proxy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, label FROM proxies ORDER BY created_at, rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	proxies := make([]outbound.Proxy, 0)
	for rows.Next() {
		var proxy outbound.Proxy
		if err := rows.Scan(&proxy.ID, &proxy.Label); err != nil {
			return nil, err
		}
		proxies = append(proxies, proxy)
	}
	return proxies, rows.Err()
}

// ProxyInfo is a stored proxy as the console lists it: never with credentials.
type ProxyInfo struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Address string `json:"address"`
	Auth    bool   `json:"auth"`
	Bound   int64  `json:"bound_accounts"`
}

// ProxyInfos lists proxies with their credential-free address and the number
// of accounts bound to each.
func (s *Store) ProxyInfos(ctx context.Context) ([]ProxyInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id, p.label, p.url,
		(SELECT COUNT(*) FROM accounts a WHERE a.proxy_id = p.id)
		FROM proxies p ORDER BY p.created_at, p.rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ProxyInfo, 0)
	for rows.Next() {
		var info ProxyInfo
		var raw string
		if err := rows.Scan(&info.ID, &info.Label, &raw, &info.Bound); err != nil {
			return nil, err
		}
		if parsed, err := url.Parse(raw); err == nil {
			info.Address = parsed.Scheme + "://" + parsed.Host
			info.Auth = parsed.User != nil
		}
		out = append(out, info)
	}
	return out, rows.Err()
}

// RenameProxy changes a proxy's display label.
func (s *Store) RenameProxy(ctx context.Context, id, label string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE proxies SET label=? WHERE id=?`, label, id)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

func (s *Store) ProxyURL(ctx context.Context, id string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT url FROM proxies WHERE id=?`, id).Scan(&value)
	return value, err
}

func (s *Store) DeleteProxy(ctx context.Context, id string) (bool, error) {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer transaction.Rollback()
	var bound int
	if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts WHERE proxy_id=?`, id).Scan(&bound); err != nil {
		return false, err
	}
	if bound > 0 {
		return false, ErrProxyInUse
	}
	result, err := transaction.ExecContext(ctx, `DELETE FROM proxies WHERE id=?`, id)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return count > 0, transaction.Commit()
}

func (s *Store) SetProxy(ctx context.Context, id int64, proxyID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE accounts SET proxy_id=?, updated_at=? WHERE id=? AND (? IN ('', 'direct') OR EXISTS (SELECT 1 FROM proxies WHERE id=?))`, proxyID, time.Now().Unix(), id, proxyID, proxyID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}
