// Package store is the embedded persistence layer: a single SQLite database
// (pure-Go driver, no CGO) replacing the v1 Postgres + Neo4j pair. It holds
// scans and their findings; graph/compliance tables are reserved for later phases.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/graph"
)

//go:embed schema.sql
var schemaSQL string

// Store wraps the SQLite database handle.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path and applies the schema.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite at %s: %w", path, err)
	}
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// CreateScan inserts a scan row and returns nothing; id is caller-supplied so it
// can be referenced before findings are written.
func (s *Store) CreateScan(ctx context.Context, id, provider, account, identity string, startedAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (id, provider, account, identity, started_at) VALUES (?, ?, ?, ?, ?)`,
		id, provider, account, identity, startedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("inserting scan: %w", err)
	}
	return nil
}

// CountFindings returns the number of findings stored for a scan.
func (s *Store) CountFindings(ctx context.Context, scanID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scanID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting findings: %w", err)
	}
	return n, nil
}

// ScanMeta is the metadata row for one scan, returned by the read queries that
// back the `findings`, `export`, and `paths` commands.
type ScanMeta struct {
	ID           string
	Provider     string
	Account      string
	Identity     string
	StartedAt    time.Time
	FinishedAt   time.Time
	FindingCount int
}

// FindingFilter narrows a LoadFindings query. Empty slices mean "no filter on
// this dimension"; all supplied dimensions are ANDed together.
type FindingFilter struct {
	Severities []findings.Severity
	Services   []string
	Statuses   []findings.Status
}

// LatestScanID returns the id of the most recently started scan, or an error
// wrapping sql.ErrNoRows if the database holds no scans yet.
func (s *Store) LatestScanID(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM scans ORDER BY started_at DESC, id DESC LIMIT 1`).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("finding latest scan: %w", err)
	}
	return id, nil
}

// GetScan returns the metadata for one scan.
func (s *Store) GetScan(ctx context.Context, id string) (ScanMeta, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, provider, account, identity, started_at, finished_at, finding_count
		 FROM scans WHERE id = ?`, id)
	return scanScan(row)
}

// ListScans returns scan metadata newest-first, capped at limit (0 = no cap).
func (s *Store) ListScans(ctx context.Context, limit int) ([]ScanMeta, error) {
	q := `SELECT id, provider, account, identity, started_at, finished_at, finding_count
	      FROM scans ORDER BY started_at DESC, id DESC`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing scans: %w", err)
	}
	defer rows.Close()

	var out []ScanMeta
	for rows.Next() {
		m, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanScan(r rowScanner) (ScanMeta, error) {
	var (
		m                   ScanMeta
		account, identity   sql.NullString
		startedAt, finished sql.NullString
	)
	if err := r.Scan(&m.ID, &m.Provider, &account, &identity, &startedAt, &finished, &m.FindingCount); err != nil {
		return ScanMeta{}, fmt.Errorf("scanning scan row: %w", err)
	}
	m.Account = account.String
	m.Identity = identity.String
	// started_at is NOT NULL and always written as RFC3339; a present-but-
	// unparseable value signals data corruption and must surface, not silently
	// become the zero time. A NULL finished_at (in-progress scan) stays zero.
	if startedAt.Valid {
		t, err := time.Parse(time.RFC3339, startedAt.String)
		if err != nil {
			return ScanMeta{}, fmt.Errorf("scan %s: parsing started_at %q: %w", m.ID, startedAt.String, err)
		}
		m.StartedAt = t
	}
	if finished.Valid {
		t, err := time.Parse(time.RFC3339, finished.String)
		if err != nil {
			return ScanMeta{}, fmt.Errorf("scan %s: parsing finished_at %q: %w", m.ID, finished.String, err)
		}
		m.FinishedAt = t
	}
	return m, nil
}

// LoadFindings returns the findings for a scan, reconstructed losslessly from
// the stored raw JSON and filtered/sorted for display (most-severe first).
func (s *Store) LoadFindings(ctx context.Context, scanID string, filter FindingFilter) ([]findings.Finding, error) {
	q := `SELECT raw FROM findings WHERE scan_id = ?`
	args := []any{scanID}

	if len(filter.Severities) > 0 {
		q += " AND severity IN (" + placeholders(len(filter.Severities)) + ")"
		for _, sev := range filter.Severities {
			args = append(args, string(sev))
		}
	}
	if len(filter.Services) > 0 {
		q += " AND service IN (" + placeholders(len(filter.Services)) + ")"
		for _, svc := range filter.Services {
			args = append(args, svc)
		}
	}
	if len(filter.Statuses) > 0 {
		q += " AND status IN (" + placeholders(len(filter.Statuses)) + ")"
		for _, st := range filter.Statuses {
			args = append(args, string(st))
		}
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("loading findings: %w", err)
	}
	defer rows.Close()

	var out []findings.Finding
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scanning finding row: %w", err)
		}
		var f findings.Finding
		if err := json.Unmarshal([]byte(raw), &f); err != nil {
			return nil, fmt.Errorf("unmarshaling finding: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	sortFindings(out)
	return out, nil
}

// placeholders returns "?,?,?" for n bind parameters.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, 2*n-1)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}

// sortFindings orders findings most-severe first, then by service and resource
// id, giving stable, readable output across CLI and exports.
func sortFindings(fs []findings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ar, br := a.Severity.Rank(), b.Severity.Rank(); ar != br {
			return ar > br
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return a.Resource.ID < b.Resource.ID
	})
}

// DistinctServices returns the distinct service values present in a scan's
// findings (sorted). It lets the CLI tell "this scan has no findings for the
// requested service" apart from "you filtered on a service this scan never
// produced" — a dangerous false negative for a security tool if conflated.
func (s *Store) DistinctServices(ctx context.Context, scanID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT service FROM findings WHERE scan_id = ? ORDER BY service`, scanID)
	if err != nil {
		return nil, fmt.Errorf("listing services: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var svc string
		if err := rows.Scan(&svc); err != nil {
			return nil, fmt.Errorf("scanning service row: %w", err)
		}
		out = append(out, svc)
	}
	return out, rows.Err()
}

// SaveGraph persists the attack-path graph for a scan: principal nodes, all
// edges, and scored paths. It runs in a single transaction and is idempotent
// per scan (it clears any prior graph rows for the scan first), so a re-scan
// writing to the same id replaces rather than duplicates.
func (s *Store) SaveGraph(ctx context.Context, scanID string, g *graph.Graph) error {
	if g == nil {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	for _, table := range []string{"principals", "edges", "attack_paths"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE scan_id = ?", scanID); err != nil {
			return fmt.Errorf("clearing %s: %w", table, err)
		}
	}

	for _, n := range g.Principals() {
		raw, err := json.Marshal(n)
		if err != nil {
			return fmt.Errorf("marshal principal %s: %w", n.ID, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO principals (scan_id, id, type, account, raw) VALUES (?,?,?,?,?)`,
			scanID, n.ID, n.Type, "", string(raw)); err != nil {
			return fmt.Errorf("insert principal %s: %w", n.ID, err)
		}
	}

	for _, e := range g.Edges {
		raw, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("marshal edge %s->%s: %w", e.Src, e.Dst, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO edges (scan_id, src, dst, kind, raw) VALUES (?,?,?,?,?)`,
			scanID, e.Src, e.Dst, string(e.Kind), string(raw)); err != nil {
			return fmt.Errorf("insert edge %s->%s: %w", e.Src, e.Dst, err)
		}
	}

	for _, p := range g.Paths {
		raw, err := json.Marshal(p)
		if err != nil {
			return fmt.Errorf("marshal path %s: %w", p.ID, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO attack_paths (scan_id, id, score, raw) VALUES (?,?,?,?)`,
			scanID, p.ID, p.Score, string(raw)); err != nil {
			return fmt.Errorf("insert path %s: %w", p.ID, err)
		}
	}

	return tx.Commit()
}

// LoadAttackPaths returns the scored attack paths for a scan, highest score
// first, reconstructed losslessly from the stored raw JSON.
func (s *Store) LoadAttackPaths(ctx context.Context, scanID string) ([]graph.Path, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT raw FROM attack_paths WHERE scan_id = ? ORDER BY score DESC, id ASC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("loading attack paths: %w", err)
	}
	defer rows.Close()

	var out []graph.Path
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scanning attack-path row: %w", err)
		}
		var p graph.Path
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, fmt.Errorf("unmarshaling attack path: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountAttackPaths returns how many attack paths are stored for a scan.
func (s *Store) CountAttackPaths(ctx context.Context, scanID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM attack_paths WHERE scan_id = ?`, scanID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting attack paths: %w", err)
	}
	return n, nil
}

// SaveFindings writes all findings for a scan in a single transaction and
// finalizes the scan row (finished_at + count).
func (s *Store) SaveFindings(ctx context.Context, scanID string, fs []findings.Finding, finishedAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO findings
		(id, scan_id, check_id, title, severity, status, provider, service,
		 account, region, resource_id, resource_type, description, remediation,
		 poc, reachable, raw, first_seen, last_seen)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, f := range fs {
		raw, err := json.Marshal(f)
		if err != nil {
			return fmt.Errorf("marshal finding %s: %w", f.ID, err)
		}
		if _, err := stmt.ExecContext(ctx,
			f.ID, scanID, f.CheckID, f.Title, string(f.Severity), string(f.Status),
			f.Provider, f.Service, f.Resource.Account, f.Resource.Region,
			f.Resource.ID, f.Resource.Type, f.Description, f.Remediation,
			f.PoC, string(f.Reachable), string(raw),
			f.FirstSeen.UTC().Format(time.RFC3339), f.LastSeen.UTC().Format(time.RFC3339),
		); err != nil {
			return fmt.Errorf("insert finding %s: %w", f.ID, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE scans SET finished_at = ?, finding_count = ? WHERE id = ?`,
		finishedAt.UTC().Format(time.RFC3339), len(fs), scanID); err != nil {
		return fmt.Errorf("finalize scan: %w", err)
	}
	return tx.Commit()
}
