package store

import (
	"database/sql"
	"errors"
	"strings"
)

// Vulnerability data (OSV advisories) and the findings matched against reported components.
// Matching logic lives in package vuln; this file only persists and queries.

const vulnSchema = `
CREATE TABLE IF NOT EXISTS vuln (
  id        TEXT PRIMARY KEY,
  aliases   TEXT NOT NULL DEFAULT '',
  summary   TEXT NOT NULL DEFAULT '',
  details   TEXT NOT NULL DEFAULT '',
  severity  TEXT NOT NULL DEFAULT 'unknown',
  score     REAL NOT NULL DEFAULT -1,
  published INTEGER NOT NULL DEFAULT 0,
  modified  INTEGER NOT NULL DEFAULT 0,
  refs      TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS vuln_affected (
  vuln_id  TEXT NOT NULL,
  package  TEXT NOT NULL,
  ranges   TEXT NOT NULL DEFAULT '[]',
  versions TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_vuln_affected_pkg ON vuln_affected(package);
CREATE INDEX IF NOT EXISTS idx_vuln_affected_id ON vuln_affected(vuln_id);
CREATE TABLE IF NOT EXISTS component_vuln (
  group_id   TEXT NOT NULL,
  artifact   TEXT NOT NULL,
  version    TEXT NOT NULL,
  vuln_id    TEXT NOT NULL,
  fixed      TEXT NOT NULL DEFAULT '',
  first_seen INTEGER NOT NULL,
  PRIMARY KEY (group_id, artifact, version, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_component_vuln_id ON component_vuln(vuln_id);
`

// severityRank is the SQL expression used to sort by severity (higher = worse).
const severityRank = `CASE v.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'none' THEN 1 ELSE 0 END`

type VulnRow struct {
	ID        string         `json:"id"`
	Aliases   string         `json:"aliases"` // comma separated (CVE ids)
	Summary   string         `json:"summary"`
	Details   string         `json:"details,omitempty"`
	Severity  string         `json:"severity"`
	Score     float64        `json:"score"` // CVSS v3 base score, -1 if unknown
	Published int64          `json:"published"`
	Modified  int64          `json:"modified"`
	Refs      string         `json:"refs"` // newline separated URLs
	Withdrawn bool           `json:"-"`
	Affected  []*AffectedRow `json:"affected,omitempty"`
}

type AffectedRow struct {
	VulnID   string `json:"-"`
	Package  string `json:"package"`
	Ranges   string `json:"ranges"`   // OSV ranges JSON
	Versions string `json:"versions"` // OSV versions JSON
}

type VulnImportCounts struct {
	Inserted  int `json:"inserted"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
	Withdrawn int `json:"withdrawn"`
}

// UpsertVulns stores a batch of advisories in one transaction. Records whose modified time is not newer
// than the stored one are left alone; withdrawn advisories are removed together with their findings.
func (s *Store) UpsertVulns(rows []*VulnRow) (VulnImportCounts, error) {
	var c VulnImportCounts
	tx, err := s.db.Begin()
	if err != nil {
		return c, err
	}
	defer tx.Rollback()
	for _, r := range rows {
		var modified int64
		err := tx.QueryRow(`SELECT modified FROM vuln WHERE id = ?`, r.ID).Scan(&modified)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return c, err
		}
		if r.Withdrawn {
			if exists {
				for _, q := range []string{`DELETE FROM vuln WHERE id = ?`, `DELETE FROM vuln_affected WHERE vuln_id = ?`, `DELETE FROM component_vuln WHERE vuln_id = ?`} {
					if _, err := tx.Exec(q, r.ID); err != nil {
						return c, err
					}
				}
			}
			c.Withdrawn++
			continue
		}
		if exists && r.Modified != 0 && modified >= r.Modified {
			c.Unchanged++
			continue
		}
		if _, err := tx.Exec(`INSERT INTO vuln(id, aliases, summary, details, severity, score, published, modified, refs) VALUES(?,?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET aliases=excluded.aliases, summary=excluded.summary, details=excluded.details,
			severity=excluded.severity, score=excluded.score, published=excluded.published, modified=excluded.modified, refs=excluded.refs`,
			r.ID, r.Aliases, r.Summary, r.Details, r.Severity, r.Score, r.Published, r.Modified, r.Refs); err != nil {
			return c, err
		}
		if _, err := tx.Exec(`DELETE FROM vuln_affected WHERE vuln_id = ?`, r.ID); err != nil {
			return c, err
		}
		for _, a := range r.Affected {
			if _, err := tx.Exec(`INSERT INTO vuln_affected(vuln_id, package, ranges, versions) VALUES(?,?,?,?)`, r.ID, a.Package, a.Ranges, a.Versions); err != nil {
				return c, err
			}
		}
		if exists {
			c.Updated++
		} else {
			c.Inserted++
		}
	}
	return c, tx.Commit()
}

// AffectedByPackages loads the affected entries for a set of "group:artifact" packages.
func (s *Store) AffectedByPackages(pkgs []string) (map[string][]*AffectedRow, error) {
	out := map[string][]*AffectedRow{}
	for start := 0; start < len(pkgs); start += 500 { // stay below SQLite's bound-parameter limit
		end := min(start+500, len(pkgs))
		args := make([]any, 0, end-start)
		for _, p := range pkgs[start:end] {
			args = append(args, p)
		}
		rows, err := s.db.Query(`SELECT vuln_id, package, ranges, versions FROM vuln_affected WHERE package IN (?`+strings.Repeat(",?", len(args)-1)+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			a := &AffectedRow{}
			if err := rows.Scan(&a.VulnID, &a.Package, &a.Ranges, &a.Versions); err != nil {
				rows.Close()
				return nil, err
			}
			out[a.Package] = append(out[a.Package], a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GAV is one distinct group:artifact:version currently reported by any agent.
type GAV struct{ Group, Artifact, Version string }

// DistinctComponents lists matchable components (group and version known).
func (s *Store) DistinctComponents() ([]GAV, error) {
	rows, err := s.db.Query(`SELECT DISTINCT group_id, artifact, version FROM component WHERE group_id <> '' AND version <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GAV
	for rows.Next() {
		var g GAV
		if err := rows.Scan(&g.Group, &g.Artifact, &g.Version); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Finding is one component version affected by one advisory.
type Finding struct {
	Group    string `json:"group"`
	Artifact string `json:"artifact"`
	Version  string `json:"version"`
	VulnID   string `json:"vuln_id"`
	Fixed    string `json:"fixed"` // comma separated fixed versions
}

func (f Finding) key() string {
	return f.Group + "\x00" + f.Artifact + "\x00" + f.Version + "\x00" + f.VulnID
}

// SyncFindings makes component_vuln equal to found, keeping first_seen for findings that persist.
// It returns the findings that did not exist before.
func (s *Store) SyncFindings(found []Finding) ([]Finding, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	existing := map[string]bool{}
	rows, err := tx.Query(`SELECT group_id, artifact, version, vuln_id FROM component_vuln`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.Group, &f.Artifact, &f.Version, &f.VulnID); err != nil {
			rows.Close()
			return nil, err
		}
		existing[f.key()] = true
	}
	rows.Close()
	wanted := map[string]bool{}
	var fresh []Finding
	ts := now()
	for _, f := range found {
		k := f.key()
		if wanted[k] {
			continue
		}
		wanted[k] = true
		if existing[k] {
			if _, err := tx.Exec(`UPDATE component_vuln SET fixed = ? WHERE group_id = ? AND artifact = ? AND version = ? AND vuln_id = ?`,
				f.Fixed, f.Group, f.Artifact, f.Version, f.VulnID); err != nil {
				return nil, err
			}
			continue
		}
		if _, err := tx.Exec(`INSERT INTO component_vuln(group_id, artifact, version, vuln_id, fixed, first_seen) VALUES(?,?,?,?,?,?)`,
			f.Group, f.Artifact, f.Version, f.VulnID, f.Fixed, ts); err != nil {
			return nil, err
		}
		fresh = append(fresh, f)
	}
	for k := range existing {
		if !wanted[k] {
			p := strings.Split(k, "\x00")
			if _, err := tx.Exec(`DELETE FROM component_vuln WHERE group_id = ? AND artifact = ? AND version = ? AND vuln_id = ?`, p[0], p[1], p[2], p[3]); err != nil {
				return nil, err
			}
		}
	}
	return fresh, tx.Commit()
}

// FindingRow is a finding joined with its advisory and where the component is deployed.
type FindingRow struct {
	Group     string  `json:"group"`
	Artifact  string  `json:"artifact"`
	Version   string  `json:"version"`
	VulnID    string  `json:"vuln_id"`
	Aliases   string  `json:"aliases"`
	Summary   string  `json:"summary"`
	Severity  string  `json:"severity"`
	Score     float64 `json:"score"`
	Fixed     string  `json:"fixed"`
	FirstSeen int64   `json:"first_seen"`
	Apps      string  `json:"apps"`
	Instances int64   `json:"instances"`
}

type FindingQuery struct {
	AppID    int64
	Severity string // minimum level: critical, high, medium, low
	Keyword  string // matches component, advisory id, CVE alias or summary
	VulnID   string // exact advisory id
	Limit    int
}

var minRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2}

// QueryFindings lists findings for components that are currently deployed, most severe first.
func (s *Store) QueryFindings(q FindingQuery) ([]*FindingRow, error) {
	where := []string{"1=1"}
	var args []any
	if q.AppID > 0 {
		where, args = append(where, "c.app_id = ?"), append(args, q.AppID)
	}
	if r, ok := minRank[q.Severity]; ok {
		where, args = append(where, severityRank+" >= ?"), append(args, r)
	}
	if q.VulnID != "" {
		where, args = append(where, "v.id = ?"), append(args, q.VulnID)
	}
	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		like := "%" + kw + "%"
		where = append(where, "(cv.artifact LIKE ? OR cv.group_id LIKE ? OR v.id LIKE ? OR v.aliases LIKE ? OR v.summary LIKE ?)")
		args = append(args, like, like, like, like, like)
	}
	if q.Limit <= 0 || q.Limit > 5000 {
		q.Limit = 1000
	}
	rows, err := s.db.Query(`SELECT cv.group_id, cv.artifact, cv.version, v.id, v.aliases, v.summary, v.severity, v.score, cv.fixed, cv.first_seen,
		GROUP_CONCAT(DISTINCT a.name || '/' || a.env), COUNT(DISTINCT c.agent_id)
		FROM component_vuln cv
		JOIN vuln v ON v.id = cv.vuln_id
		JOIN component c ON c.group_id = cv.group_id AND c.artifact = cv.artifact AND c.version = cv.version
		JOIN app a ON a.id = c.app_id
		WHERE `+strings.Join(where, " AND ")+`
		GROUP BY cv.group_id, cv.artifact, cv.version, v.id
		ORDER BY `+severityRank+` DESC, v.score DESC, cv.artifact, cv.version LIMIT ?`, append(args, q.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FindingRow
	for rows.Next() {
		f := &FindingRow{}
		if err := rows.Scan(&f.Group, &f.Artifact, &f.Version, &f.VulnID, &f.Aliases, &f.Summary, &f.Severity, &f.Score, &f.Fixed, &f.FirstSeen, &f.Apps, &f.Instances); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

type VulnSummary struct {
	Advisories         int64            `json:"advisories"`
	Packages           int64            `json:"packages"`
	Findings           int64            `json:"findings"`
	BySeverity         map[string]int64 `json:"by_severity"`
	AffectedComponents int64            `json:"affected_components"`
	AffectedApps       int64            `json:"affected_apps"`
	Unmatchable        int64            `json:"unmatchable_components"` // no group/version: cannot be matched
}

// SummarizeVulns counts advisories in the database and findings on deployed components.
func (s *Store) SummarizeVulns(appID int64) (*VulnSummary, error) {
	sum := &VulnSummary{BySeverity: map[string]int64{}}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM vuln`).Scan(&sum.Advisories); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(DISTINCT package) FROM vuln_affected`).Scan(&sum.Packages); err != nil {
		return nil, err
	}
	appFilter, args := "", []any{}
	if appID > 0 {
		appFilter, args = " AND c.app_id = ?", []any{appID}
	}
	rows, err := s.db.Query(`SELECT v.severity, COUNT(*) FROM (
		SELECT DISTINCT cv.group_id, cv.artifact, cv.version, cv.vuln_id FROM component_vuln cv
		JOIN component c ON c.group_id = cv.group_id AND c.artifact = cv.artifact AND c.version = cv.version WHERE 1=1`+appFilter+`
		) f JOIN vuln v ON v.id = f.vuln_id GROUP BY v.severity`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var level string
		var n int64
		if err := rows.Scan(&level, &n); err != nil {
			rows.Close()
			return nil, err
		}
		sum.BySeverity[level] = n
		sum.Findings += n
	}
	rows.Close()
	if err := s.db.QueryRow(`SELECT COUNT(DISTINCT cv.group_id || ':' || cv.artifact || ':' || cv.version), COUNT(DISTINCT c.app_id)
		FROM component_vuln cv JOIN component c ON c.group_id = cv.group_id AND c.artifact = cv.artifact AND c.version = cv.version WHERE 1=1`+appFilter, args...).
		Scan(&sum.AffectedComponents, &sum.AffectedApps); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(DISTINCT c.artifact || ':' || c.version) FROM component c WHERE (c.group_id = '' OR c.version = '')`+appFilter, args...).
		Scan(&sum.Unmatchable); err != nil {
		return nil, err
	}
	return sum, nil
}

// GetVuln returns one advisory with its affected packages.
func (s *Store) GetVuln(id string) (*VulnRow, error) {
	v := &VulnRow{}
	err := s.db.QueryRow(`SELECT id, aliases, summary, details, severity, score, published, modified, refs FROM vuln WHERE id = ?`, id).
		Scan(&v.ID, &v.Aliases, &v.Summary, &v.Details, &v.Severity, &v.Score, &v.Published, &v.Modified, &v.Refs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT package, ranges, versions FROM vuln_affected WHERE vuln_id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		a := &AffectedRow{VulnID: id}
		if err := rows.Scan(&a.Package, &a.Ranges, &a.Versions); err != nil {
			return nil, err
		}
		v.Affected = append(v.Affected, a)
	}
	return v, rows.Err()
}
