package store

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"regexp"
	"strconv"
	"strings"
)

// Incidents group repeated alarms of the same attack against the same endpoint (docs 6.5.3), so analysts
// triage one record instead of thousands. Grouping key (fingerprint): app + attack type + detector +
// normalised request path (query dropped; numeric, UUID and long hex/token segments replaced).

const incidentSchema = `
CREATE TABLE IF NOT EXISTS incident (
  fingerprint   TEXT PRIMARY KEY,
  app_id        INTEGER NOT NULL,
  attack_type   TEXT NOT NULL,
  algorithm     TEXT NOT NULL DEFAULT '',
  path_pattern  TEXT NOT NULL,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  count         INTEGER NOT NULL,
  blocked       INTEGER NOT NULL DEFAULT 0,
  last_event_id TEXT NOT NULL DEFAULT '',
  last_ip       TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'new',
  reopened      INTEGER NOT NULL DEFAULT 0,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_last ON incident(last_seen);
CREATE INDEX IF NOT EXISTS idx_incident_app ON incident(app_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_incident_status ON incident(status, last_seen);
`

var (
	reUUID  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHex   = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	reToken = regexp.MustCompile(`^[A-Za-z0-9_\-=.]{24,}$`)
	reNum   = regexp.MustCompile(`^[0-9]+$`)
)

// PathPattern reduces a request URL to its endpoint: /api/item/7?x=1 -> /api/item/{n}.
func PathPattern(url string) string {
	if url == "" {
		return "(no request)" // operation outside an HTTP request (startup, scheduled task)
	}
	p := url
	if i := strings.Index(p, "://"); i >= 0 {
		if j := strings.Index(p[i+3:], "/"); j >= 0 {
			p = p[i+3+j:]
		} else {
			p = "/"
		}
	}
	if i := strings.IndexAny(p, "?#;"); i >= 0 {
		p = p[:i]
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case s == "":
		case reNum.MatchString(s):
			segs[i] = "{n}"
		case reUUID.MatchString(s):
			segs[i] = "{uuid}"
		case reHex.MatchString(s):
			segs[i] = "{hex}"
		case reToken.MatchString(s) && strings.IndexFunc(s, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0:
			segs[i] = "{token}"
		}
	}
	p = strings.Join(segs, "/")
	if len(p) > 512 {
		p = p[:512]
	}
	if p == "" {
		p = "/"
	}
	return p
}

// Fingerprint is the incident key of an alarm.
func Fingerprint(appID int64, attackType, algorithm, url string) (string, string) {
	pattern := PathPattern(url)
	sum := sha1.Sum([]byte(strconv.FormatInt(appID, 10) + "\x00" + attackType + "\x00" + algorithm + "\x00" + pattern))
	return hex.EncodeToString(sum[:8]), pattern
}

type incidentDelta struct {
	appID                   int64
	typ, algorithm, pattern string
	first, last             int64
	count, blocked          int64
	lastEvent, lastIP       string
}

func (d *incidentDelta) add(a *Alarm) {
	if d.count == 0 || a.EventTime < d.first {
		d.first = a.EventTime
	}
	if d.count == 0 || a.EventTime >= d.last {
		d.last, d.lastEvent, d.lastIP = a.EventTime, a.EventID, a.ClientIP
	}
	d.count++
	if a.Action == "block" {
		d.blocked++
	}
}

// upsertIncidents applies per-batch deltas. An incident marked "fixed" reopens when the attack recurs;
// "false_positive" and "ignored" stay as decided.
func upsertIncidents(tx *sql.Tx, deltas map[string]*incidentDelta) error {
	ts := now()
	for fp, d := range deltas {
		if _, err := tx.Exec(`INSERT INTO incident(fingerprint, app_id, attack_type, algorithm, path_pattern, first_seen, last_seen, count, blocked, last_event_id, last_ip, status, updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,'new',?)
			ON CONFLICT(fingerprint) DO UPDATE SET
			  count = count + excluded.count,
			  blocked = blocked + excluded.blocked,
			  first_seen = MIN(first_seen, excluded.first_seen),
			  last_event_id = CASE WHEN excluded.last_seen >= last_seen THEN excluded.last_event_id ELSE last_event_id END,
			  last_ip = CASE WHEN excluded.last_seen >= last_seen THEN excluded.last_ip ELSE last_ip END,
			  last_seen = MAX(last_seen, excluded.last_seen),
			  reopened = CASE WHEN status = 'fixed' THEN reopened + 1 ELSE reopened END,
			  status = CASE WHEN status = 'fixed' THEN 'new' ELSE status END,
			  updated_at = excluded.updated_at`,
			fp, d.appID, d.typ, d.algorithm, d.pattern, d.first, d.last, d.count, d.blocked, d.lastEvent, d.lastIP, ts); err != nil {
			return err
		}
	}
	return nil
}

// ensureAlarmFingerprintColumn adds alarm.fingerprint to databases created before incidents existed.
func (s *Store) ensureAlarmFingerprintColumn() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('alarm') WHERE name = 'fingerprint'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := s.db.Exec(`ALTER TABLE alarm ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_alarm_fp ON alarm(fingerprint, event_time)`)
	return err
}

// BackfillIncidents assigns fingerprints to alarms stored before incidents existed, in small transactions
// so ingestion continues meanwhile. Safe to run repeatedly; returns the number of alarms processed.
func (s *Store) BackfillIncidents(batch int) (int, error) {
	if s.GetSetting("incident_backfill_v1", "") == "done" {
		return 0, nil
	}
	total := 0
	for {
		rows, err := s.db.Query(`SELECT rowid, event_id, app_id, attack_type, algorithm, action, url, client_ip, event_time
			FROM alarm WHERE fingerprint = '' LIMIT ?`, batch)
		if err != nil {
			return total, err
		}
		type item struct {
			rowid int64
			a     Alarm
		}
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.rowid, &it.a.EventID, &it.a.AppID, &it.a.AttackType, &it.a.Algorithm, &it.a.Action, &it.a.URL, &it.a.ClientIP, &it.a.EventTime); err != nil {
				rows.Close()
				return total, err
			}
			items = append(items, it)
		}
		rows.Close()
		if len(items) == 0 {
			break
		}
		tx, err := s.db.Begin()
		if err != nil {
			return total, err
		}
		deltas := map[string]*incidentDelta{}
		for i := range items {
			a := &items[i].a
			fp, pattern := Fingerprint(a.AppID, a.AttackType, a.Algorithm, a.URL)
			if _, err := tx.Exec(`UPDATE alarm SET fingerprint = ? WHERE rowid = ?`, fp, items[i].rowid); err != nil {
				tx.Rollback()
				return total, err
			}
			d := deltas[fp]
			if d == nil {
				d = &incidentDelta{appID: a.AppID, typ: a.AttackType, algorithm: a.Algorithm, pattern: pattern}
				deltas[fp] = d
			}
			d.add(a)
		}
		if err := upsertIncidents(tx, deltas); err != nil {
			tx.Rollback()
			return total, err
		}
		if err := tx.Commit(); err != nil {
			return total, err
		}
		total += len(items)
		if total%100_000 < batch {
			log.Printf("incident backfill: %d alarms grouped so far", total)
		}
	}
	return total, s.SetSetting("incident_backfill_v1", "done")
}

// ------------------------------------------------------------------ queries

type Incident struct {
	Fingerprint string `json:"fingerprint"`
	AppID       int64  `json:"app_id"`
	AppName     string `json:"app_name"`
	AttackType  string `json:"attack_type"`
	Algorithm   string `json:"algorithm"`
	PathPattern string `json:"path_pattern"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
	Count       int64  `json:"count"`
	Blocked     int64  `json:"blocked"`
	LastEventID string `json:"last_event_id"`
	LastIP      string `json:"last_ip"`
	Status      string `json:"status"`
	Reopened    int64  `json:"reopened"`
	UpdatedAt   int64  `json:"updated_at"`
}

type IncidentQuery struct {
	AppID      int64
	AttackType string
	Status     string
	Blocked    bool  // only incidents with at least one blocked alarm
	Since      int64 // last_seen >= since
	Keyword    string
	Page       int
	PageSize   int
}

const incidentCols = `i.fingerprint, i.app_id, COALESCE(a.name,''), i.attack_type, i.algorithm, i.path_pattern, i.first_seen, i.last_seen,
	i.count, i.blocked, i.last_event_id, i.last_ip, i.status, i.reopened, i.updated_at`

func scanIncident(r interface{ Scan(...any) error }) (*Incident, error) {
	in := &Incident{}
	err := r.Scan(&in.Fingerprint, &in.AppID, &in.AppName, &in.AttackType, &in.Algorithm, &in.PathPattern, &in.FirstSeen, &in.LastSeen,
		&in.Count, &in.Blocked, &in.LastEventID, &in.LastIP, &in.Status, &in.Reopened, &in.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return in, err
}

// QueryIncidents lists incidents, most recently active first.
func (s *Store) QueryIncidents(q IncidentQuery) ([]*Incident, int, error) {
	where, args := []string{"1=1"}, []any{}
	if q.AppID > 0 {
		where, args = append(where, "i.app_id = ?"), append(args, q.AppID)
	}
	if q.AttackType != "" {
		where, args = append(where, "i.attack_type = ?"), append(args, q.AttackType)
	}
	if q.Status != "" {
		where, args = append(where, "i.status = ?"), append(args, q.Status)
	}
	if q.Blocked {
		where = append(where, "i.blocked > 0")
	}
	if q.Since > 0 {
		where, args = append(where, "i.last_seen >= ?"), append(args, q.Since)
	}
	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		where, args = append(where, "(i.path_pattern LIKE ? OR i.last_ip LIKE ? OR i.algorithm LIKE ?)"), append(args, "%"+kw+"%", "%"+kw+"%", "%"+kw+"%")
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM incident i WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if q.PageSize <= 0 || q.PageSize > 200 {
		q.PageSize = 20
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	rows, err := s.db.Query(`SELECT `+incidentCols+` FROM incident i LEFT JOIN app a ON a.id = i.app_id WHERE `+cond+`
		ORDER BY i.last_seen DESC LIMIT ? OFFSET ?`, append(args, q.PageSize, (q.Page-1)*q.PageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*Incident{}
	for rows.Next() {
		in, err := scanIncident(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, in)
	}
	return out, total, rows.Err()
}

func (s *Store) GetIncident(fp string) (*Incident, error) {
	return scanIncident(s.db.QueryRow(`SELECT `+incidentCols+` FROM incident i LEFT JOIN app a ON a.id = i.app_id WHERE i.fingerprint = ?`, fp))
}

// IncidentSources returns the most frequent client IPs of an incident.
func (s *Store) IncidentSources(fp string, limit int) ([]Count, error) {
	rows, err := s.db.Query(`SELECT client_ip, COUNT(*) FROM alarm WHERE fingerprint = ? GROUP BY client_ip ORDER BY COUNT(*) DESC LIMIT ?`, fp, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetIncidentStatus triages an incident; with cascade, its alarms still in "new" get the same status.
// Returns the number of alarms updated.
func (s *Store) SetIncidentStatus(fp, status string, cascade bool) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE incident SET status = ?, updated_at = ? WHERE fingerprint = ?`, status, now(), fp)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotFound
	}
	var changed int64
	if cascade {
		res, err := tx.Exec(`UPDATE alarm SET status = ? WHERE fingerprint = ? AND status = 'new'`, status, fp)
		if err != nil {
			return 0, err
		}
		changed, _ = res.RowsAffected()
	}
	return changed, tx.Commit()
}

// purgeIncidents removes incidents without activity since cutoff (called with alarm retention).
func (s *Store) purgeIncidents(cutoff int64) error {
	_, err := s.db.Exec(`DELETE FROM incident WHERE last_seen < ?`, cutoff)
	return err
}
