// Package vuln matches the components agents report (group:artifact:version) against vulnerability
// advisories in the OSV format (https://ossf.github.io/osv-schema/), e.g. the offline export
// https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip (GitHub Advisory Database, etc.).
package vuln

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Advisory is the subset of an OSV record the platform uses.
type Advisory struct {
	ID               string         `json:"id"`
	Modified         string         `json:"modified"`
	Published        string         `json:"published"`
	Withdrawn        string         `json:"withdrawn"`
	Aliases          []string       `json:"aliases"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Severity         []osvSeverity  `json:"severity"`
	Affected         []osvAffected  `json:"affected"`
	References       []osvReference `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges           []Range  `json:"ranges"`
	Versions         []string `json:"versions"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// Range is one OSV affected range; only ECOSYSTEM and SEMVER ranges are evaluated (GIT ranges need commits).
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Affected is what is stored per (advisory, Maven package).
type Affected struct {
	VulnID   string
	Package  string // "group:artifact"
	Ranges   []Range
	Versions []string
}

// ParseAdvisory decodes one OSV JSON document.
func ParseAdvisory(data []byte) (*Advisory, error) {
	var a Advisory
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	if a.ID == "" {
		return nil, fmt.Errorf("missing id")
	}
	return &a, nil
}

// MavenAffected returns the advisory's affected entries for the Maven ecosystem.
func (a *Advisory) MavenAffected() []Affected {
	var out []Affected
	for _, af := range a.Affected {
		if !strings.EqualFold(af.Package.Ecosystem, "Maven") || !strings.Contains(af.Package.Name, ":") {
			continue
		}
		out = append(out, Affected{VulnID: a.ID, Package: strings.TrimSpace(af.Package.Name), Ranges: af.Ranges, Versions: af.Versions})
	}
	return out
}

// Rating returns the severity level (critical/high/medium/low/none/unknown) and CVSS v3 base score.
// Database-provided ratings (GHSA) win; otherwise the CVSS v3 vector is scored.
func (a *Advisory) Rating() (string, float64) {
	score := -1.0
	for _, s := range a.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V3") {
			if v, err := CVSS3Score(s.Score); err == nil {
				score = v
				break
			}
		}
	}
	level := normalizeLevel(a.DatabaseSpecific.Severity)
	if level == "" {
		for _, af := range a.Affected {
			if level = normalizeLevel(af.DatabaseSpecific.Severity); level != "" {
				break
			}
		}
	}
	if level == "" && score >= 0 {
		level = LevelFromScore(score)
	}
	if level == "" {
		level = "unknown"
	}
	return level, score
}

func normalizeLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	}
	return ""
}

// LevelRank orders severity levels for sorting (higher = more severe).
func LevelRank(level string) int {
	switch level {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "none":
		return 1
	}
	return 0
}

// ParseTime parses OSV RFC 3339 timestamps into Unix milliseconds (0 when absent/invalid).
func ParseTime(s string) int64 {
	if s == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0
	}
	return t.UnixMilli()
}

// Matches reports whether version is affected, and the fixed versions of the ranges that matched.
// Range semantics follow the OSV spec: events are applied in version order, "introduced" opens an affected
// interval, "fixed" closes it (exclusive) and "last_affected" closes it after that version (inclusive).
func (af *Affected) Matches(version string) (bool, []string) {
	version = strings.TrimSpace(version)
	if version == "" {
		return false, nil
	}
	for _, v := range af.Versions {
		if CompareMaven(v, version) == 0 {
			return true, af.fixedVersions()
		}
	}
	for _, r := range af.Ranges {
		if r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
			continue
		}
		if rangeAffects(r.Events, version) {
			var fixed []string
			for _, e := range r.Events {
				if e.Fixed != "" && CompareMaven(e.Fixed, version) > 0 {
					fixed = append(fixed, e.Fixed)
				}
			}
			sort.Slice(fixed, func(i, j int) bool { return CompareMaven(fixed[i], fixed[j]) < 0 })
			return true, fixed
		}
	}
	return false, nil
}

func (af *Affected) fixedVersions() []string {
	var out []string
	for _, r := range af.Ranges {
		for _, e := range r.Events {
			if e.Fixed != "" {
				out = append(out, e.Fixed)
			}
		}
	}
	return out
}

func eventVersion(e Event) string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.LastAffected != "":
		return e.LastAffected
	}
	return e.Limit
}

func rangeAffects(events []Event, version string) bool {
	evs := make([]Event, 0, len(events))
	for _, e := range events {
		if e.Limit == "" { // "limit" only bounds git commit walks
			evs = append(evs, e)
		}
	}
	sort.SliceStable(evs, func(i, j int) bool {
		a, b := eventVersion(evs[i]), eventVersion(evs[j])
		if a == "0" || b == "0" { // introduced "0" means "from the very beginning"
			return a == "0" && b != "0"
		}
		return CompareMaven(a, b) < 0
	})
	affected := false
	for _, e := range evs {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || CompareMaven(version, e.Introduced) >= 0 {
				affected = true
			}
		case e.Fixed != "":
			if CompareMaven(version, e.Fixed) >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			if CompareMaven(version, e.LastAffected) > 0 {
				affected = false
			}
		}
	}
	return affected
}
