package vuln

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"zhuwei-rasp/server/internal/store"
)

const (
	maxDocBytes  = 8 << 20 // one OSV document
	batchSize    = 500
	debounce     = 3 * time.Second
	notifyListed = 10
)

// Service imports advisories and keeps the component findings (component_vuln) current.
type Service struct {
	st     *store.Store
	notify func(text string, event any) // webhook sender; nil = no notifications
	mu     sync.Mutex                   // one import / rematch at a time
	dirty  chan struct{}
}

func NewService(st *store.Store, notify func(text string, event any)) *Service {
	s := &Service{st: st, notify: notify, dirty: make(chan struct{}, 1)}
	go s.loop()
	return s
}

// Trigger schedules a rematch soon (debounced); called whenever an agent reports its components.
func (s *Service) Trigger() {
	select {
	case s.dirty <- struct{}{}:
	default:
	}
}

func (s *Service) loop() {
	for range s.dirty {
		time.Sleep(debounce) // coalesce bursts of dependency reports after a fleet restart
		select {
		case <-s.dirty:
		default:
		}
		if _, err := s.Rematch(); err != nil {
			log.Printf("vulnerability rematch: %v", err)
		}
	}
}

type MatchResult struct {
	Components  int `json:"components"`   // distinct group:artifact:version checked
	Findings    int `json:"findings"`     // component/advisory pairs now affected
	NewFindings int `json:"new_findings"` // not present before this run
}

// Rematch evaluates every deployed component against the advisory database.
func (s *Service) Rematch() (MatchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rematchLocked()
}

func (s *Service) rematchLocked() (MatchResult, error) {
	var res MatchResult
	gavs, err := s.st.DistinctComponents()
	if err != nil {
		return res, err
	}
	res.Components = len(gavs)
	pkgSet := map[string]bool{}
	for _, g := range gavs {
		pkgSet[g.Group+":"+g.Artifact] = true
	}
	pkgs := make([]string, 0, len(pkgSet))
	for p := range pkgSet {
		pkgs = append(pkgs, p)
	}
	affected, err := s.st.AffectedByPackages(pkgs)
	if err != nil {
		return res, err
	}
	parsed := map[*store.AffectedRow]*Affected{}
	var found []store.Finding
	for _, g := range gavs {
		for _, row := range affected[g.Group+":"+g.Artifact] {
			af := parsed[row]
			if af == nil {
				af = &Affected{VulnID: row.VulnID, Package: row.Package}
				_ = json.Unmarshal([]byte(row.Ranges), &af.Ranges)
				_ = json.Unmarshal([]byte(row.Versions), &af.Versions)
				parsed[row] = af
			}
			if hit, fixed := af.Matches(g.Version); hit {
				found = append(found, store.Finding{Group: g.Group, Artifact: g.Artifact, Version: g.Version, VulnID: row.VulnID, Fixed: strings.Join(fixed, ",")})
			}
		}
	}
	fresh, err := s.st.SyncFindings(found)
	if err != nil {
		return res, err
	}
	res.Findings, res.NewFindings = len(found), len(fresh)
	if len(fresh) > 0 {
		s.announce(fresh)
	}
	return res, nil
}

// announce sends one webhook message per rematch. With notify_level=block (default) only high and critical
// findings are sent; with notify_level=all every new finding is.
func (s *Service) announce(fresh []store.Finding) {
	if s.notify == nil || s.st.GetSetting("notify_webhook", "") == "" {
		return
	}
	all := s.st.GetSetting("notify_level", "block") == "all"
	type item struct {
		store.Finding
		Severity string `json:"severity"`
		Aliases  string `json:"aliases"`
		Summary  string `json:"summary"`
	}
	var items []item
	for _, f := range fresh {
		v, err := s.st.GetVuln(f.VulnID)
		if err != nil {
			continue
		}
		if !all && LevelRank(v.Severity) < LevelRank("high") {
			continue
		}
		items = append(items, item{f, v.Severity, v.Aliases, v.Summary})
	}
	if len(items) == 0 {
		return
	}
	sort.SliceStable(items, func(i, j int) bool { return LevelRank(items[i].Severity) > LevelRank(items[j].Severity) })
	var b strings.Builder
	fmt.Fprintf(&b, "[ZhuWei-RASP] %d new vulnerable component findings", len(items))
	for i, it := range items {
		if i == notifyListed {
			fmt.Fprintf(&b, "\n… and %d more", len(items)-notifyListed)
			break
		}
		id := it.VulnID
		if it.Aliases != "" {
			id = strings.Split(it.Aliases, ",")[0]
		}
		fixed := "no fixed version"
		if it.Fixed != "" {
			fixed = "fixed in " + it.Fixed
		}
		fmt.Fprintf(&b, "\n- [%s] %s:%s:%s %s (%s)", it.Severity, it.Group, it.Artifact, it.Version, id, fixed)
	}
	s.notify(b.String(), map[string]any{"type": "vulnerable_components", "findings": items})
}

type ImportResult struct {
	Source  string                 `json:"source"`
	Files   int                    `json:"files"`   // JSON documents read
	Skipped int                    `json:"skipped"` // not Maven, or unparsable
	Errors  []string               `json:"errors,omitempty"`
	Store   store.VulnImportCounts `json:"store"`
	Match   MatchResult            `json:"match"`
	At      int64                  `json:"at"`
}

// ImportPath imports a .zip export, a single .json file (one advisory or an array) or a directory of them,
// then rematches all components.
func (s *Service) ImportPath(path string) (*ImportResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	imp := &importer{st: s.st, res: &ImportResult{Source: filepath.Base(path)}}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	switch {
	case info.IsDir():
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".json") {
				return err
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			return imp.doc(p, f)
		})
	case strings.EqualFold(filepath.Ext(path), ".zip") || isZip(path):
		var zr *zip.ReadCloser
		if zr, err = zip.OpenReader(path); err == nil {
			defer zr.Close()
			for _, zf := range zr.File {
				if zf.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(zf.Name), ".json") {
					continue
				}
				rc, oerr := zf.Open()
				if oerr != nil {
					imp.fail(zf.Name, oerr)
					continue
				}
				err = imp.doc(zf.Name, rc)
				rc.Close()
				if err != nil {
					break
				}
			}
		}
	default:
		var f *os.File
		if f, err = os.Open(path); err == nil {
			defer f.Close()
			err = imp.doc(path, f)
		}
	}
	if err == nil {
		err = imp.flush()
	}
	if err != nil {
		return nil, err
	}
	res := imp.res
	res.At = time.Now().UnixMilli()
	if res.Match, err = s.rematchLocked(); err != nil {
		return nil, err
	}
	if b, err := json.Marshal(res); err == nil {
		_ = s.st.SetSetting("vuln_last_import", string(b))
	}
	return res, nil
}

func isZip(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	return n == 4 && string(head) == "PK\x03\x04"
}

type importer struct {
	st    *store.Store
	res   *ImportResult
	batch []*store.VulnRow
}

func (im *importer) fail(name string, err error) {
	im.res.Skipped++
	if len(im.res.Errors) < 20 {
		im.res.Errors = append(im.res.Errors, fmt.Sprintf("%s: %v", name, err))
	}
}

// doc reads one JSON document: an advisory object or an array of advisories.
func (im *importer) doc(name string, r io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(r, maxDocBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxDocBytes {
		im.fail(name, fmt.Errorf("document larger than %d bytes", maxDocBytes))
		return nil
	}
	trimmed := strings.TrimSpace(string(data))
	var raws []json.RawMessage
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &raws); err != nil {
			im.fail(name, err)
			return nil
		}
	} else {
		raws = []json.RawMessage{data}
	}
	for _, raw := range raws {
		im.res.Files++
		a, err := ParseAdvisory(raw)
		if err != nil {
			im.fail(name, err)
			continue
		}
		row := toRow(a)
		if row == nil {
			im.res.Skipped++ // no Maven package
			continue
		}
		im.batch = append(im.batch, row)
		if len(im.batch) >= batchSize {
			if err := im.flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (im *importer) flush() error {
	if len(im.batch) == 0 {
		return nil
	}
	c, err := im.st.UpsertVulns(im.batch)
	if err != nil {
		return err
	}
	im.res.Store.Inserted += c.Inserted
	im.res.Store.Updated += c.Updated
	im.res.Store.Unchanged += c.Unchanged
	im.res.Store.Withdrawn += c.Withdrawn
	im.batch = im.batch[:0]
	return nil
}

func toRow(a *Advisory) *store.VulnRow {
	maven := a.MavenAffected()
	if a.Withdrawn != "" {
		return &store.VulnRow{ID: a.ID, Withdrawn: true}
	}
	if len(maven) == 0 {
		return nil
	}
	level, score := a.Rating()
	var refs []string
	for _, r := range a.References {
		if r.URL != "" && len(refs) < 20 {
			refs = append(refs, r.URL)
		}
	}
	details := a.Details
	if len(details) > 20000 {
		details = details[:20000]
	}
	row := &store.VulnRow{
		ID: a.ID, Aliases: strings.Join(a.Aliases, ","), Summary: a.Summary, Details: details,
		Severity: level, Score: score, Published: ParseTime(a.Published), Modified: ParseTime(a.Modified), Refs: strings.Join(refs, "\n"),
	}
	for _, m := range maven {
		ranges, _ := json.Marshal(m.Ranges)
		versions, _ := json.Marshal(m.Versions)
		if m.Versions == nil {
			versions = []byte("[]")
		}
		row.Affected = append(row.Affected, &store.AffectedRow{Package: m.Package, Ranges: string(ranges), Versions: string(versions)})
	}
	return row
}

// maxDownloadBytes bounds an automatic OSV download (the Maven export is ~10 MB compressed).
const maxDownloadBytes = 512 << 20

// StartAutoUpdate downloads an OSV export from url every interval (first run after a short delay) and
// imports it. Off unless configured: the platform otherwise never initiates outbound connections.
// HTTP(S)_PROXY environment variables are honoured.
func (s *Service) StartAutoUpdate(url string, every time.Duration, audit func(detail string)) {
	go func() {
		time.Sleep(time.Minute)
		for {
			res, err := s.UpdateFrom(url)
			if err != nil {
				log.Printf("vulnerability data update from %s failed: %v", url, err)
			} else {
				log.Printf("vulnerability data updated from %s: %d documents, %d inserted, %d updated, %d withdrawn; %d findings (%d new)",
					url, res.Files, res.Store.Inserted, res.Store.Updated, res.Store.Withdrawn, res.Match.Findings, res.Match.NewFindings)
				if audit != nil {
					audit(fmt.Sprintf("documents=%d inserted=%d updated=%d withdrawn=%d findings=%d new=%d",
						res.Files, res.Store.Inserted, res.Store.Updated, res.Store.Withdrawn, res.Match.Findings, res.Match.NewFindings))
				}
			}
			time.Sleep(every)
		}
	}()
}

// UpdateFrom downloads one OSV export (zip) and imports it.
func (s *Service) UpdateFrom(url string) (*ImportResult, error) {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "rasp-osv-download-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDownloadBytes+1))
	tmp.Close()
	if err != nil {
		return nil, err
	}
	if n > maxDownloadBytes {
		return nil, fmt.Errorf("download larger than %d MiB", maxDownloadBytes>>20)
	}
	if !isZip(tmp.Name()) {
		return nil, fmt.Errorf("downloaded file is not a zip archive")
	}
	res, err := s.ImportPath(tmp.Name())
	if err != nil {
		return nil, err
	}
	res.Source = url
	return res, nil
}
