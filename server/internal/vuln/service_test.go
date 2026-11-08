package vuln

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zhuwei-rasp/server/internal/store"
)

func writeZip(t *testing.T, path string, docs map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range docs {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

const jacksonOSV = `{"id":"GHSA-jjjh-jjxp-wpff","modified":"2023-01-01T00:00:00Z","aliases":["CVE-2022-42003"],
 "summary":"Uncontrolled resource consumption in jackson-databind",
 "affected":[{"package":{"ecosystem":"Maven","name":"com.fasterxml.jackson.core:jackson-databind"},
   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.4.0-rc1"},{"fixed":"2.12.7.1"}]},
             {"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.13.4.2"}]}]}],
 "database_specific":{"severity":"HIGH"}}`

const lowOSV = `{"id":"GHSA-low-0000-0000","modified":"2023-01-01T00:00:00Z","summary":"minor issue",
 "affected":[{"package":{"ecosystem":"Maven","name":"com.h2database:h2"},"versions":["2.3.232"]}],
 "database_specific":{"severity":"LOW"}}`

func TestImportMatchNotifyAndUpdate(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	app := &store.App{Name: "order", Env: "prod", Policy: "{}"}
	if err := st.CreateApp(app); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceComponents("agent-1", app.ID, []store.Component{
		{Group: "org.apache.logging.log4j", Artifact: "log4j-core", Version: "2.14.1", Path: "/lib/log4j-core-2.14.1.jar"},
		{Group: "com.fasterxml.jackson.core", Artifact: "jackson-databind", Version: "2.13.3", Path: "/lib/jackson-databind.jar"},
		{Group: "com.h2database", Artifact: "h2", Version: "2.3.232", Path: "/lib/h2.jar"},
		{Group: "", Artifact: "legacy", Version: "1.0", Path: "/lib/legacy-1.0.jar"}, // cannot be matched
		{Group: "org.apache.logging.log4j", Artifact: "log4j-api", Version: "2.14.1", Path: "/lib/log4j-api.jar"},
	}); err != nil {
		t.Fatal(err)
	}
	var sent []string
	svc := &Service{st: st, notify: func(text string, _ any) { sent = append(sent, text) }, dirty: make(chan struct{}, 1)}
	_ = st.SetSetting("notify_webhook", "http://example.invalid/hook") // only checked for presence here

	export := filepath.Join(dir, "osv.zip")
	writeZip(t, export, map[string]string{
		"GHSA-jfh8-c2jp-5v3q.json": sampleOSV, "GHSA-jjjh-jjxp-wpff.json": jacksonOSV, "low.json": lowOSV,
		"npm-only.json": `{"id":"GHSA-npm","affected":[{"package":{"ecosystem":"npm","name":"x"}}]}`,
		"broken.json":   `{not json`, "README.txt": "ignored",
	})
	res, err := svc.ImportPath(export)
	if err != nil {
		t.Fatal(err)
	}
	if res.Store.Inserted != 3 || res.Skipped != 2 || res.Match.Components != 4 || res.Match.Findings != 3 || res.Match.NewFindings != 3 {
		t.Fatalf("first import = %+v", res)
	}
	// default notify_level=block: only high and critical findings are announced
	if len(sent) != 1 || !strings.Contains(sent[0], "2 new vulnerable component findings") ||
		!strings.Contains(sent[0], "[critical] org.apache.logging.log4j:log4j-core:2.14.1 CVE-2021-44228 (fixed in 2.15.0)") ||
		strings.Contains(sent[0], "h2") {
		t.Fatalf("notification = %q", sent)
	}

	findings, err := st.QueryFindings(store.FindingQuery{})
	if err != nil || len(findings) != 3 {
		t.Fatalf("findings = %v %v", findings, err)
	}
	if findings[0].Severity != "critical" || findings[0].Apps != "order/prod" || findings[0].Instances != 1 || findings[1].Fixed != "2.13.4.2" {
		t.Fatalf("ordering/content = %+v %+v", findings[0], findings[1])
	}
	if high, _ := st.QueryFindings(store.FindingQuery{Severity: "high"}); len(high) != 2 {
		t.Fatalf("severity filter = %d", len(high))
	}
	if byCVE, _ := st.QueryFindings(store.FindingQuery{Keyword: "CVE-2022-42003"}); len(byCVE) != 1 {
		t.Fatalf("alias search = %d", len(byCVE))
	}
	sum, _ := st.SummarizeVulns(0)
	if sum.Advisories != 3 || sum.Findings != 3 || sum.BySeverity["critical"] != 1 || sum.AffectedComponents != 3 || sum.AffectedApps != 1 || sum.Unmatchable != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	comps, _ := st.QueryComponents(0, "log4j", 100)
	for _, c := range comps {
		if c.Artifact == "log4j-core" && (c.Vulns != 1 || c.Severity != "critical") || c.Artifact == "log4j-api" && c.Vulns != 0 {
			t.Fatalf("component vuln columns = %+v", c)
		}
	}

	// Rematch is idempotent: nothing new, nothing announced.
	sent = nil
	if r, _ := svc.Rematch(); r.NewFindings != 0 || r.Findings != 3 || len(sent) != 0 {
		t.Fatalf("rematch = %+v sent=%v", r, sent)
	}

	// Upgrading a component removes its finding; a newer advisory revision narrows a range; withdrawal deletes.
	_ = st.ReplaceComponents("agent-1", app.ID, []store.Component{
		{Group: "org.apache.logging.log4j", Artifact: "log4j-core", Version: "2.17.1", Path: "/lib/log4j-core-2.17.1.jar"},
		{Group: "com.fasterxml.jackson.core", Artifact: "jackson-databind", Version: "2.13.3", Path: "/lib/jackson-databind.jar"},
		{Group: "com.h2database", Artifact: "h2", Version: "2.3.232", Path: "/lib/h2.jar"},
	})
	update := filepath.Join(dir, "update.json")
	_ = os.WriteFile(update, []byte(`[`+strings.Replace(strings.Replace(jacksonOSV, "2023-01-01", "2024-01-01", 1), `"introduced":"2.13.0"`, `"introduced":"2.13.4"`, 1)+
		`,{"id":"GHSA-low-0000-0000","modified":"2024-02-01T00:00:00Z","withdrawn":"2024-02-01T00:00:00Z"}]`), 0o600)
	res, err = svc.ImportPath(update)
	if err != nil {
		t.Fatal(err)
	}
	if res.Store.Updated != 1 || res.Store.Withdrawn != 1 || res.Match.Findings != 0 {
		t.Fatalf("update import = %+v", res)
	}
	if v, err := st.GetVuln("GHSA-low-0000-0000"); err == nil {
		t.Fatalf("withdrawn advisory still present: %+v", v)
	}
	// Re-importing the original export: older "modified" timestamps do not overwrite newer data.
	res, _ = svc.ImportPath(export)
	if res.Store.Unchanged != 2 || res.Store.Inserted != 1 { // log4j unchanged, jackson older, low re-inserted
		t.Fatalf("re-import = %+v", res.Store)
	}
}
