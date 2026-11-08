package console

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"zhuwei-rasp/server/internal/httpx"
	"zhuwei-rasp/server/internal/store"
)

// maxImportBytes bounds an uploaded OSV export. Full ecosystem exports are best imported on the server
// host with `rasp-server import-osv`, which has no size limit and no HTTP timeout.
const maxImportBytes = 256 << 20

func (a *API) registerVulns(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/vulns/summary", a.auth(a.vulnSummary))
	mux.HandleFunc("GET /api/v1/vulns/findings", a.auth(a.vulnFindings))
	mux.HandleFunc("GET /api/v1/vulns/{id}", a.auth(a.vulnDetail))
	mux.HandleFunc("POST /api/v1/vulns/import", a.auth(a.vulnImport))
	mux.HandleFunc("POST /api/v1/vulns/rematch", a.auth(a.vulnRematch))
}

func (a *API) vulnSummary(w http.ResponseWriter, r *http.Request, _ string) {
	sum, err := a.st.SummarizeVulns(httpx.QueryInt(r, "app_id", 0))
	if err != nil {
		storeErr(w, err)
		return
	}
	var last json.RawMessage
	if v := a.st.GetSetting("vuln_last_import", ""); v != "" {
		last = json.RawMessage(v)
	}
	httpx.OK(w, map[string]any{"summary": sum, "last_import": last})
}

func (a *API) vulnFindings(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	list, err := a.st.QueryFindings(store.FindingQuery{
		AppID: httpx.QueryInt(r, "app_id", 0), Severity: q.Get("severity"), Keyword: q.Get("q"),
		VulnID: q.Get("vuln_id"), Limit: int(httpx.QueryInt(r, "limit", 1000)),
	})
	if err != nil {
		storeErr(w, err)
		return
	}
	if list == nil {
		list = []*store.FindingRow{}
	}
	httpx.OK(w, list)
}

func (a *API) vulnDetail(w http.ResponseWriter, r *http.Request, _ string) {
	v, err := a.st.GetVuln(r.PathValue("id"))
	if err != nil {
		storeErr(w, err)
		return
	}
	findings, err := a.st.QueryFindings(store.FindingQuery{VulnID: v.ID, Limit: 5000})
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, map[string]any{"advisory": v, "findings": findings})
}

// vulnImport accepts an OSV export as the request body: a .zip archive or JSON (one advisory or an array).
func (a *API) vulnImport(w http.ResponseWriter, r *http.Request, user string) {
	if a.Vulns == nil {
		httpx.Fail(w, http.StatusServiceUnavailable, "vulnerability matching is not enabled")
		return
	}
	tmp, err := os.CreateTemp("", "rasp-osv-*")
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "cannot buffer upload")
		return
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(r.Body, maxImportBytes+1))
	tmp.Close()
	switch {
	case err != nil:
		httpx.Fail(w, http.StatusBadRequest, "upload failed")
		return
	case n == 0:
		httpx.Fail(w, http.StatusBadRequest, "empty upload: send an OSV .zip export or JSON as the request body")
		return
	case n > maxImportBytes:
		httpx.Fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("upload larger than %d MiB: use `rasp-server import-osv` on the server host", maxImportBytes>>20))
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "upload"
	}
	// The importer decides between zip and JSON by content, so the temp file name does not matter.
	res, err := a.Vulns.ImportPath(tmp.Name())
	if err != nil {
		log.Printf("osv import: %v", err)
		httpx.Fail(w, http.StatusBadRequest, "import failed: "+err.Error())
		return
	}
	res.Source = name
	if res.Files == 0 || (res.Files == res.Skipped && len(res.Errors) > 0) {
		// nothing usable: report why instead of a misleading "ok"
		httpx.FailData(w, http.StatusBadRequest, "no valid OSV advisories in upload", res.Errors)
		return
	}
	a.st.AddAudit(user, "import_vulns", name, fmt.Sprintf("documents=%d inserted=%d updated=%d withdrawn=%d findings=%d new=%d",
		res.Files, res.Store.Inserted, res.Store.Updated, res.Store.Withdrawn, res.Match.Findings, res.Match.NewFindings))
	httpx.OK(w, res)
}

func (a *API) vulnRematch(w http.ResponseWriter, r *http.Request, user string) {
	if a.Vulns == nil {
		httpx.Fail(w, http.StatusServiceUnavailable, "vulnerability matching is not enabled")
		return
	}
	res, err := a.Vulns.Rematch()
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, res)
}
