package console

import (
	"fmt"
	"net/http"

	"zhuwei-rasp/server/internal/httpx"
	"zhuwei-rasp/server/internal/store"
)

func (a *API) registerIncidents(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/incidents", a.auth(a.listIncidents))
	mux.HandleFunc("GET /api/v1/incidents/{fp}", a.auth(a.getIncident))
	mux.HandleFunc("POST /api/v1/incidents/{fp}/status", a.auth(a.setIncidentStatus))
}

func (a *API) listIncidents(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	list, total, err := a.st.QueryIncidents(store.IncidentQuery{
		AppID: httpx.QueryInt(r, "app_id", 0), AttackType: q.Get("type"), Status: q.Get("status"),
		Blocked: q.Get("blocked") == "1", Since: httpx.QueryInt(r, "since", 0), Keyword: q.Get("q"),
		Page: int(httpx.QueryInt(r, "page", 1)), PageSize: int(httpx.QueryInt(r, "page_size", 20)),
	})
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, map[string]any{"items": list, "total": total})
}

// getIncident returns the incident with its top source IPs and most recent alarms.
func (a *API) getIncident(w http.ResponseWriter, r *http.Request, _ string) {
	fp := r.PathValue("fp")
	in, err := a.st.GetIncident(fp)
	if err != nil {
		storeErr(w, err)
		return
	}
	sources, err := a.st.IncidentSources(fp, 10)
	if err != nil {
		storeErr(w, err)
		return
	}
	recent, _, err := a.st.QueryAlarms(store.AlarmQuery{Fingerprint: fp, PageSize: 20})
	if err != nil {
		storeErr(w, err)
		return
	}
	if recent == nil {
		recent = []*store.Alarm{}
	}
	httpx.OK(w, map[string]any{"incident": in, "top_sources": sources, "recent_alarms": recent})
}

// setIncidentStatus triages an incident; "apply_to_alarms" also sets the status of its alarms still in "new".
func (a *API) setIncidentStatus(w http.ResponseWriter, r *http.Request, user string) {
	var req struct {
		Status        string `json:"status"`
		ApplyToAlarms bool   `json:"apply_to_alarms"`
	}
	if err := httpx.ReadJSON(r, 4096, &req); err != nil || !alarmStatuses[req.Status] {
		httpx.Fail(w, http.StatusBadRequest, "status must be new/confirmed/false_positive/fixed/ignored")
		return
	}
	fp := r.PathValue("fp")
	n, err := a.st.SetIncidentStatus(fp, req.Status, req.ApplyToAlarms)
	if err != nil {
		storeErr(w, err)
		return
	}
	a.st.AddAudit(user, "incident_status", fp, fmt.Sprintf("%s (alarms updated: %d)", req.Status, n))
	httpx.OK(w, map[string]any{"alarms_updated": n})
}
