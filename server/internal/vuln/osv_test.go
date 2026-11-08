package vuln

import (
	"strings"
	"testing"
)

func TestCVSS3Score(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0, // log4shell
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for vec, want := range cases {
		got, err := CVSS3Score(vec)
		if err != nil || got != want {
			t.Errorf("CVSS3Score(%s) = %v, %v; want %v", vec, got, err, want)
		}
	}
	for _, bad := range []string{"", "CVSS:2.0/AV:N", "CVSS:3.1/AV:N/AC:L", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"} {
		if _, err := CVSS3Score(bad); err == nil {
			t.Errorf("CVSS3Score(%q) should fail", bad)
		}
	}
}

const sampleOSV = `{
  "id": "GHSA-jfh8-c2jp-5v3q", "modified": "2024-06-01T00:00:00Z", "published": "2021-12-10T00:00:00Z",
  "aliases": ["CVE-2021-44228"], "summary": "Remote code injection in Log4j",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
  "affected": [
    {"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.12.2"}]}]},
    {"package": {"ecosystem": "npm", "name": "log4js"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}
  ],
  "database_specific": {"severity": "CRITICAL"}
}`

func TestAdvisoryMatching(t *testing.T) {
	a, err := ParseAdvisory([]byte(sampleOSV))
	if err != nil {
		t.Fatal(err)
	}
	if lvl, score := a.Rating(); lvl != "critical" || score != 10 {
		t.Fatalf("rating = %s %v", lvl, score)
	}
	aff := a.MavenAffected()
	if len(aff) != 1 || aff[0].Package != "org.apache.logging.log4j:log4j-core" {
		t.Fatalf("maven affected = %+v", aff)
	}
	cases := map[string]string{ // version -> expected fixed list ("" = not affected)
		"2.14.1": "2.15.0", "2.13.0": "2.15.0", "2.15.0-rc1": "2.15.0", "2.15.0": "", "2.17.1": "",
		"2.12.1": "2.12.2", "2.0-beta9": "2.12.2", "2.0-beta8": "", "2.0": "2.12.2", "2.12.2": "", "1.2.17": "",
	}
	for v, want := range cases {
		hit, fixed := aff[0].Matches(v)
		if hit != (want != "") || (hit && strings.Join(fixed, ",") != want) {
			t.Errorf("Matches(%s) = %v %v, want %q", v, hit, fixed, want)
		}
	}
}

func TestRangeEventVariants(t *testing.T) {
	af := Affected{Ranges: []Range{
		{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {LastAffected: "1.4.2"}}},
		{Type: "GIT", Events: []Event{{Introduced: "0"}}}, // ignored
	}, Versions: []string{"3.0.0"}}
	for v, want := range map[string]bool{"0.1": true, "1.4.2": true, "1.4.2.1": false, "2.0": false, "3.0": true, "": false} {
		if hit, _ := af.Matches(v); hit != want {
			t.Errorf("Matches(%q) = %v, want %v", v, hit, want)
		}
	}
	// unsorted events and an open-ended re-introduction
	af = Affected{Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Fixed: "1.5"}, {Introduced: "2.0"}, {Introduced: "1.0"}}}}}
	for v, want := range map[string]bool{"0.9": false, "1.2": true, "1.5": false, "1.9": false, "2.0": true, "9.9": true} {
		if hit, _ := af.Matches(v); hit != want {
			t.Errorf("unsorted Matches(%q) = %v, want %v", v, hit, want)
		}
	}
}

func TestRatingFallbacks(t *testing.T) {
	a, _ := ParseAdvisory([]byte(`{"id":"X-1","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"}]}`))
	if lvl, score := a.Rating(); lvl != "medium" || score != 6.4 {
		t.Errorf("score-derived rating = %s %v", lvl, score)
	}
	a, _ = ParseAdvisory([]byte(`{"id":"X-2","database_specific":{"severity":"MODERATE"}}`))
	if lvl, score := a.Rating(); lvl != "medium" || score != -1 {
		t.Errorf("database rating = %s %v", lvl, score)
	}
	a, _ = ParseAdvisory([]byte(`{"id":"X-3"}`))
	if lvl, _ := a.Rating(); lvl != "unknown" {
		t.Errorf("no rating = %s", lvl)
	}
	if _, err := ParseAdvisory([]byte(`{"summary":"no id"}`)); err == nil {
		t.Error("advisory without id should fail")
	}
}
