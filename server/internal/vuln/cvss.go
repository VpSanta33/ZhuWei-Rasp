package vuln

import (
	"fmt"
	"math"
	"strings"
)

// CVSS3Score computes the CVSS v3.0/v3.1 base score of a vector such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" (specification section 7.1, 3.1 rounding).
func CVSS3Score(vector string) (float64, error) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, fmt.Errorf("not a CVSS v3 vector: %q", vector)
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	val := map[string]float64{}
	for k, table := range weights {
		w, ok := table[m[k]]
		if !ok {
			return 0, fmt.Errorf("CVSS vector %q: missing or invalid %s", vector, k)
		}
		val[k] = w
	}
	changed := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return 0, fmt.Errorf("CVSS vector %q: missing or invalid S", vector)
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	prW, ok := pr[m["PR"]]
	if !ok {
		return 0, fmt.Errorf("CVSS vector %q: missing or invalid PR", vector)
	}
	iss := 1 - (1-val["C"])*(1-val["I"])*(1-val["A"])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, nil
	}
	exploitability := 8.22 * val["AV"] * val["AC"] * prW * val["UI"]
	if changed {
		return roundUp(math.Min(1.08*(impact+exploitability), 10)), nil
	}
	return roundUp(math.Min(impact+exploitability, 10)), nil
}

// roundUp is the CVSS v3.1 Roundup function (avoids floating point artefacts such as 4.000000001 -> 4.1).
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// LevelFromScore maps a CVSS base score to the qualitative rating scale.
func LevelFromScore(s float64) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	case s > 0:
		return "low"
	}
	return "none"
}
