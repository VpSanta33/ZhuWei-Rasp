// Package policy builds the effective agent configuration (docs chapter 6.5.2):
// app policy + whitelist (app and global) + global kill switch, versioned by content hash.
package policy

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"zhuwei-rasp/server/internal/store"
)

//go:embed default_policy.json
var defaultPolicy []byte

var (
	validModes  = map[string]bool{"off": true, "monitor": true, "block": true}
	validTypes  = map[string]bool{"sql": true, "command": true, "readFile": true, "writeFile": true, "ssrf": true, "deserialization": true, "jndi": true}
	validAction = map[string]bool{"pass": true, "ignore": true, "log": true, "block": true}
	validOps    = map[string]bool{"eq": true, "ne": true, "contains": true, "not_contains": true, "prefix": true, "suffix": true,
		"regex": true, "in": true, "not_in": true, "exists": true, "contains_user_input": true}
)

// Default returns the built-in policy (monitor mode) as compact JSON.
func Default() string {
	var m map[string]any
	if err := json.Unmarshal(defaultPolicy, &m); err != nil {
		panic(err)
	}
	delete(m, "version")
	delete(m, "whitelist")
	b, _ := json.Marshal(m)
	return string(b)
}

// Validate checks a policy document edited in the console and returns it normalised.
func Validate(raw string) (string, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return "", fmt.Errorf("policy is not valid JSON: %w", err)
	}
	if mode, _ := m["mode"].(string); !validModes[mode] {
		return "", fmt.Errorf("mode must be off, monitor or block")
	}
	if v, ok := m["body_max_bytes"]; ok {
		n, isNum := v.(float64)
		if !isNum || n < 0 || n > 1<<20 || n != float64(int64(n)) {
			return "", fmt.Errorf("body_max_bytes must be an integer between 0 and 1048576")
		}
	}
	if v, ok := m["async_context"]; ok {
		if _, isBool := v.(bool); !isBool {
			return "", fmt.Errorf("async_context must be true or false")
		}
	}
	if checks, ok := m["checks"].(map[string]any); ok {
		for t, v := range checks {
			if !validTypes[t] {
				return "", fmt.Errorf("unknown check type %q", t)
			}
			c, _ := v.(map[string]any)
			if a, ok := c["action"].(string); ok && !validAction[a] {
				return "", fmt.Errorf("checks.%s.action %q is invalid", t, a)
			}
		}
	}
	rules, _ := m["rules"].([]any)
	ids := map[string]bool{}
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			return "", fmt.Errorf("rules[%d] must be an object", i)
		}
		id, _ := rm["id"].(string)
		if id == "" || ids[id] {
			return "", fmt.Errorf("rules[%d]: id missing or duplicated", i)
		}
		ids[id] = true
		if t, _ := rm["type"].(string); !validTypes[t] {
			return "", fmt.Errorf("rule %s: unknown type %q", id, t)
		}
		if a, ok := rm["action"].(string); ok && !validAction[a] {
			return "", fmt.Errorf("rule %s: invalid action %q", id, a)
		}
		conds, _ := rm["conditions"].([]any)
		if len(conds) == 0 {
			return "", fmt.Errorf("rule %s: at least one condition required", id)
		}
		for j, c := range conds {
			cm, _ := c.(map[string]any)
			op, _ := cm["op"].(string)
			if !validOps[op] {
				return "", fmt.Errorf("rule %s condition %d: unknown op %q", id, j, op)
			}
			if f, _ := cm["field"].(string); f == "" {
				return "", fmt.Errorf("rule %s condition %d: field required", id, j)
			}
			if op == "regex" {
				v, _ := cm["value"].(string)
				if _, err := regexp.Compile(v); err != nil {
					return "", fmt.Errorf("rule %s condition %d: bad regex: %w", id, j, err)
				}
			}
		}
	}
	delete(m, "version")
	delete(m, "whitelist")
	delete(m, "kill_switch")
	b, _ := json.Marshal(m)
	return string(b), nil
}

// BlockingRules returns the ids of the rules that would actually block in this policy: mode is block,
// the rule is enabled with action block, and its check type is enabled with a block cap. Defaults
// mirror the agent (rule action log, rule/check enabled, check cap block).
func BlockingRules(raw string) []string {
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil || m["mode"] != "block" {
		return nil
	}
	checks, _ := m["checks"].(map[string]any)
	rules, _ := m["rules"].([]any)
	out := []string{}
	for _, r := range rules {
		rm, _ := r.(map[string]any)
		if rm == nil || rm["enabled"] == false || rm["action"] != "block" {
			continue
		}
		t, _ := rm["type"].(string)
		c, _ := checks[t].(map[string]any)
		if c != nil && (c["enabled"] == false || (c["action"] != nil && c["action"] != "block")) {
			continue
		}
		id, _ := rm["id"].(string)
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// NewlyBlocking lists rules that block in next but not in prev: changes that need explicit confirmation.
func NewlyBlocking(prev, next string) []string {
	had := map[string]bool{}
	for _, id := range BlockingRules(prev) {
		had[id] = true
	}
	out := []string{}
	for _, id := range BlockingRules(next) {
		if !had[id] {
			out = append(out, id)
		}
	}
	return out
}

// Effective composes the config delivered to agents of an app.
func Effective(app *store.App, wl []*store.Whitelist, killSwitch bool) (map[string]any, string) {
	var m map[string]any
	if err := json.Unmarshal([]byte(app.Policy), &m); err != nil || m == nil {
		_ = json.Unmarshal([]byte(Default()), &m)
	}
	entries := make([]map[string]any, 0, len(wl))
	sort.Slice(wl, func(i, j int) bool { return wl[i].ID < wl[j].ID })
	for _, w := range wl {
		types := []string{}
		for _, t := range strings.Split(w.Types, ",") {
			if t = strings.TrimSpace(t); t != "" {
				types = append(types, t)
			}
		}
		entries = append(entries, map[string]any{"url": w.URL, "match": w.Match, "types": types})
	}
	m["whitelist"] = entries
	m["kill_switch"] = killSwitch
	delete(m, "version")
	b, _ := json.Marshal(m) // map keys are sorted => stable hash
	sum := sha256.Sum256(b)
	version := hex.EncodeToString(sum[:])[:12]
	m["version"] = version
	return m, version
}
