package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"zhuwei-rasp/server/internal/store"
)

func TestDefaultPolicyIsValid(t *testing.T) {
	if _, err := Validate(Default()); err != nil {
		t.Fatalf("built-in default policy is invalid: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]string{
		`{"mode":"bogus"}`:                      "mode",
		`{"mode":"block","checks":{"nope":{}}}`: "unknown check type",
		`{"mode":"block","rules":[{"id":"a","type":"sql","conditions":[]}]}`:                                                                                       "at least one condition",
		`{"mode":"block","rules":[{"id":"a","type":"sql","conditions":[{"field":"q","op":"zzz"}]}]}`:                                                               "unknown op",
		`{"mode":"block","rules":[{"id":"a","type":"sql","conditions":[{"field":"q","op":"regex","value":"("}]}]}`:                                                 "bad regex",
		`{"mode":"block","rules":[{"id":"a","type":"sql","conditions":[{"field":"q","op":"eq"}]},{"id":"a","type":"sql","conditions":[{"field":"q","op":"eq"}]}]}`: "duplicated",
	}
	for in, want := range cases {
		_, err := Validate(in)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Validate(%s) = %v, want error containing %q", in, err, want)
		}
	}
}

func TestEffectiveVersionChangesWithInputs(t *testing.T) {
	app := &store.App{Policy: Default()}
	_, v1 := Effective(app, nil, false)
	_, v1b := Effective(app, nil, false)
	if v1 != v1b {
		t.Fatalf("version not stable: %s vs %s", v1, v1b)
	}
	cfg, v2 := Effective(app, []*store.Whitelist{{ID: 1, URL: "/a", Match: "prefix", Types: "sql,command"}}, false)
	if v2 == v1 {
		t.Fatal("whitelist change did not change version")
	}
	b, _ := json.Marshal(cfg["whitelist"])
	if !strings.Contains(string(b), `"types":["sql","command"]`) {
		t.Fatalf("whitelist not rendered: %s", b)
	}
	_, v3 := Effective(app, nil, true)
	if v3 == v1 {
		t.Fatal("kill switch did not change version")
	}
}
