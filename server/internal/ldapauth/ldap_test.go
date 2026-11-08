package ldapauth

import (
	"errors"
	"testing"

	"zhuwei-rasp/server/internal/ldapauth/ldaptest"
)

const (
	adminsDN = "cn=rasp-admins,ou=groups,dc=corp,dc=com"
	opsDN    = "cn=rasp-operators,ou=groups,dc=corp,dc=com"
	viewDN   = "cn=rasp-viewers,ou=groups,dc=corp,dc=com"
)

func directory(t *testing.T) (*Config, *ldaptest.Server) {
	srv := &ldaptest.Server{ServiceDN: "cn=svc,dc=corp,dc=com", ServicePassword: "svc-secret", Users: []ldaptest.User{
		{UID: "alice", DN: "uid=alice,ou=people,dc=corp,dc=com", Password: "alice-pass", Groups: []string{"CN=RASP-Admins,ou=groups,dc=corp,dc=com", opsDN}},
		{UID: "bob", DN: "uid=bob,ou=people,dc=corp,dc=com", Password: "bob-pass", Groups: []string{opsDN}},
		{UID: "carol", DN: "uid=carol,ou=people,dc=corp,dc=com", Password: "carol-pass", Groups: []string{viewDN}},
		{UID: "dave", DN: "uid=dave,ou=people,dc=corp,dc=com", Password: "dave-pass", Groups: []string{"cn=finance,dc=corp,dc=com"}},
	}}
	cfg := &Config{URL: srv.Start(t), BindDN: srv.ServiceDN, BindPassword: srv.ServicePassword, BaseDN: "ou=people,dc=corp,dc=com",
		UserAttr: "uid", AdminGroup: adminsDN, OperatorGroup: opsDN, ViewerGroup: viewDN}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg, srv
}

func TestRoleMapping(t *testing.T) {
	cfg, _ := directory(t)
	for user, want := range map[string]string{"alice": "admin", "bob": "operator", "carol": "viewer"} {
		role, err := cfg.Authenticate(user, user+"-pass")
		if err != nil || role != want {
			t.Errorf("%s: role=%q err=%v, want %s", user, role, err, want)
		}
	}
	if _, err := cfg.Authenticate("dave", "dave-pass"); !errors.Is(err, ErrNoRole) {
		t.Errorf("unmapped user: %v", err)
	}
}

func TestRejections(t *testing.T) {
	cfg, srv := directory(t)
	for _, tc := range []struct{ user, pass string }{
		{"alice", "wrong"}, {"alice", ""}, {"nobody", "x"}, {"", "x"},
		{"*", "alice-pass"},   // must not become a wildcard search
		{"alice)(uid=*", "x"}, // filter injection attempt
	} {
		if _, err := cfg.Authenticate(tc.user, tc.pass); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Authenticate(%q, %q) = %v, want invalid credentials", tc.user, tc.pass, err)
		}
	}
	// the escaped values reached the server as literal equality values
	found := false
	for _, s := range srv.Searches {
		if s == "*" || s == "alice)(uid=*" {
			found = true
		}
	}
	if !found {
		t.Errorf("escaped search values not seen: %q", srv.Searches)
	}
	bad := *cfg
	bad.BindPassword = "nope"
	if _, err := bad.Authenticate("alice", "alice-pass"); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong service password should be a configuration error, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, c := range []Config{
		{URL: "http://x", BaseDN: "dc=x", UserAttr: "uid", ViewerGroup: "cn=g"},
		{URL: "ldaps://x:636", UserAttr: "uid", ViewerGroup: "cn=g"},
		{URL: "ldaps://x:636", BaseDN: "dc=x", UserAttr: "uid"},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("Validate(%+v) should fail", c)
		}
	}
	if !(&Config{URL: "ldaps://x"}).Encrypted() || (&Config{URL: "ldap://x"}).Encrypted() || !(&Config{URL: "ldap://x", StartTLS: true}).Encrypted() {
		t.Error("Encrypted()")
	}
}
