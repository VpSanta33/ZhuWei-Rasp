// Package ldapauth authenticates console users against an LDAP / Active Directory server and maps their
// group membership to console roles.
package ldapauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config describes the directory. Group DNs are compared case-insensitively.
type Config struct {
	URL           string // ldaps://host:636 or ldap://host:389
	StartTLS      bool   // upgrade ldap:// with StartTLS
	CAFile        string // PEM bundle for a private CA (optional)
	BindDN        string // read-only service account used for the user lookup
	BindPassword  string
	BaseDN        string // where users live, e.g. ou=people,dc=corp,dc=com
	UserAttr      string // uid (OpenLDAP) or sAMAccountName (AD)
	AdminGroup    string // group DNs mapped to roles; the highest matching role wins
	OperatorGroup string
	ViewerGroup   string
	Timeout       time.Duration
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrNoRole             = errors.New("user is not in any group mapped to a console role")
)

// Enabled reports whether LDAP login is configured.
func (c *Config) Enabled() bool { return c != nil && c.URL != "" }

// Validate checks the configuration at start-up.
func (c *Config) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return fmt.Errorf("ldap url must look like ldaps://host:636 or ldap://host:389")
	}
	if c.BaseDN == "" || c.UserAttr == "" {
		return fmt.Errorf("ldap base DN and user attribute are required")
	}
	if c.AdminGroup == "" && c.OperatorGroup == "" && c.ViewerGroup == "" {
		return fmt.Errorf("map at least one LDAP group to a role (admin, operator or viewer group)")
	}
	if c.CAFile != "" {
		if _, err := os.ReadFile(c.CAFile); err != nil {
			return fmt.Errorf("ldap CA file: %w", err)
		}
	}
	return nil
}

// Encrypted reports whether credentials travel over TLS.
func (c *Config) Encrypted() bool {
	return strings.HasPrefix(strings.ToLower(c.URL), "ldaps://") || c.StartTLS
}

func (c *Config) tlsConfig(host string) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", c.CAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func (c *Config) dial() (*ldap.Conn, error) {
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(u.Host)
	if host == "" {
		host = u.Host
	}
	tlsCfg, err := c.tlsConfig(host)
	if err != nil {
		return nil, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	conn, err := ldap.DialURL(c.URL, ldap.DialWithTLSConfig(tlsCfg), ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(timeout)
	if c.StartTLS && u.Scheme == "ldap" {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	return conn, nil
}

// Authenticate verifies username/password and returns the mapped role (viewer, operator or admin).
func (c *Config) Authenticate(username, password string) (string, error) {
	// An empty password would be an "unauthenticated bind", which many servers accept: never allow it.
	if strings.TrimSpace(username) == "" || password == "" {
		return "", ErrInvalidCredentials
	}
	conn, err := c.dial()
	if err != nil {
		return "", fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()
	if c.BindDN != "" {
		if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
			return "", fmt.Errorf("ldap service bind: %w", err)
		}
	}
	res, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		fmt.Sprintf("(%s=%s)", ldap.EscapeFilter(c.UserAttr), ldap.EscapeFilter(username)),
		[]string{"memberOf"}, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return "", ErrInvalidCredentials // ambiguous user name
		}
		return "", fmt.Errorf("ldap search: %w", err)
	}
	if len(res.Entries) != 1 {
		return "", ErrInvalidCredentials
	}
	entry := res.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("ldap user bind: %w", err)
	}
	role := c.roleFor(entry.GetAttributeValues("memberOf"))
	if role == "" {
		return "", ErrNoRole
	}
	return role, nil
}

func (c *Config) roleFor(groups []string) string {
	has := func(dn string) bool {
		if dn == "" {
			return false
		}
		for _, g := range groups {
			if strings.EqualFold(strings.TrimSpace(g), strings.TrimSpace(dn)) {
				return true
			}
		}
		return false
	}
	switch {
	case has(c.AdminGroup):
		return "admin"
	case has(c.OperatorGroup):
		return "operator"
	case has(c.ViewerGroup):
		return "viewer"
	}
	return ""
}
