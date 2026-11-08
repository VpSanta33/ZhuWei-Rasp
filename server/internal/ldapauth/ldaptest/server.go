// Package ldaptest is a tiny in-process LDAP server (simple bind + subtree equality search) for tests.
package ldaptest

import (
	"net"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type User struct {
	UID, DN, Password string
	Groups            []string
}

type Server struct {
	ServiceDN, ServicePassword string
	Users                      []User
	mu                         sync.Mutex
	Searches                   []string // equality values received (for assertions)
}

// Start listens on 127.0.0.1 and returns the ldap:// URL; it stops with the test.
func (s *Server) Start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return "ldap://" + ln.Addr().String()
}

func result(msgID int64, appTag ber.Tag, code int64) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "id"))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appTag, nil, "result")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "code"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "message"))
	p.AppendChild(op)
	return p
}

func entry(msgID int64, u User) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "id"))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "SearchResultEntry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, u.DN, "dn"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
	attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "memberOf", "type"))
	vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
	for _, g := range u.Groups {
		vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, g, "val"))
	}
	attr.AppendChild(vals)
	attrs.AppendChild(attr)
	op.AppendChild(attrs)
	p.AppendChild(op)
	return p
}

// equality returns the value of the first equalityMatch in the filter; wildcard reports a
// present/substring match (what an unescaped "*" would produce).
func equality(f *ber.Packet) (value string, wildcard bool) {
	if f.ClassType == ber.ClassContext {
		switch f.Tag {
		case 3: // equalityMatch
			if len(f.Children) == 2 {
				return string(f.Children[1].Data.Bytes()), false
			}
		case 4, 7: // substrings, present
			return "", true
		}
	}
	for _, c := range f.Children {
		if v, w := equality(c); v != "" || w {
			return v, w
		}
	}
	return "", false
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	serviceBound := false
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case 0: // BindRequest: version, name, simple password [0]
			dn := string(op.Children[1].Data.Bytes())
			pw := string(op.Children[2].Data.Bytes())
			code := int64(49) // invalidCredentials
			if dn == s.ServiceDN && pw == s.ServicePassword && pw != "" {
				code, serviceBound = 0, true
			}
			for _, u := range s.Users {
				if dn == u.DN && pw == u.Password && pw != "" {
					code = 0
				}
			}
			_, _ = c.Write(result(id, 1, code).Bytes())
		case 3: // SearchRequest
			if !serviceBound {
				_, _ = c.Write(result(id, 5, 50).Bytes()) // insufficientAccessRights
				continue
			}
			value, wildcard := equality(op.Children[6])
			s.mu.Lock()
			s.Searches = append(s.Searches, value)
			s.mu.Unlock()
			for _, u := range s.Users {
				if wildcard || strings.EqualFold(u.UID, value) {
					_, _ = c.Write(entry(id, u).Bytes())
				}
			}
			_, _ = c.Write(result(id, 5, 0).Bytes())
		case 2: // Unbind
			return
		default:
			_, _ = c.Write(result(id, 1, 2).Bytes()) // protocolError
		}
	}
}
