// Package signing signs the policies the server delivers to agents (ECDSA P-256 / SHA-256, "ES256").
//
// Agents pin the public key in conf/rasp.properties (policy.public_key) and reject any config whose
// signature does not verify, so a compromised network path, proxy or a tampered local cache cannot
// switch an agent to "off" or inject rules. The HMAC on the transport authenticates the agent to the
// server; this signature authenticates the policy to the agent.
package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const Alg = "ES256"

type Signer struct {
	key    *ecdsa.PrivateKey
	pubDER []byte
	keyID  string
}

// LoadOrCreate reads a PKCS#8 PEM private key from path, generating one (mode 0600) when the file does
// not exist. The public key is also written to path + ".pub" for distribution to hosts.
func LoadOrCreate(path string) (s *Signer, created bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return nil, false, gerr
		}
		der, merr := x509.MarshalPKCS8PrivateKey(k)
		if merr != nil {
			return nil, false, merr
		}
		f, oerr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if oerr != nil {
			return nil, false, oerr
		}
		werr := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return nil, false, werr
		}
		b, created = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), true
	} else if err != nil {
		return nil, false, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, false, fmt.Errorf("%s: expected a PKCS#8 \"PRIVATE KEY\" PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, false, err
	}
	k, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, false, fmt.Errorf("%s: signing key must be ECDSA P-256", path)
	}
	s, err = fromKey(k)
	if err != nil {
		return nil, false, err
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: s.pubDER})
	_ = os.WriteFile(path+".pub", pub, 0o644)
	return s, created, nil
}

func fromKey(k *ecdsa.PrivateKey) (*Signer, error) {
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &Signer{key: k, pubDER: der, keyID: hex.EncodeToString(sum[:8])}, nil
}

// KeyID is a short fingerprint of the public key (first 8 bytes of SHA-256 over the SPKI DER).
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey returns the base64 SPKI DER, the value agents put in policy.public_key.
func (s *Signer) PublicKey() string { return base64.StdEncoding.EncodeToString(s.pubDER) }

// PublicPEM returns the public key as PEM.
func (s *Signer) PublicPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: s.pubDER}))
}

// Sign returns the base64 ASN.1 DER signature over payload (verifiable with Java "SHA256withECDSA").
func (s *Signer) Sign(payload []byte) (string, error) {
	sum := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, sum[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify checks a signature produced by Sign (used by tests and tooling).
func (s *Signer) Verify(payload []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(&s.key.PublicKey, sum[:], sig)
}
