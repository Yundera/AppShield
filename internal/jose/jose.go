// Package jose implements the small slice of JOSE the gate actually needs:
// RS256 compact JWS, and the JWK/JWKS encoding of an RSA key.
//
// A full JOSE library would be the largest dependency in the binary, and the
// gate uses exactly one algorithm with exactly one key. The JWK encoding is
// deliberately byte-compatible with what `jose`'s exportJWK wrote in 2.x, and
// ParseKey also accepts the {"keys":[…]} set 2.x wrapped it in on disk, so an
// existing /data/oauth/jwks.json keeps working and the signing key does not
// rotate on upgrade.
package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// JWK is one key in JWK form. Private members are omitted when absent, which
// is what turns a private key into its public counterpart.
type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	D   string `json:"d,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
	Dp  string `json:"dp,omitempty"`
	Dq  string `json:"dq,omitempty"`
	Qi  string `json:"qi,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// JWKS is a key set document.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Key is an RSA signing key with its key id.
type Key struct {
	Private *rsa.PrivateKey
	Kid     string
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64Int(i *big.Int) string { return b64(i.Bytes()) }

func decodeInt(s string) (*big.Int, error) {
	// Accept padded base64url too: not every producer strips padding.
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

// GenerateKey creates a fresh 2048-bit signing key with a random 8-byte kid,
// matching what 2.x generated.
func GenerateKey() (*Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kidBytes := make([]byte, 8)
	if _, err := rand.Read(kidBytes); err != nil {
		return nil, err
	}
	return &Key{Private: priv, Kid: fmt.Sprintf("%x", kidBytes)}, nil
}

// MarshalJWK renders the private key as a JWK, in the same shape 2.x wrote.
func (k *Key) MarshalJWK() JWK {
	p := k.Private
	p.Precompute()
	jwk := JWK{
		Kty: "RSA",
		N:   b64Int(p.N),
		E:   b64(bigEndianExponent(p.E)),
		D:   b64Int(p.D),
		Use: "sig",
		Alg: "RS256",
		Kid: k.Kid,
	}
	if len(p.Primes) >= 2 {
		jwk.P, jwk.Q = b64Int(p.Primes[0]), b64Int(p.Primes[1])
	}
	if p.Precomputed.Dp != nil {
		jwk.Dp, jwk.Dq = b64Int(p.Precomputed.Dp), b64Int(p.Precomputed.Dq)
		jwk.Qi = b64Int(p.Precomputed.Qinv)
	}
	return jwk
}

// PublicJWK strips every private member. This is what /jwks publishes and what
// local token verification uses.
func (k *Key) PublicJWK() JWK {
	j := k.MarshalJWK()
	j.D, j.P, j.Q, j.Dp, j.Dq, j.Qi = "", "", "", "", "", ""
	return j
}

// PublicJWKS renders the single-key set served at the jwks endpoint.
func (k *Key) PublicJWKS() JWKS { return JWKS{Keys: []JWK{k.PublicJWK()}} }

func bigEndianExponent(e int) []byte {
	b := big.NewInt(int64(e)).Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	return b
}

// ParseKey reads a private key from JWK JSON: either a bare JWK (what 3.x
// writes) or a JWKS holding exactly one key (what every 2.x wrote).
//
// It returns an error rather than falling back to generating a new key: a
// parse bug that silently rotated the signing key would 401 every live access
// token and break every client with a cached JWKS.
func ParseKey(raw []byte) (*Key, error) {
	var doc struct {
		JWK
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("jwks.json is not valid JSON: %w", err)
	}
	jwk := doc.JWK
	if doc.Keys != nil {
		// Several keys would mean guessing which one signed the live tokens.
		if len(doc.Keys) != 1 {
			return nil, fmt.Errorf("jwks.json holds %d keys, want exactly 1", len(doc.Keys))
		}
		jwk = doc.Keys[0]
	}
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type %q, want RSA", jwk.Kty)
	}
	if jwk.D == "" || jwk.P == "" || jwk.Q == "" {
		return nil, errors.New("jwks.json does not contain a private key")
	}
	n, err := decodeInt(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("modulus: %w", err)
	}
	e, err := decodeInt(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("exponent: %w", err)
	}
	d, err := decodeInt(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("private exponent: %w", err)
	}
	p, err := decodeInt(jwk.P)
	if err != nil {
		return nil, fmt.Errorf("prime p: %w", err)
	}
	q, err := decodeInt(jwk.Q)
	if err != nil {
		return nil, fmt.Errorf("prime q: %w", err)
	}
	if !e.IsInt64() || e.Int64() > (1<<31-1) {
		return nil, errors.New("exponent out of range")
	}

	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	// Recompute rather than trusting dp/dq/qi from the file, and validate.
	priv.Precompute()
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("key is inconsistent: %w", err)
	}
	return &Key{Private: priv, Kid: jwk.Kid}, nil
}

// PublicKeyFromJWK builds a verification key from a public JWK.
func PublicKeyFromJWK(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type %q", jwk.Kty)
	}
	n, err := decodeInt(jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := decodeInt(jwk.E)
	if err != nil {
		return nil, err
	}
	if !e.IsInt64() || e.Int64() > (1<<31-1) {
		return nil, errors.New("exponent out of range")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// Sign produces a compact RS256 JWS. typ sets the header's typ member —
// "JWT" for id tokens, "at+jwt" for access tokens.
func (k *Key) Sign(typ string, claims any) (string, error) {
	hdr, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid,omitempty"`
	}{Alg: "RS256", Typ: typ, Kid: k.Kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(hdr) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.Private, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

// Header is the decoded protected header of a compact JWS.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Verify checks an RS256 compact JWS against pub and returns the raw payload.
//
// The algorithm is pinned rather than taken from the token, so an attacker
// cannot downgrade to "none" or to an HMAC keyed by the public key.
func Verify(token string, pub *rsa.PublicKey) (Header, []byte, error) {
	var hdr Header
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return hdr, nil, errors.New("not a compact JWS")
	}
	rawHdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return hdr, nil, errors.New("malformed header")
	}
	if err := json.Unmarshal(rawHdr, &hdr); err != nil {
		return hdr, nil, errors.New("malformed header")
	}
	if hdr.Alg != "RS256" {
		return hdr, nil, fmt.Errorf("unsupported alg %q", hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return hdr, nil, errors.New("malformed signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return hdr, nil, errors.New("bad signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return hdr, nil, errors.New("malformed payload")
	}
	return hdr, payload, nil
}
