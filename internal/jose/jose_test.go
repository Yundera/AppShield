package jose

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type claims struct {
	Sub string `json:"sub"`
	Iss string `json:"iss"`
	Exp int64  `json:"exp"`
}

func testKey(t *testing.T) *Key {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignVerifyRoundTrip(t *testing.T) {
	k := testKey(t)
	want := claims{Sub: "user-1", Iss: "https://app.example.com", Exp: 1_800_000_000}

	tok, err := k.Sign("at+jwt", want)
	if err != nil {
		t.Fatal(err)
	}
	hdr, payload, err := Verify(tok, &k.Private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Alg != "RS256" || hdr.Typ != "at+jwt" || hdr.Kid != k.Kid {
		t.Errorf("header = %+v", hdr)
	}
	var got claims
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("claims = %+v, want %+v", got, want)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	k, other := testKey(t), testKey(t)
	tok, _ := k.Sign("JWT", claims{Sub: "x"})
	if _, _, err := Verify(tok, &other.Private.PublicKey); err == nil {
		t.Error("a token signed by a different key verified")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	k := testKey(t)
	tok, _ := k.Sign("JWT", claims{Sub: "alice"})
	parts := strings.Split(tok, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`))
	if _, _, err := Verify(strings.Join(parts, "."), &k.Private.PublicKey); err == nil {
		t.Error("a tampered payload verified")
	}
}

// The algorithm is pinned, not taken from the token.
func TestVerifyRejectsAlgSubstitution(t *testing.T) {
	k := testKey(t)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`))

	for _, alg := range []string{"none", "HS256", "RS512"} {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `","typ":"JWT"}`))
		if _, _, err := Verify(hdr+"."+payload+".", &k.Private.PublicKey); err == nil {
			t.Errorf("alg=%q was accepted", alg)
		}
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	k := testKey(t)
	for _, tok := range []string{"", "a", "a.b", "a.b.c.d", "!!.??.##"} {
		if _, _, err := Verify(tok, &k.Private.PublicKey); err == nil {
			t.Errorf("malformed token %q verified", tok)
		}
	}
}

func TestPublicJWKHasNoPrivateMembers(t *testing.T) {
	k := testKey(t)
	pub := k.PublicJWK()
	if pub.D != "" || pub.P != "" || pub.Q != "" || pub.Dp != "" || pub.Dq != "" || pub.Qi != "" {
		t.Errorf("public JWK leaks private members: %+v", pub)
	}
	if pub.N == "" || pub.E == "" || pub.Kid != k.Kid {
		t.Errorf("public JWK is missing what a verifier needs: %+v", pub)
	}

	// It must still be usable as a verification key.
	rsaPub, err := PublicKeyFromJWK(pub)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := k.Sign("JWT", claims{Sub: "x"})
	if _, _, err := Verify(tok, rsaPub); err != nil {
		t.Errorf("public JWK could not verify our own token: %v", err)
	}
}

func TestJWKSDocumentShape(t *testing.T) {
	k := testKey(t)
	blob, err := json.Marshal(k.PublicJWKS())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(doc.Keys))
	}
	for _, member := range []string{"kty", "n", "e", "kid", "alg", "use"} {
		if _, ok := doc.Keys[0][member]; !ok {
			t.Errorf("JWKS key is missing %q", member)
		}
	}
	for _, member := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, ok := doc.Keys[0][member]; ok {
			t.Errorf("JWKS key leaks private member %q", member)
		}
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	k := testKey(t)
	blob, err := json.Marshal(k.MarshalJWK())
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kid != k.Kid {
		t.Errorf("kid = %q, want %q", got.Kid, k.Kid)
	}
	if got.Private.N.Cmp(k.Private.N) != 0 || got.Private.D.Cmp(k.Private.D) != 0 {
		t.Error("key material changed across the round trip")
	}
}

// The migration case: an existing /data/oauth/jwks.json written by 2.x's `jose`
// must load, or the broker refuses to start on upgrade. 2.x wrote the key
// wrapped in a set, `{"keys":[jwk]}` — the fixture keeps that exact shape.
func TestParsesGenuineV2JWKS(t *testing.T) {
	blob, err := os.ReadFile("testdata/v2-jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseKey(blob)
	if err != nil {
		t.Fatalf("a real 2.x jwks.json failed to parse: %v", err)
	}
	if k.Kid == "" {
		t.Error("kid was not carried over")
	}
	if bits := k.Private.N.BitLen(); bits < 2000 {
		t.Errorf("modulus is %d bits, want ~2048", bits)
	}

	// The parsed key must actually work for signing and verification.
	tok, err := k.Sign("at+jwt", claims{Sub: "user-1", Iss: "https://beacon.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(tok, &k.Private.PublicKey); err != nil {
		t.Errorf("token signed with the migrated key did not verify: %v", err)
	}
}

// Never fall back to generating a key: that would rotate the signing key and
// 401 every token in flight.
func TestParseKeyFailsClosed(t *testing.T) {
	cases := map[string]string{
		"not json":     `{not json`,
		"empty object": `{}`,
		"wrong kty":    `{"kty":"EC","n":"AA","e":"AQAB","d":"AA","p":"AA","q":"AA"}`,
		"public only":  `{"kty":"RSA","n":"AA","e":"AQAB"}`,
		"bad base64":   `{"kty":"RSA","n":"!!!","e":"AQAB","d":"AA","p":"AA","q":"AA"}`,
		"inconsistent": `{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB","p":"AQAB","q":"AQAB"}`,
		"empty set":    `{"keys":[]}`,
		"two keys":     `{"keys":[{"kty":"RSA"},{"kty":"RSA"}]}`,
		"public set":   `{"keys":[{"kty":"RSA","n":"AA","e":"AQAB"}]}`,
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKey([]byte(blob)); err == nil {
				t.Error("expected an error rather than a silently regenerated key")
			}
		})
	}
}

func TestParseKeyAcceptsPaddedBase64(t *testing.T) {
	k := testKey(t)
	jwk := k.MarshalJWK()
	// Some producers emit standard padded base64url; be liberal on the way in.
	jwk.N = base64.URLEncoding.EncodeToString(k.Private.N.Bytes())
	blob, _ := json.Marshal(jwk)
	if _, err := ParseKey(blob); err != nil {
		t.Errorf("padded base64url was rejected: %v", err)
	}
}

func TestGeneratedKeysAreDistinct(t *testing.T) {
	a, b := testKey(t), testKey(t)
	if a.Kid == b.Kid {
		t.Error("two generated keys share a kid")
	}
	if a.Private.N.Cmp(b.Private.N) == 0 {
		t.Error("two generated keys share a modulus")
	}
}

func TestSignIsDeterministicallyVerifiableAcrossKeySizes(t *testing.T) {
	// A smaller key still has to work: the fixture's size is not load-bearing.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k := &Key{Private: priv, Kid: "test"}
	tok, err := k.Sign("JWT", claims{Sub: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(tok, &priv.PublicKey); err != nil {
		t.Fatal(err)
	}
}
