// Package ghapp mints short-lived GitHub App installation tokens and serves
// them to git via the credential helper protocol.
package ghapp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

const (
	// JWTLifetime is how long the app JWT is valid. GitHub allows at most 10 minutes.
	JWTLifetime = 9 * time.Minute
	// JWTBackdate protects against clock skew (GitHub recommends backdating iat).
	JWTBackdate = 60 * time.Second
)

// ParsePrivateKey parses an RSA private key in PKCS#1 or PKCS#8 PEM form
// (GitHub downloads PKCS#1). Error messages never include key material.
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("private key is not valid PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("private key is not a valid RSA PKCS#1/PKCS#8 key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}
	return rk, nil
}

// SignJWT creates an RS256 JWT identifying the app. iat is backdated and exp
// is at most 10 minutes after the real issue time.
func SignJWT(key *rsa.PrivateKey, appID string, now time.Time) (string, error) {
	if appID == "" {
		return "", errors.New("app ID is empty")
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-JWTBackdate).Unix(),
		"exp": now.Add(JWTLifetime).Unix(),
		"iss": appID,
	})
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}
