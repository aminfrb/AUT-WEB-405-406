package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Passwords are never stored in plain text. We store a PBKDF2-HMAC-SHA256
// hash in this self-describing format:
//
//	pbkdf2-sha256$<iterations>$<salt, base64>$<derived key, base64>
//
// Keeping the iteration count inside the string means we can raise the cost
// later without invalidating hashes that already exist.
const (
	hashScheme = "pbkdf2-sha256"

	// DefaultIterations follows the OWASP Password Storage Cheat Sheet value
	// for PBKDF2-HMAC-SHA256. The high count makes guessing slow on purpose.
	DefaultIterations = 600_000

	saltLength = 16 // bytes; a random salt makes equal passwords hash differently
	keyLength  = 32 // bytes of derived key
)

var errBadHash = errors.New("password hash has an unknown format")

// HashPassword derives a storable hash from password with a fresh random salt.
func HashPassword(password string, iterations int) (string, error) {
	if iterations < 1 {
		return "", errors.New("iterations must be positive")
	}
	salt := make([]byte, saltLength)
	rand.Read(salt) // crypto/rand.Read never fails since Go 1.24
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLength)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", hashScheme, iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// CheckPassword reports whether password matches the stored hash.
func CheckPassword(password, encoded string) bool {
	iterations, salt, want, err := parseHash(encoded)
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(want))
	// ConstantTimeCompare takes the same time whether the first or the last
	// byte differs, so timing does not reveal how close a guess was.
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// parseHash splits an encoded hash into its parts.
func parseHash(encoded string) (iterations int, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return 0, nil, nil, errBadHash
	}
	iterations, err = strconv.Atoi(parts[1])
	if err != nil || iterations < 1 {
		return 0, nil, nil, errBadHash
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return 0, nil, nil, errBadHash
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(key) == 0 {
		return 0, nil, nil, errBadHash
	}
	return iterations, salt, key, nil
}
