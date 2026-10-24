package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// UserStore holds usernames and their password hashes. It is read once at
// start-up and never modified, so it is safe for concurrent use.
type UserStore struct {
	hashes map[string]string

	// dummyHash is checked when the username does not exist, so a failed
	// login costs the same time whether the user exists or not.
	dummyHash string
}

// LoadUsers reads a JSON object of the form {"username": "<hash>", ...}.
func LoadUsers(path string) (*UserStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read users file: %w", err)
	}
	var hashes map[string]string
	if err := json.Unmarshal(data, &hashes); err != nil {
		return nil, fmt.Errorf("parse users file %s: %w", path, err)
	}
	return NewUserStore(hashes)
}

// NewUserStore validates every hash and prepares the dummy hash.
func NewUserStore(hashes map[string]string) (*UserStore, error) {
	if len(hashes) == 0 {
		return nil, errors.New("no users configured")
	}
	iterations := 0
	for name, hash := range hashes {
		n, _, _, err := parseHash(hash)
		if name == "" || err != nil {
			return nil, fmt.Errorf("user %q: %w", name, errBadHash)
		}
		iterations = max(iterations, n)
	}
	// Use the highest real cost, so the dummy check is never faster than a real one.
	dummy, err := HashPassword("not-a-real-password", iterations)
	if err != nil {
		return nil, err
	}
	return &UserStore{hashes: hashes, dummyHash: dummy}, nil
}

// Len returns the number of configured users.
func (s *UserStore) Len() int { return len(s.hashes) }

// Authenticate reports whether username exists and password is correct.
func (s *UserStore) Authenticate(username, password string) bool {
	hash, ok := s.hashes[username]
	if !ok {
		// Do the same slow work as for a real user, then fail. Otherwise an
		// attacker could find valid usernames by timing the responses.
		CheckPassword(password, s.dummyHash)
		return false
	}
	return CheckPassword(password, hash)
}
