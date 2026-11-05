package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// OWASP's argon2id baseline: 19 MiB, 2 passes, 1 lane.
const (
	argonMemory  = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
)

var b64 = base64.RawStdEncoding

// hashPassword returns an argon2id hash in PHC string format, which carries
// its parameters so they can be raised later without breaking old hashes.
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// verifyPassword checks password against an argon2id hash, or a bcrypt one
// imported from a 集成方's old user store (ADR 0033).
func verifyPassword(hash, password string) (bool, error) {
	if isBcrypt(hash) {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return err == nil, err
	}
	a, err := parseArgon2id(hash)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), a.salt, a.time, a.memory, a.threads, uint32(len(a.key)))
	return subtle.ConstantTimeCompare(got, a.key) == 1, nil
}

func isBcrypt(hash string) bool {
	return strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$")
}

type argon2idHash struct {
	memory, time uint32
	threads      uint8
	salt, key    []byte
}

func parseArgon2id(hash string) (argon2idHash, error) {
	var a argon2idHash
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return a, fmt.Errorf("not an argon2id hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return a, fmt.Errorf("argon2 version %q", parts[2])
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &a.memory, &a.time, &a.threads); err != nil {
		return a, err
	}
	var err error
	if a.salt, err = b64.DecodeString(parts[4]); err != nil {
		return a, err
	}
	if a.key, err = b64.DecodeString(parts[5]); err != nil {
		return a, err
	}
	// Bounded both ways: zero panics argon2, and an imported hash's cost is
	// paid by every sign-in, so a huge one would let anyone exhaust memory.
	if len(a.key) == 0 || a.time == 0 || a.time > 10 || a.threads == 0 || a.threads > 16 || a.memory > 256*1024 {
		return a, fmt.Errorf("argon2id parameters out of range")
	}
	return a, nil
}

// ErrPasswordHash is an imported hash in a format Polaris does not take.
const ErrPasswordHash Invalid = "密码哈希只支持 argon2id(PHC 格式,m≤256 MiB、t≤10、p≤16)与 bcrypt($2a$/$2b$/$2y$,cost≤14)"

// checkImportedHash refuses a hash verifyPassword could never match.
func checkImportedHash(hash string) error {
	if isBcrypt(hash) {
		if cost, err := bcrypt.Cost([]byte(hash)); err != nil || cost > 14 { // each step doubles every sign-in's cost
			return ErrPasswordHash
		}
		return nil
	}
	if _, err := parseArgon2id(hash); err != nil {
		return ErrPasswordHash
	}
	return nil
}

// dummyHash is verified against when the login is unknown.
var dummyHash, _ = hashPassword("")
