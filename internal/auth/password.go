// Package auth hashes and verifies the basic-auth password so the config never
// stores it in plaintext. The format is a self-describing PHC-style string:
//
//	pbkdf2-sha256$<iterations>$<base64-salt>$<base64-hash>
//
// PBKDF2-HMAC-SHA256 is implemented on top of the standard library only.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const (
	prefix      = "pbkdf2-sha256"
	defaultIter = 210000
	saltLen     = 16
	keyLen      = 32
)

var enc = base64.RawStdEncoding

// Hash returns an encoded PBKDF2 hash of plain using a fresh random salt.
func Hash(plain string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2([]byte(plain), salt, defaultIter, keyLen)
	return fmt.Sprintf("%s$%d$%s$%s", prefix, defaultIter, enc.EncodeToString(salt), enc.EncodeToString(dk)), nil
}

// Valid reports whether s is a well-formed encoded hash.
func Valid(s string) bool {
	_, _, _, err := parse(s)
	return err == nil
}

// Verify reports whether plain matches the encoded hash in constant time.
func Verify(encoded, plain string) bool {
	iter, salt, want, err := parse(encoded)
	if err != nil {
		return false
	}
	got := pbkdf2([]byte(plain), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func parse(s string) (iter int, salt, hash []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 4 || parts[0] != prefix {
		return 0, nil, nil, fmt.Errorf("not a %s hash", prefix)
	}
	iter, err = strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return 0, nil, nil, fmt.Errorf("invalid iteration count")
	}
	if salt, err = enc.DecodeString(parts[2]); err != nil {
		return 0, nil, nil, fmt.Errorf("invalid salt: %w", err)
	}
	if hash, err = enc.DecodeString(parts[3]); err != nil {
		return 0, nil, nil, fmt.Errorf("invalid hash: %w", err)
	}
	return iter, salt, hash, nil
}

// pbkdf2 implements PBKDF2-HMAC-SHA256 (RFC 8018) using only the stdlib.
func pbkdf2(password, salt []byte, iter, dkLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	blocks := (dkLen + hLen - 1) / hLen
	dk := make([]byte, 0, blocks*hLen)
	idx := make([]byte, 4)
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		binary.BigEndian.PutUint32(idx, uint32(block))
		prf.Write(salt)
		prf.Write(idx)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:dkLen]
}
