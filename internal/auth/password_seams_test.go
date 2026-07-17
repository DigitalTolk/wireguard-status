package auth

import (
	"errors"
	"testing"
)

// TestHashRandFailure exercises the RNG-failure path via the randRead seam.
func TestHashRandFailure(t *testing.T) {
	orig := randRead
	t.Cleanup(func() { randRead = orig })

	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	if _, err := Hash("pw"); err == nil {
		t.Fatal("Hash should fail when the RNG fails")
	}
}

// TestParseEdgeCases covers each distinct decode/validation failure in parse.
func TestParseEdgeCases(t *testing.T) {
	cases := map[string]string{
		"wrong prefix":      "bcrypt$1$YQ$Yg",
		"wrong field count": "pbkdf2-sha256$1$YQ",
		"non-numeric iter":  "pbkdf2-sha256$x$YQ$Yg",
		"zero iter":         "pbkdf2-sha256$0$YQ$Yg",
		"negative iter":     "pbkdf2-sha256$-3$YQ$Yg",
		"bad base64 salt":   "pbkdf2-sha256$1$!!!$Yg",
		"bad base64 hash":   "pbkdf2-sha256$1$YQ$!!!",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if Valid(s) {
				t.Errorf("Valid(%q) should be false", s)
			}
			if Verify(s, "pw") {
				t.Errorf("Verify(%q) should be false", s)
			}
		})
	}
}

// TestVerifyWrongLengthHash makes sure a well-formed hash of the wrong content
// is rejected (the constant-time compare returns 0).
func TestVerifyWrongLengthHash(t *testing.T) {
	h, err := Hash("correct-horse")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if Verify(h, "battery-staple") {
		t.Error("Verify should reject the wrong password")
	}
}
