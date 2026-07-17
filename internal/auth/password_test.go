package auth

import "testing"

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := Hash("sec;ret#1")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !Valid(h) {
		t.Fatalf("Valid(%q) = false", h)
	}
	if !Verify(h, "sec;ret#1") {
		t.Errorf("Verify should accept the correct password")
	}
	if Verify(h, "wrong") {
		t.Errorf("Verify should reject a wrong password")
	}
}

func TestHashIsSaltedAndNotPlaintext(t *testing.T) {
	h1, _ := Hash("hunter2")
	h2, _ := Hash("hunter2")
	if h1 == h2 {
		t.Errorf("two hashes of the same password should differ (random salt)")
	}
	for _, h := range []string{h1, h2} {
		if got := indexOf(h, "hunter2"); got >= 0 {
			t.Errorf("hash %q must not contain the plaintext", h)
		}
	}
}

func TestValidRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "plaintext", "pbkdf2-sha256$abc$xx$yy", "bcrypt$1$a$b"} {
		if Valid(s) {
			t.Errorf("Valid(%q) should be false", s)
		}
	}
	if Verify("garbage", "x") {
		t.Errorf("Verify against garbage hash should be false")
	}
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
