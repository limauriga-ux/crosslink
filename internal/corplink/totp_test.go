package corplink

import (
	"testing"
)

func TestTOTPFormat(t *testing.T) {
	code, err := TOTP("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Errorf("TOTP length = %d, want 6", len(code))
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("TOTP code %q contains non-digit", code)
		}
	}
}

func TestTOTPInvalidSecret(t *testing.T) {
	_, err := TOTP("not-valid!!!")
	if err == nil {
		t.Error("expected error for invalid base32")
	}
}
