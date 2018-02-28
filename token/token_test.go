package token

import "testing"

func TestVerify(t *testing.T) {
	validSecrets := []string{
		"JBSWY3DPEHPK3PXP",
		"HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
		"MZXW6CQ=", // With optional, discouraged, padding
	}
	invalidSecrets := []string{
		"hi",
		"",
	}

	for _, secret := range validSecrets {
		if err := Verify(secret); err != nil {
			t.Errorf("%q should be valid secret, got err: %v", secret, err)
		}
	}

	for _, secret := range invalidSecrets {
		if err := Verify(secret); err == nil {
			t.Errorf("%q should be invalid secret; got no err", secret)
		}
	}

}
