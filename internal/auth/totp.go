package auth

import (
	"time"

	"github.com/yongjohnlee80/golib/auth/totp"
)

// The second factor's arithmetic is golib's (D3): RFC 6238, SHA-1, six digits,
// 30 seconds, the authenticator apps' common ground.

func totpNewSeed() ([]byte, error)                    { return totp.NewSecret() }
func totpEncode(seed []byte) string                   { return totp.Encode(seed) }
func totpURI(issuer, account string, s []byte) string { return totp.URI(issuer, account, s) }

// totpVerify accepts a code once: ±1 step, never the last accepted one or
// older. A user who never used a code has lastStep 0, which no real step is.
func totpVerify(seed []byte, code string, at time.Time, lastStep int64) (int64, bool) {
	if lastStep == 0 {
		lastStep = -1
	}
	return totp.Verify(seed, code, at, lastStep)
}

func totpRecoveryCodes(n int) ([]string, error) { return totp.RecoveryCodes(n) }

// totpNormRecovery is a recovery code as typed, made comparable: "" for one
// that cannot be one.
func totpNormRecovery(code string) string {
	n, err := totp.NormalizeRecoveryCode(code)
	if err != nil {
		return ""
	}
	return n
}
