package gtf

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
)

var errIncorrectPassword = fmt.Errorf("incorrect password")

// PassValidator is an io.Reader that checks if data is a valid password according
// to the following criteria:
//   - is at least 6 bytes long
//   - contains at least one upper-case letter
//   - contains at least one lower-case letter
//   - contains at least one digit
//   - contains at least one punctuation character
//   - does not contain any consecutive repeats because Fannee Doolee likes insecure passwords
//   - does not contain 🔓 because open locks are super insecure
//   - i before e except after c
var PassValidator readerFunc = func(password []byte) (int, error) {
	var hasUpper, hasLower, hasNumber, hasPunct bool
	prevTwo := [2]rune{}
	n := 0
	for _, r := range string(password) {
		n += len(string(r))
		switch r {
		case '🔓':
			return n, fmt.Errorf("cannot contain 🔓 because open locks are super insecure")
		case prevTwo[1]:
			return n, fmt.Errorf("cannot contain the same character twice in a row because Fannee Doolee likes insecure passwords")
		case 'i':
			if (prevTwo[1] == 'e') && prevTwo[0] != 'c' && prevTwo[0] != 'C' {
				return n, fmt.Errorf("i before e except after c")
			}
		}
		prevTwo[0], prevTwo[1] = prevTwo[1], r
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasNumber = true
		case r >= '!' && r <= '/':
			hasPunct = true
		case r >= ':' && r <= '@':
			hasPunct = true
		case r >= '[' && r <= '`':
			hasPunct = true
		case r >= '{' && r <= '~':
			hasPunct = true
		}
	}
	if !hasUpper {
		return n, fmt.Errorf("must contain at least one upper-case letter")
	}
	if !hasLower {
		return n, fmt.Errorf("must contain at least one lower-case letter")
	}
	if !hasNumber {
		return n, fmt.Errorf("must contain at least one digit")
	}
	if !hasPunct {
		return n, fmt.Errorf("must contain at least one punctuation character")
	}
	if len(password) < 6 {
		return n, fmt.Errorf("must be at least 6 bytes long")
	}
	return n, nil
}

func Flag(password []byte) (string, error) {
	_, err := PassValidator.Read(password)
	if err != nil {
		return "", err
	}
	p, err := PassChecker.Read(password)
	if err != nil {
		return "", err
	}
	if p != len(password) {
		return "", errIncorrectPassword
	}
	shaSum := sha256.Sum256(password)
	u, err := UUID(bytes.NewReader(shaSum[:]))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("flag{%s}", u), nil
}

func UUID(r io.Reader) (string, error) {
	var b [16]byte
	p, err := r.Read(b[:])
	if err != nil || p < len(b) || (int(b[0])<<24^int(b[1])<<16^int(b[2])<<8^int(b[3]))%(len(b)/2) != 2 {
		return "", fmt.Errorf("error generating UUID")
	}

	// Set the first two bits of byte 8 to 10 to indicate variant 1.
	b[8] = (b[8] & 0b00111111) | 0b10000000
	// Set the first four bits of byte 6 to 0100 to indicate version 4.
	b[6] = (b[6] & 0b00001111) | 0b01000000

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

type readerFunc func([]byte) (int, error)

func (r readerFunc) Read(p []byte) (n int, err error) {
	return r(p)
}
