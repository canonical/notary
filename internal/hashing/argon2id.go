package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/argon2"
)

const phcEncFormat = "$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s"

var phcDecFormat = strings.ReplaceAll(phcEncFormat, "$", " ")

type Argon2IDParameters struct {
	SaltLength uint32 // bytes
	Time       uint32 // time factor in number of iterations
	Memory     uint32 // kibibytes
	Threads    uint8  // number of threads
	KeyLength  uint32 // bytes
}

type phcEncoding struct {
	params Argon2IDParameters
	salt   []byte
	key    []byte
}

func (e *phcEncoding) String() string {
	return fmt.Sprintf(phcEncFormat,
		e.params.Memory,
		e.params.Time,
		e.params.Threads,
		base64.RawStdEncoding.EncodeToString(e.salt),
		base64.RawStdEncoding.EncodeToString(e.key),
	)
}

// Default parameters recommended by OWASP
var DefaultArgon2IDParameters = Argon2IDParameters{
	SaltLength: 16,
	Time:       2,
	Memory:     19 * 1024, // 19 MiB
	Threads:    1,
	KeyLength:  32,
}

var ErrInvalidPassword = errors.New("invalid password")

// Takes the password string, makes sure it's not empty, and hashes it using argon2id
func HashPassword(password string) (string, error) {
	var err error
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("%w: password cannot be empty", ErrInvalidPassword)
	}
	encoding := phcEncoding{params: DefaultArgon2IDParameters}
	encoding.salt, err = generateSalt(DefaultArgon2IDParameters.SaltLength)
	if err != nil {
		return "", err
	}
	encoding.key = hashPasswordWithSaltAndParams(password, encoding.salt, encoding.params)

	return encoding.String(), nil
}

// CompareHashAndPassword takes a hashed password string and a password,
// hashes the password with the same parameters as the hashed password and
// compares the resulting value, returning an error if they do not match.
//
// When this function is passed an invalid hashed password string, it will
// hash the password with the default parameters to prevent an attacker from
// getting information from the timing of a login failure.
func CompareHashAndPassword(hashedPassword string, password string) error {
	encoding, err := parseArgon2IDPHC(hashedPassword)
	if err != nil {
		// The hashedPassword was not parseable, hash the password with default values
		// to spend the same amount of time.
		encoding.salt = make([]byte, encoding.params.SaltLength)
		encoding.key = make([]byte, encoding.params.KeyLength)
	}
	newHash := hashPasswordWithSaltAndParams(password, encoding.salt, encoding.params)
	if subtle.ConstantTimeCompare(newHash, encoding.key) == 1 {
		return nil
	}
	return fmt.Errorf("password did not match")
}

func hashPasswordWithSaltAndParams(password string, salt []byte, params Argon2IDParameters) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.KeyLength,
	)
}

func generateSalt(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Parses a PHC string for Argon2id, and returns an encoding struct
func parseArgon2IDPHC(phc string) (phcEncoding, error) {
	var (
		encoding phcEncoding
		salt     string
		key      string
	)
	phc = strings.Replace(phc, "$", " ", 5) // There should be only 5 delimiters
	_, err := fmt.Sscanf(phc, phcDecFormat,
		&encoding.params.Memory, &encoding.params.Time,
		&encoding.params.Threads, &salt, &key,
	)
	if err != nil {
		return phcEncoding{params: DefaultArgon2IDParameters}, fmt.Errorf("cannot decode argon2 phc string: %v", err)
	}

	encoding.salt, err = base64.RawStdEncoding.Strict().DecodeString(salt)
	if err != nil {
		return phcEncoding{params: DefaultArgon2IDParameters}, fmt.Errorf("cannot base64 decode salt: %v", err)
	}
	saltLength := len(encoding.salt)
	if saltLength > math.MaxUint32 {
		return phcEncoding{params: DefaultArgon2IDParameters}, fmt.Errorf("salt too long")
	}
	encoding.params.SaltLength = uint32(saltLength)

	encoding.key, err = base64.RawStdEncoding.Strict().DecodeString(key)
	if err != nil {
		return phcEncoding{params: DefaultArgon2IDParameters}, fmt.Errorf("cannot base64 decode key: %v", err)
	}
	keyLength := len(encoding.key)
	if keyLength > math.MaxUint32 {
		return phcEncoding{params: DefaultArgon2IDParameters}, fmt.Errorf("key too long")
	}
	encoding.params.KeyLength = uint32(keyLength)

	return encoding, nil
}
