package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const phcFormat = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"

type Argon2IDParameters struct {
	SaltLength uint32 // bytes
	Time       uint32 // time factor in number of iterations
	Memory     uint32 // kibibytes
	Threads    uint8  // number of threads
	KeyLength  uint32 // bytes
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
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("%w: password cannot be empty", ErrInvalidPassword)
	}
	salt, err := generateSalt(DefaultArgon2IDParameters.SaltLength)
	if err != nil {
		return "", err
	}
	hash := hashPasswordWithSaltAndParams(password, salt, DefaultArgon2IDParameters)

	encoded_salt := base64.RawStdEncoding.EncodeToString(salt)
	encoded_hash := base64.RawStdEncoding.EncodeToString(hash)
	hashedPassword := fmt.Sprintf(phcFormat,
		argon2.Version,
		DefaultArgon2IDParameters.Memory,
		DefaultArgon2IDParameters.Time,
		DefaultArgon2IDParameters.Threads,
		encoded_salt,
		encoded_hash,
	)
	return string(hashedPassword), nil
}

// CompareHashAndPassword takes a hashed password string and a password,
// hashes the password with the same parameters as the hashed password and
// compares the resulting value, returning an error if they do not match.
//
// When this function is passed an invalid hashed password string, it will
// hash the password with the default parameters to prevent an attacker from
// getting information from the timing of a login failure.
func CompareHashAndPassword(hashedPassword string, password string) error {
	params, salt, hash, err := parseArgon2IDPHC(hashedPassword)
	if err != nil {
		// The hashedPassword was not parseable, hash the password with default values
		// to spend the same amount of time.
		salt = make([]byte, params.SaltLength)
		hash = make([]byte, params.KeyLength)
	}
	newHash := hashPasswordWithSaltAndParams(password, salt, params)
	if subtle.ConstantTimeCompare(newHash, hash) == 1 {
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

// Parses a PHC string for Argon2id, and returns Argon2id parameters, the salt and the hash
func parseArgon2IDPHC(phc string) (Argon2IDParameters, []byte, []byte, error) {
	fields := strings.Split(phc, "$")
	if len(fields) != 6 {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("not enough fields")
	}
	if fields[1] != "argon2id" {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("unsupported mode: %v", fields[1])
	}
	if fields[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("unsupported version: %v", fields[2])
	}

	kvs := strings.Split(fields[3], ",")

	params := make(map[string]string)
	for _, kv := range kvs {
		parts := strings.Split(kv, "=")
		if len(parts) != 2 {
			return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("invalid parameters format: %v", parts)
		}
		params[parts[0]] = parts[1]
	}

	m, ok := params["m"]
	if !ok {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("missing memory parameter")
	}
	t, ok := params["t"]
	if !ok {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("missing time parameter")
	}
	p, ok := params["p"]
	if !ok {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("missing parallelism parameter")
	}
	memory, err := strconv.ParseUint(m, 10, 32)
	if err != nil {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("cannot parse memory to uint32: %v", err)
	}
	time, err := strconv.ParseUint(t, 10, 32)
	if err != nil {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("cannot parse time to uint32: %v", err)
	}
	threads, err := strconv.ParseUint(p, 10, 8)
	if err != nil {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("cannot parse parallelism to uint8: %v", err)
	}

	parameters := DefaultArgon2IDParameters
	parameters.Memory = uint32(memory)
	parameters.Time = uint32(time)
	parameters.Threads = uint8(threads)

	salt, err := base64.RawStdEncoding.Strict().DecodeString(fields[4])
	if err != nil {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("cannot base64 decode salt: %v", err)
	}
	hashedPassword, err := base64.RawStdEncoding.Strict().DecodeString(fields[5])
	if err != nil {
		return DefaultArgon2IDParameters, nil, nil, fmt.Errorf("cannot base64 decode hash: %v", err)
	}

	return parameters, salt, hashedPassword, nil
}
