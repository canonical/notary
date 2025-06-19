package encryption_backend

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/miekg/pkcs11"
	"go.uber.org/zap"
)

type fakePKCS11Provider struct {
	key []byte
	iv  []byte
}

func newfakePKCS11Provider() (*fakePKCS11Provider, error) {
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate test key: %v", err)
	}
	return &fakePKCS11Provider{key: key}, nil
}

func (m *fakePKCS11Provider) Initialize() error                { return nil }
func (m *fakePKCS11Provider) Finalize() error                  { return nil }
func (m *fakePKCS11Provider) GetSlotList(bool) ([]uint, error) { return []uint{0}, nil }
func (m *fakePKCS11Provider) OpenSession(uint, uint) (pkcs11.SessionHandle, error) {
	return pkcs11.SessionHandle(1), nil
}
func (m *fakePKCS11Provider) CloseSession(pkcs11.SessionHandle) error        { return nil }
func (m *fakePKCS11Provider) Login(pkcs11.SessionHandle, uint, string) error { return nil }
func (m *fakePKCS11Provider) Logout(pkcs11.SessionHandle) error              { return nil }
func (m *fakePKCS11Provider) FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
	return nil
}
func (m *fakePKCS11Provider) FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
	return []pkcs11.ObjectHandle{pkcs11.ObjectHandle(1)}, false, nil
}
func (m *fakePKCS11Provider) FindObjectsFinal(pkcs11.SessionHandle) error { return nil }

func (m *fakePKCS11Provider) EncryptInit(sh pkcs11.SessionHandle, mech []*pkcs11.Mechanism, obj pkcs11.ObjectHandle) error {
	if len(mech) > 0 && mech[0].Parameter != nil {
		m.iv = mech[0].Parameter
	}
	return nil
}

func (m *fakePKCS11Provider) Encrypt(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	if m.iv == nil {
		return nil, fmt.Errorf("IV not set")
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return nil, err
	}

	padding := aes.BlockSize - len(message)%aes.BlockSize
	if padding > 0 {
		message = append(message, make([]byte, padding)...)
	}

	ciphertext := make([]byte, len(message))
	mode := cipher.NewCBCEncrypter(block, m.iv)
	mode.CryptBlocks(ciphertext, message)

	return ciphertext, nil
}

func (m *fakePKCS11Provider) DecryptInit(sh pkcs11.SessionHandle, mech []*pkcs11.Mechanism, obj pkcs11.ObjectHandle) error {
	if len(mech) > 0 && mech[0].Parameter != nil {
		m.iv = mech[0].Parameter
	}
	return nil
}

func (m *fakePKCS11Provider) Decrypt(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	if m.iv == nil {
		return nil, fmt.Errorf("IV not set")
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return nil, err
	}

	if len(message)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(message))
	mode := cipher.NewCBCDecrypter(block, m.iv)
	mode.CryptBlocks(plaintext, message)

	for i := len(plaintext) - 1; i >= 0; i-- {
		if plaintext[i] != 0 {
			return plaintext[:i+1], nil
		}
	}
	return plaintext, nil
}

func TestPKCS11BackendEncryptDecryptSuccess(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
	}{
		{
			name:    "normal message",
			message: []byte("test data to encrypt and decrypt"),
		},
		{
			name:    "short message",
			message: []byte("short"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtx, err := newfakePKCS11Provider()
			if err != nil {
				t.Fatalf("Failed to create mock context: %v", err)
			}
			logger, err := zap.NewDevelopment()
			if err != nil {
				t.Fatalf("Failed to create logger: %v", err)
			}

			backend := &PKCS11Backend{
				pkcs11Provider: mockCtx,
				pin:            "1234",
				keyID:          1,
				logger:         logger,
			}

			ciphertext1, err := backend.Encrypt(tt.message)
			if err != nil {
				t.Fatalf("Expected encryption to succeed, got error: %v", err)
			}

			if len(ciphertext1) < 16 {
				t.Fatal("Expected ciphertext to be at least 16 bytes long, too short to contain the IV and the message")
			}
			if len(ciphertext1[16:])%aes.BlockSize != 0 {
				t.Fatal("Expected ciphertext to be block-aligned")
			}

			ciphertext2, err := backend.Encrypt(tt.message)
			if err != nil {
				t.Fatalf("Expected second encryption to succeed, got error: %v", err)
			}
			if bytes.Equal(ciphertext1[:16], ciphertext2[:16]) {
				t.Fatal("Expected IVs to be different between calls")
			}
			if bytes.Equal(ciphertext1, ciphertext2) {
				t.Fatal("Expected ciphertexts to be different due to different IVs")
			}

			decrypted, err := backend.Decrypt(ciphertext1)
			if err != nil {
				t.Fatalf("Expected decryption to succeed, got error: %v", err)
			}
			if !bytes.Equal(tt.message, decrypted) {
				t.Fatalf("Expected decrypted data to match original.\nExpected: %q\nGot: %q", tt.message, decrypted)
			}
		})
	}
}

func TestPKCS11BackendDecryptInvalidInput(t *testing.T) {
	mockCtx, err := newfakePKCS11Provider()
	if err != nil {
		t.Fatalf("Failed to create mock context: %v", err)
	}
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	backend := &PKCS11Backend{
		pkcs11Provider: mockCtx,
		pin:            "1234",
		keyID:          1,
		logger:         logger,
	}

	invalidInput := []byte("A")
	expectedError := "invalid ciphertext: too short to contain IV"

	_, err = backend.Decrypt(invalidInput)
	if err == nil {
		t.Fatal("Expected decryption to fail but it succeeded")
	}
	if err.Error() != expectedError {
		t.Errorf("Expected error message %q, got %q", expectedError, err.Error())
	}
}
