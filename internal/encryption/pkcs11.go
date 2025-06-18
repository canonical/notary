package encryption

import (
	"crypto/rand"
	"fmt"

	"github.com/miekg/pkcs11"
	"go.uber.org/zap"
)

// PKCS11Backend implements EncryptionBackend using the PKCS11 protocol for HSMs.
type PKCS11Backend struct {
	ctx    *pkcs11.Ctx
	pin    string
	keyID  uint16
	logger *zap.Logger
}

const ivSize = 16 // bytes

// NewPKCS11Backend creates a new PKCS11Backend.
func NewPKCS11Backend(libPath string, pin string, keyID uint16, logger *zap.Logger) (*PKCS11Backend, error) {
	ctx := pkcs11.New(libPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library at %s", libPath)
	}

	return &PKCS11Backend{
		ctx:    ctx,
		pin:    pin,
		keyID:  keyID,
		logger: logger,
	}, nil
}

// Encrypt encrypts the plaintext using AES-CBC algorithm.
func (h *PKCS11Backend) Encrypt(data []byte) ([]byte, error) {
	session, key, err := h.connectToBackend()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to backend: %w", err)
	}
	defer func() {
		if cleanupErr := h.cleanupSession(session); cleanupErr != nil {
			h.logger.Error("Error during cleanup of PKCS11 resources after encryption", zap.Error(cleanupErr))
		}
	}()

	iv, err := generateRandomIV()
	if err != nil {
		return nil, err
	}

	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)

	if err := h.ctx.EncryptInit(session, []*pkcs11.Mechanism{mech}, key); err != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}

	ciphertext, err := h.ctx.Encrypt(session, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Prepend IV to ciphertext
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:ivSize], iv)
	copy(result[ivSize:], ciphertext)

	return result, nil
}

// Decrypt decrypts the ciphertext using AES-CBC algorithm.
// The ciphertext is expected to contain the IV at the beginning.
func (h *PKCS11Backend) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < ivSize {
		return nil, fmt.Errorf("invalid ciphertext: too short to contain IV")
	}

	// Extract IV from the start of the combined data
	iv := ciphertext[:ivSize]
	ciphertext = ciphertext[ivSize:]

	session, key, err := h.connectToBackend()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to backend: %w", err)
	}
	defer func() {
		if cleanupErr := h.cleanupSession(session); cleanupErr != nil {
			h.logger.Error("Error during cleanup of PKCS11 resources after decryption", zap.Error(cleanupErr))
		}
	}()

	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)

	if err := h.ctx.DecryptInit(session, []*pkcs11.Mechanism{mech}, key); err != nil {
		return nil, fmt.Errorf("failed to initialize decryption: %w", err)
	}

	plaintext, err := h.ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return plaintext, nil
}

func (h *PKCS11Backend) findKey(session pkcs11.SessionHandle, id uint16) (pkcs11.ObjectHandle, error) {
	keyIDBytes := []byte{byte(id >> 8), byte(id & 0xff)}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyIDBytes),
	}

	if err := h.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("failed to initialize object search: %w", err)
	}
	objects, _, err := h.ctx.FindObjects(session, 1)
	if err != nil || len(objects) == 0 {
		return 0, fmt.Errorf("failed to find objects: %w", err)
	}
	if err := h.ctx.FindObjectsFinal(session); err != nil {
		return 0, fmt.Errorf("failed to finalize object search: %w", err)
	}
	return objects[0], nil
}

// cleanupSession performs cleanup of an active session
func (h *PKCS11Backend) cleanupSession(session pkcs11.SessionHandle) error {
	if err := h.ctx.Logout(session); err != nil {
		return err
	}
	if err := h.ctx.CloseSession(session); err != nil {
		return err
	}
	if err := h.ctx.Finalize(); err != nil {
		return err
	}
	return nil
}

// cleanupInitialization performs cleanup of just the initialization
func (h *PKCS11Backend) cleanupInitialization() error {
	if err := h.ctx.Finalize(); err != nil {
		return err
	}
	return nil
}

func (h *PKCS11Backend) connectToBackend() (pkcs11.SessionHandle, pkcs11.ObjectHandle, error) {
	if err := h.ctx.Initialize(); err != nil {
		return 0, 0, err
	}

	slots, err := h.ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		if cleanupErr := h.cleanupInitialization(); cleanupErr != nil {
			h.logger.Error("Error during cleanup of PKCS11 resources while connecting to backend", zap.Error(cleanupErr))
		}
		return 0, 0, err
	}

	var session pkcs11.SessionHandle
	var keyHandle pkcs11.ObjectHandle
	var lastErr error

	for _, slot := range slots {
		session, err = h.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			lastErr = err
			continue
		}

		if err := h.ctx.Login(session, pkcs11.CKU_USER, h.pin); err != nil {
			h.ctx.CloseSession(session)
			lastErr = err
			continue
		}

		keyHandle, err = h.findKey(session, h.keyID)
		if err != nil {
			h.ctx.Logout(session)
			h.ctx.CloseSession(session)
			lastErr = err
			continue
		}

		return session, keyHandle, nil
	}

	if cleanupErr := h.cleanupInitialization(); cleanupErr != nil {
		h.logger.Error("Error during cleanup of PKCS11 resources while connecting to backend", zap.Error(cleanupErr))
	}
	return 0, 0, fmt.Errorf("failed to find key in any slot: %v", lastErr)
}

func generateRandomIV() ([]byte, error) {
	iv := make([]byte, ivSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}
