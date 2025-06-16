package encryption

import (
	"crypto/rand"
	"fmt"

	"github.com/miekg/pkcs11"
)

// PKCS11Backend implements EncryptionBackend using PKCS11 protocol for HSMs.
type PKCS11Backend struct {
	ctx   *pkcs11.Ctx
	pin   string
	keyID uint16
}

const ivSize = 16

// NewPKCS11Backend creates a new PKCS11Backend.
func NewPKCS11Backend(libPath string, pin string, keyID uint16) (*PKCS11Backend, error) {
	ctx := pkcs11.New(libPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library at %s", libPath)
	}

	return &PKCS11Backend{
		ctx:   ctx,
		pin:   pin,
		keyID: keyID,
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
			// Log cleanup errors but don't override the main operation error
			fmt.Printf("Warning: cleanup errors during encryption: %v\n", cleanupErr)
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
			// Log cleanup errors but don't override the main operation error
			fmt.Printf("Warning: cleanup errors during decryption: %v\n", cleanupErr)
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
			fmt.Printf("Warning: cleanup error after GetSlotList failure: %v\n", cleanupErr)
		}
		return 0, 0, err
	}
	slot := slots[0]

	session, err := h.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		if cleanupErr := h.cleanupInitialization(); cleanupErr != nil {
			fmt.Printf("Warning: cleanup error after OpenSession failure: %v\n", cleanupErr)
		}
		return 0, 0, err
	}

	// If login fails, we need to close the session and finalize
	if err := h.ctx.Login(session, pkcs11.CKU_USER, h.pin); err != nil {
		if closeErr := h.ctx.CloseSession(session); closeErr != nil {
			fmt.Printf("Warning: close session error after login failure: %v\n", closeErr)
		}
		if cleanupErr := h.cleanupInitialization(); cleanupErr != nil {
			fmt.Printf("Warning: cleanup error after login failure: %v\n", cleanupErr)
		}
		return 0, 0, err
	}

	keyHandle, err := h.findKey(session, h.keyID)
	if err != nil {
		if cleanupErr := h.cleanupSession(session); cleanupErr != nil {
			fmt.Printf("Warning: cleanup error after findKey failure: %v\n", cleanupErr)
		}
		return 0, 0, err
	}
	return session, keyHandle, nil
}

func generateRandomIV() ([]byte, error) {
	iv := make([]byte, ivSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}
