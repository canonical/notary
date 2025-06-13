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
	defer h.cleanup(session)

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
	defer h.cleanup(session)

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

func (h *PKCS11Backend) connectToBackend() (pkcs11.SessionHandle, pkcs11.ObjectHandle, error) {
	if err := h.ctx.Initialize(); err != nil {
		return 0, 0, fmt.Errorf("failed to initialize backend: %w", err)
	}

	slots, err := h.ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		h.ctx.Finalize()
		return 0, 0, fmt.Errorf("failed to get slot list: %w", err)
	}
	slot := slots[0]

	session, err := h.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		h.ctx.Finalize()
		return 0, 0, fmt.Errorf("failed to open session: %w", err)
	}

	if err := h.ctx.Login(session, pkcs11.CKU_USER, h.pin); err != nil {
		h.ctx.CloseSession(session)
		h.ctx.Finalize()
		return 0, 0, fmt.Errorf("failed to login: %w", err)
	}

	keyHandle, err := h.findKey(session, h.keyID)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to find key: %w", err)
	}
	return session, keyHandle, nil
}

func (h *PKCS11Backend) cleanup(session pkcs11.SessionHandle) {
	h.ctx.Logout(session)
	h.ctx.CloseSession(session)
	h.ctx.Finalize()
}

func generateRandomIV() ([]byte, error) {
	iv := make([]byte, ivSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}
