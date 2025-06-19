package encryption_backend

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
	"go.uber.org/zap"
)

// PKCS11Provider defines the interface for PKCS11 operations needed by our backend
type PKCS11Provider interface {
	Initialize() error
	Finalize() error
	GetSlotList(bool) ([]uint, error)
	OpenSession(uint, uint) (pkcs11.SessionHandle, error)
	CloseSession(pkcs11.SessionHandle) error
	Login(pkcs11.SessionHandle, uint, string) error
	Logout(pkcs11.SessionHandle) error
	FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error
	FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(pkcs11.SessionHandle) error
	EncryptInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Encrypt(pkcs11.SessionHandle, []byte) ([]byte, error)
	DecryptInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Decrypt(pkcs11.SessionHandle, []byte) ([]byte, error)
}

// realPKCS11Provider implements PKCS11Provider using the real pkcs11.Ctx
type realPKCS11Provider struct {
	ctx *pkcs11.Ctx
}

func (p *realPKCS11Provider) Initialize() error { return p.ctx.Initialize() }
func (p *realPKCS11Provider) Finalize() error   { return p.ctx.Finalize() }
func (p *realPKCS11Provider) GetSlotList(tokenPresent bool) ([]uint, error) {
	return p.ctx.GetSlotList(tokenPresent)
}
func (p *realPKCS11Provider) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	return p.ctx.OpenSession(slotID, flags)
}
func (p *realPKCS11Provider) CloseSession(sh pkcs11.SessionHandle) error {
	return p.ctx.CloseSession(sh)
}
func (p *realPKCS11Provider) Login(sh pkcs11.SessionHandle, ut uint, pin string) error {
	return p.ctx.Login(sh, ut, pin)
}
func (p *realPKCS11Provider) Logout(sh pkcs11.SessionHandle) error { return p.ctx.Logout(sh) }
func (p *realPKCS11Provider) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	return p.ctx.FindObjectsInit(sh, temp)
}
func (p *realPKCS11Provider) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	return p.ctx.FindObjects(sh, max)
}
func (p *realPKCS11Provider) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	return p.ctx.FindObjectsFinal(sh)
}
func (p *realPKCS11Provider) EncryptInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return p.ctx.EncryptInit(sh, m, o)
}
func (p *realPKCS11Provider) Encrypt(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	return p.ctx.Encrypt(sh, message)
}
func (p *realPKCS11Provider) DecryptInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return p.ctx.DecryptInit(sh, m, o)
}
func (p *realPKCS11Provider) Decrypt(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	return p.ctx.Decrypt(sh, message)
}

// PKCS11Backend implements EncryptionBackend using the PKCS11 protocol for HSMs.
type PKCS11Backend struct {
	pkcs11Provider PKCS11Provider
	pin            string
	keyID          uint16
	logger         *zap.Logger
}

const ivSize = 16 // bytes

// NewPKCS11Backend creates a new PKCS11Backend.
func NewPKCS11Backend(libPath string, pin string, keyID uint16, logger *zap.Logger) (*PKCS11Backend, error) {
	ctx := pkcs11.New(libPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library at %s", libPath)
	}

	return &PKCS11Backend{
		pkcs11Provider: &realPKCS11Provider{ctx: ctx},
		pin:            pin,
		keyID:          keyID,
		logger:         logger,
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

	if err := h.pkcs11Provider.EncryptInit(session, []*pkcs11.Mechanism{mech}, key); err != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}

	ciphertext, err := h.pkcs11Provider.Encrypt(session, data)
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
		return nil, errors.New("invalid ciphertext: too short to contain IV")
	}

	// Extract IV from the start of the ciphertext
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

	if err := h.pkcs11Provider.DecryptInit(session, []*pkcs11.Mechanism{mech}, key); err != nil {
		return nil, fmt.Errorf("failed to initialize decryption: %w", err)
	}

	plaintext, err := h.pkcs11Provider.Decrypt(session, ciphertext)
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

	if err := h.pkcs11Provider.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("failed to initialize object search: %w", err)
	}
	objects, _, err := h.pkcs11Provider.FindObjects(session, 1)
	if err != nil || len(objects) == 0 {
		return 0, fmt.Errorf("failed to find objects: %w", err)
	}
	if err := h.pkcs11Provider.FindObjectsFinal(session); err != nil {
		return 0, fmt.Errorf("failed to finalize object search: %w", err)
	}
	return objects[0], nil
}

// cleanupSession performs cleanup of an active session
func (h *PKCS11Backend) cleanupSession(session pkcs11.SessionHandle) error {
	if err := h.pkcs11Provider.Logout(session); err != nil {
		return err
	}
	if err := h.pkcs11Provider.CloseSession(session); err != nil {
		return err
	}
	if err := h.pkcs11Provider.Finalize(); err != nil {
		return err
	}
	return nil
}

// cleanupInitialization performs cleanup of just the initialization
func (h *PKCS11Backend) cleanupInitialization() error {
	if err := h.pkcs11Provider.Finalize(); err != nil {
		return err
	}
	return nil
}

func (h *PKCS11Backend) openSessionOnSlot(slot uint) (pkcs11.SessionHandle, error) {
	session, err := h.pkcs11Provider.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}

	if err := h.pkcs11Provider.Login(session, pkcs11.CKU_USER, h.pin); err != nil {
		closeErr := h.pkcs11Provider.CloseSession(session)
		if closeErr != nil {
			h.logger.Error("Error closing session after failed login", zap.Error(closeErr))
		}
		return 0, fmt.Errorf("failed to login: %w", err)
	}

	return session, nil
}

func (h *PKCS11Backend) connectToBackend() (pkcs11.SessionHandle, pkcs11.ObjectHandle, error) {
	if err := h.pkcs11Provider.Initialize(); err != nil {
		return 0, 0, err
	}

	slots, err := h.pkcs11Provider.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		if cleanupErr := h.cleanupInitialization(); cleanupErr != nil {
			h.logger.Error("Error during cleanup of PKCS11 resources while connecting to backend", zap.Error(cleanupErr))
		}
		return 0, 0, err
	}

	var lastErr error
	for _, slot := range slots {
		session, err := h.openSessionOnSlot(slot)
		if err != nil {
			lastErr = err
			continue
		}

		keyHandle, err := h.findKey(session, h.keyID)
		if err != nil {
			if logoutErr := h.pkcs11Provider.Logout(session); logoutErr != nil {
				h.logger.Error("Error logging out while connecting to backend", zap.Error(logoutErr))
			}
			if closeErr := h.pkcs11Provider.CloseSession(session); closeErr != nil {
				h.logger.Error("Error closing session while connecting to backend", zap.Error(closeErr))
			}
			lastErr = err
			continue
		}

		return session, keyHandle, nil
	}

	if cleanupErr := h.cleanupInitialization(); cleanupErr != nil {
		h.logger.Error("Error during cleanup of PKCS11 resources while connecting to backend", zap.Error(cleanupErr))
	}
	return 0, 0, fmt.Errorf("failed to find key in any slot: %w", lastErr)
}

func generateRandomIV() ([]byte, error) {
	iv := make([]byte, ivSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}
