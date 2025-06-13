package encryption_backend

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/miekg/pkcs11"
)

// HSMBackend implements EncryptionBackend using a Hardware Security Module.
type HSMBackend struct {
	libPath string
	pin     string
	keyID   uint16
}

const ivSize = 16

// NewHSMBackend creates a new HSMBackend.
// Uses PKCS11
func NewHSMBackend(libPath string, pin string, keyID uint16) *HSMBackend {
	return &HSMBackend{
		libPath: libPath,
		pin:     pin,
		keyID:   keyID,
	}
}

// Encrypt encrypts the plaintext using the HSM.
// Uses the AES-CBC algorithm.
func (h *HSMBackend) Encrypt(data []byte) ([]byte, error) {
	p, session, key, err := h.connectToHSM()
	if err != nil {
		return nil, fmt.Errorf("connect to HSM: %w", err)
	}
	defer func() {
		p.Logout(session)
		p.CloseSession(session)
		p.Finalize()
	}()

	iv, err := generateRandomIV()
	if err != nil {
		return nil, err
	}

	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)

	if err := p.EncryptInit(session, []*pkcs11.Mechanism{mech}, key); err != nil {
		return nil, fmt.Errorf("EncryptInit: %w", err)
	}

	ciphertext, err := p.Encrypt(session, data)
	if err != nil {
		return nil, fmt.Errorf("Encrypt: %w", err)
	}

	// Prepend IV to ciphertext
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:ivSize], iv)
	copy(result[ivSize:], ciphertext)

	return result, nil
}

// Decrypt decrypts the ciphertext using the HSM.
// Uses the AES-CBC algorithm.
func (h *HSMBackend) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < ivSize {
		return nil, fmt.Errorf("invalid ciphertext: too short to contain IV")
	}

	// Extract IV from the start of the combined data
	iv := ciphertext[:ivSize]
	ciphertext = ciphertext[ivSize:]

	p, session, key, err := h.connectToHSM()
	if err != nil {
		return nil, fmt.Errorf("connect to HSM: %w", err)
	}
	defer func() {
		p.Logout(session)
		p.CloseSession(session)
		p.Finalize()
	}()

	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)

	if err := p.DecryptInit(session, []*pkcs11.Mechanism{mech}, key); err != nil {
		return nil, fmt.Errorf("DecryptInit: %w", err)
	}

	plaintext, err := p.Decrypt(session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("Decrypt: %w", err)
	}
	return plaintext, nil
}

func findKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, id uint16) pkcs11.ObjectHandle {
	keyIDBytes := []byte{byte(id >> 8), byte(id & 0xff)}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyIDBytes),
	}

	if err := p.FindObjectsInit(session, template); err != nil {
		log.Fatalf("FindObjectsInit: %v", err)
	}
	objects, _, err := p.FindObjects(session, 1)
	if err != nil || len(objects) == 0 {
		log.Fatalf("FindObjects: %v", err)
	}
	if err := p.FindObjectsFinal(session); err != nil {
		log.Fatalf("FindObjectsFinal: %v", err)
	}
	return objects[0]
}

func (h *HSMBackend) connectToHSM() (*pkcs11.Ctx, pkcs11.SessionHandle, pkcs11.ObjectHandle, error) {
	if h.libPath == "" {
		return nil, 0, 0, fmt.Errorf("HSM library path cannot be empty")
	}

	p := pkcs11.New(h.libPath)
	if p == nil {
		return nil, 0, 0, fmt.Errorf("failed to load PKCS#11 library at %s", h.libPath)
	}
	fmt.Printf("Creating new HSM backend with library: %s\n", h.libPath)

	if err := p.Initialize(); err != nil {
		return nil, 0, 0, fmt.Errorf("initialize HSM: %w", err)
	}

	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		p.Finalize()
		return nil, 0, 0, fmt.Errorf("get slot list: %w", err)
	}
	slot := slots[0]

	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		p.Finalize()
		return nil, 0, 0, fmt.Errorf("open session: %w", err)
	}

	if err := p.Login(session, pkcs11.CKU_USER, h.pin); err != nil {
		p.CloseSession(session)
		p.Finalize()
		return nil, 0, 0, fmt.Errorf("login: %w", err)
	}

	keyHandle := findKey(p, session, h.keyID)
	return p, session, keyHandle, nil
}

func generateRandomIV() ([]byte, error) {
	iv := make([]byte, ivSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}
