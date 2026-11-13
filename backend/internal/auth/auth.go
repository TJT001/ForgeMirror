package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"forgemirror/backend/internal/store"
)

type Service struct {
	store        *store.Store
	dataDir      string
	challengeTTL time.Duration
	grantTTL     time.Duration
}

type Challenge struct {
	ID        string    `json:"challenge_id"`
	DeviceID  string    `json:"device_id"`
	Nonce     []byte    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
}

func New(st *store.Store, dataDir string, challengeTTL, grantTTL time.Duration) *Service {
	return &Service{store: st, dataDir: dataDir, challengeTTL: challengeTTL, grantTTL: grantTTL}
}

func (s *Service) RegisterDevice(ctx context.Context, deviceID string,
	publicKeyDER []byte) (Challenge, error) {
	if deviceID == "" {
		return Challenge{}, fmt.Errorf("device_id required")
	}
	if _, err := parsePublicKey(publicKeyDER); err != nil {
		return Challenge{}, fmt.Errorf("invalid public key: %w", err)
	}
	if err := s.store.UpsertDevice(ctx, deviceID, publicKeyDER); err != nil {
		return Challenge{}, err
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return Challenge{}, err
	}
	challenge := Challenge{
		ID:        newID(),
		DeviceID:  deviceID,
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(s.challengeTTL),
	}
	if err := s.store.CreateChallenge(ctx, challenge.ID, deviceID, nonce,
		challenge.ExpiresAt); err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

func (s *Service) CreateGrant(ctx context.Context, deviceID, challengeID, taskID string,
	signature []byte) (store.Grant, error) {
	publicKeyDER, err := s.store.GetDevice(ctx, deviceID)
	if err != nil {
		return store.Grant{}, fmt.Errorf("device not found: %w", err)
	}
	publicKey, err := parsePublicKey(publicKeyDER)
	if err != nil {
		return store.Grant{}, err
	}

	nonce, err := s.store.ConsumeChallenge(ctx, challengeID, deviceID)
	if err != nil {
		return store.Grant{}, fmt.Errorf("challenge invalid or expired: %w", err)
	}
	if err := verifySignature(publicKey, nonce, signature); err != nil {
		return store.Grant{}, fmt.Errorf("signature invalid: %w", err)
	}

	task, err := s.store.GetTask(ctx, taskID)
	if err != nil {
		return store.Grant{}, fmt.Errorf("task not found: %w", err)
	}
	if task.Status != "succeeded" {
		return store.Grant{}, fmt.Errorf("task not ready: %s", task.Status)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return store.Grant{}, fmt.Errorf("device key must be RSA for the dev backend")
	}

	keyPath := filepath.Join(s.dataDir, "works", taskID, "keys", "k_content.bin")
	kContent, err := os.ReadFile(keyPath)
	if err != nil {
		return store.Grant{}, fmt.Errorf("content key unavailable: %w", err)
	}
	if len(kContent) != 32 {
		return store.Grant{}, fmt.Errorf("content key has unexpected length")
	}

	payload, err := json.Marshal(map[string]string{
		"task_id":   taskID,
		"device_id": deviceID,
		"key":       base64.StdEncoding.EncodeToString(kContent),
	})
	if err != nil {
		return store.Grant{}, err
	}
	wrapped, err := encryptOAEP(rand.Reader, rsaPublicKey, payload, nil)
	if err != nil {
		return store.Grant{}, fmt.Errorf("wrap failed: %w", err)
	}

	grant := store.Grant{
		ID:         newID(),
		DeviceID:   deviceID,
		TaskID:     taskID,
		WrappedKey: wrapped,
		ExpiresAt:  time.Now().Add(s.grantTTL),
	}
	if err := s.store.CreateGrant(ctx, grant.ID, deviceID, taskID, wrapped,
		grant.ExpiresAt); err != nil {
		return store.Grant{}, err
	}
	return grant, nil
}

func (s *Service) RevokeGrant(ctx context.Context, grantID string) error {
	return s.store.RevokeGrant(ctx, grantID)
}

func (s *Service) GetGrant(ctx context.Context, grantID string) (store.Grant, error) {
	return s.store.GetGrant(ctx, grantID)
}

// encryptOAEP uses SHA-256 as the OAEP hash and MGF1-SHA1, matching Android
// Keystore's OAEP support on API 26-30 (MGF1-SHA256 is not available there).
func encryptOAEP(random io.Reader, pub *rsa.PublicKey, message, label []byte) ([]byte, error) {
	const hashLen = sha256.Size
	size := pub.Size()
	if len(message) > size-2*hashLen-2 {
		return nil, fmt.Errorf("message too long for OAEP")
	}
	labelHash := sha256.Sum256(label)

	padding := make([]byte, size-len(message)-2*hashLen-2)
	db := make([]byte, 0, size-hashLen-1)
	db = append(db, labelHash[:]...)
	db = append(db, padding...)
	db = append(db, 0x01)
	db = append(db, message...)

	seed := make([]byte, hashLen)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, err
	}
	maskedDB := xorBytes(db, mgf1(seed, len(db), sha1.New))
	maskedSeed := xorBytes(seed, mgf1(maskedDB, hashLen, sha1.New))

	encoded := make([]byte, 0, size)
	encoded = append(encoded, 0x00)
	encoded = append(encoded, maskedSeed...)
	encoded = append(encoded, maskedDB...)

	value := new(big.Int).SetBytes(encoded)
	encrypted := new(big.Int).Exp(value, big.NewInt(int64(pub.E)), pub.N)
	result := encrypted.Bytes()
	if len(result) < size {
		padded := make([]byte, size-len(result), size)
		result = append(padded, result...)
	}
	return result, nil
}

func mgf1(seed []byte, length int, newHash func() hash.Hash) []byte {
	out := make([]byte, 0, length)
	var counter [4]byte
	for index := uint32(0); len(out) < length; index++ {
		binary.BigEndian.PutUint32(counter[:], index)
		digest := newHash()
		digest.Write(seed)
		digest.Write(counter[:])
		out = append(out, digest.Sum(nil)...)
	}
	return out[:length]
}

func xorBytes(left, right []byte) []byte {
	out := make([]byte, len(left))
	for index := range left {
		out[index] = left[index] ^ right[index]
	}
	return out
}

func parsePublicKey(der []byte) (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(der)
}

func verifySignature(publicKey crypto.PublicKey, data, signature []byte) error {
	digest := sha256.Sum256(data)
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return fmt.Errorf("ecdsa verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type %T", publicKey)
	}
}

func newID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	hexValue := make([]byte, 32)
	hex.Encode(hexValue, value[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexValue[0:8], hexValue[8:12], hexValue[12:16], hexValue[16:20], hexValue[20:32])
}
