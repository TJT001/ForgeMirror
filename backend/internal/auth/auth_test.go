package auth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestEncryptOAEPRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("content-key-envelope")
	ciphertext, err := encryptOAEP(rand.Reader, &key.PublicKey, message, nil)
	if err != nil {
		t.Fatal(err)
	}

	size := key.PublicKey.Size()
	value := new(big.Int).Exp(new(big.Int).SetBytes(ciphertext), key.D, key.N)
	encoded := value.Bytes()
	if len(encoded) < size {
		encoded = append(make([]byte, size-len(encoded)), encoded...)
	}
	if len(encoded) != size || encoded[0] != 0 {
		t.Fatal("bad OAEP leading byte")
	}

	hashLen := sha256.Size
	maskedSeed := encoded[1 : 1+hashLen]
	maskedDB := encoded[1+hashLen:]
	seed := xorBytes(maskedSeed, mgf1(maskedDB, hashLen, sha1.New))
	db := xorBytes(maskedDB, mgf1(seed, len(maskedDB), sha1.New))

	labelHash := sha256.Sum256(nil)
	if !bytes.Equal(db[:hashLen], labelHash[:]) {
		t.Fatal("label hash mismatch")
	}
	index := hashLen
	for index < len(db) && db[index] == 0 {
		index++
	}
	if index >= len(db) || db[index] != 0x01 {
		t.Fatal("missing OAEP separator")
	}
	if !bytes.Equal(db[index+1:], message) {
		t.Fatal("message mismatch")
	}
}

func TestVerifySignatureRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("challenge-nonce")
	digest := sha256.Sum256(nonce)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(&key.PublicKey, nonce, signature); err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(&key.PublicKey, []byte("other"), signature); err == nil {
		t.Fatal("expected verification failure")
	}
}

func TestNewIDFormat(t *testing.T) {
	id := newID()
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		t.Fatalf("unexpected id format: %s", id)
	}
	if id[14] != '4' {
		t.Fatalf("expected UUID v4 variant nibble: %s", id)
	}
}
