package curve25519

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"

	goCurve25519 "golang.org/x/crypto/curve25519"
)

type Signature [64]byte

func NewSignature(bytes []byte) (s *Signature) {
	s = new(Signature)
	copy(s[:], bytes)
	return
}

func (s *Signature) isCanonical() bool {
	return isCanonicalSignature(s[:])
}

type PublicKey [32]byte

func NewPublicKey(bytes []byte) (pk *PublicKey) {
	pk = new(PublicKey)
	copy(pk[:], bytes)
	return
}

func (pk *PublicKey) isCanonical() bool {
	return isCanonicalPublicKey(pk[:])
}

type PrivateKey struct {
	raw [32]byte
}

func GenerateKey() (sk *PrivateKey) {
	sk = new(PrivateKey)
	_, _ = io.ReadFull(rand.Reader, sk.raw[:])
	clamp(sk.raw[:])
	return sk
}

func NewPrivateKey(bytes []byte) (sk *PrivateKey) {
	sk = new(PrivateKey)
	copy(sk.raw[:], bytes)
	clamp(sk.raw[:])
	return sk
}

func (sk *PrivateKey) toBytes(bytes []byte) []byte {
	if bytes == nil {
		bytes = make([]byte, 32)
	}
	copy(bytes, sk.raw[:])
	return nil
}

func (sk *PrivateKey) Public() (pk *PublicKey) {
	pk = new(PublicKey)
	goCurve25519.ScalarBaseMult((*[32]byte)(pk), &sk.raw)
	return
}

func (sk *PrivateKey) SharedSecret(pk *PublicKey) []byte {
	var ss [32]byte
	goCurve25519.ScalarMult(&ss, &sk.raw, (*[32]byte)(pk))
	return ss[:]
}

func (sk *PrivateKey) myPublic() (pk *PublicKey) {
	pk = new(PublicKey)
	keygen(pk[:], nil, sk.raw[:])
	return
}

func (sk *PrivateKey) mySharedSecret(pk *PublicKey) (ss []byte) {
	ss = make([]byte, 32)
	curve(ss, sk.raw[:], pk[:])
	return
}

func (sk *PrivateKey) Sign(message []byte) (signature *Signature) {
	publicKey := make([]byte, 32)
	signingKey := make([]byte, 32)
	keygen(publicKey, signingKey, sk.raw[:])

	hash := sha256.New()
	hash.Write(message)
	messageDigest := hash.Sum(nil)

	hash.Reset()
	hash.Write(messageDigest)
	hash.Write(signingKey)
	x := hash.Sum(nil)
	y := make([]byte, 32)
	keygen(y, nil, x)

	hash.Reset()
	hash.Write(messageDigest)
	hash.Write(y)
	h := hash.Sum(nil)

	signature = new(Signature)
	sign(signature[:], h, x, signingKey)
	copy(signature[32:], h)
	return
}

func Verify(message []byte, signature *Signature, pk *PublicKey, enforceCanonical bool) bool {
	if enforceCanonical {
		if !signature.isCanonical() {
			return false
		}
		if !pk.isCanonical() {
			return false
		}
	}

	Y := make([]byte, 32)
	v := signature[:32]
	h := signature[32:]

	verify(Y, v, h, pk[:])

	hash := sha256.New()
	hash.Write(message)
	messageDigest := hash.Sum(nil)

	hash.Reset()
	hash.Write(messageDigest)
	hash.Write(Y)
	h2 := hash.Sum(nil)

	return bytes.Equal(h, h2)
}
