package sphinxmixcrypto

import (
	"io"

	"git.schwanenlied.me/yawning/chacha20"
	"github.com/david415/go-lioness"
	"github.com/minio/blake2b-simd"
	"golang.org/x/crypto/curve25519"
)

const (
	// Size in bytes of the shared secrets.
	sharedSecretSize = 32

	securityParameter = 16
	pubKeyLen         = 32 // curve25519 uses 32 byte keys
	chachaNonceLen    = 8
	chachaKeyLen      = 32
	secretKeyLen      = chachaKeyLen + chachaNonceLen
	hashRhoPrefix     = byte(0x22)
	hashBlindPrefix   = byte(0x11)
	hashMuPrefix      = byte(0x33)
	hashPiPrefix      = byte(0x44)
	hashTauPrefix     = byte(0x55)
)

type GroupCurve25519 struct {
	g [32]byte
}

func NewGroupCurve25519() *GroupCurve25519 {
	group := GroupCurve25519{}
	group.g = group.basepoint()
	return &group
}

func (g *GroupCurve25519) basepoint() [32]byte {
	var curveOut [32]byte
	curveOut[0] = 9
	for i := 1; i < 32; i++ {
		curveOut[i] = byte(0)
	}
	return curveOut
}

func (g *GroupCurve25519) makeSecret(data [32]byte) [32]byte {
	var curveOut [32]byte
	copy(curveOut[:], data[:])
	curveOut[0] &= 248
	curveOut[31] &= 127
	curveOut[31] |= 64
	return curveOut
}

func (g *GroupCurve25519) GenerateSecret(rand io.Reader) ([32]byte, error) {
	var key [32]byte
	_, err := io.ReadFull(rand, key[:32])
	if err != nil {
		return key, err
	}
	return g.makeSecret(key), nil
}

func (g *GroupCurve25519) ExpOn(base, exp [32]byte) [32]byte {
	var dst [32]byte
	curve25519.ScalarMult(&dst, &exp, &base)
	return dst
}

func (g *GroupCurve25519) MultiExpOn(base [32]byte, exps [][32]byte) [32]byte {
	acc := base
	for i := 0; i < len(exps); i++ {
		acc = g.ExpOn(acc, exps[i])
	}
	return acc
}

func (g *GroupCurve25519) MakeExp(data [32]byte) [32]byte {
	return g.makeSecret(data)
}

type Params struct {
	group *GroupCurve25519
}

// NewParams creates a new Params struct
// with max mixnet nodes per route set to r
func NewParams() *Params {
	s := Params{
		group: NewGroupCurve25519(),
	}
	return &s
}

func (s *Params) GenerateStreamCipherKey(secret [32]byte) [32]byte {
	h := []byte{}
	h = append(h, hashRhoPrefix)
	h = append(h, secret[:]...)

	return blake2b.Sum256(h)
}

func (s *Params) GenerateCipherStream(key [chachaKeyLen]byte, numBytes uint) ([]byte, error) {
	var nonce [8]byte
	chacha, err := chacha20.NewCipher(key[:chachaKeyLen], nonce[:])
	if err != nil {
		return nil, err
	}
	r := make([]byte, numBytes)
	chacha.XORKeyStream(r, r)
	return r, nil
}

// HMAC authenticates our message.
func (s *Params) HMAC(key [16]byte, data []byte) [16]byte {
	h := blake2b.NewMAC(16, key[:])
	h.Reset()
	h.Write(data)
	var ret [16]byte
	copy(ret[:], h.Sum(nil))
	return ret
}

func (s *Params) EncryptBlock(key [lioness.KeyLen]byte, data []byte) ([]byte, error) {
	cipher, err := lioness.NewCipher(key, PayloadSize)
	if err != nil {
		return nil, err
	}
	ciphertext, err := cipher.Encrypt(data)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (s *Params) DecryptBlock(key [lioness.KeyLen]byte, data []byte) ([]byte, error) {
	cipher, err := lioness.NewCipher(key, PayloadSize)
	if err != nil {
		return nil, err
	}
	ciphertext, err := cipher.Decrypt(data)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (s *Params) Hash(data []byte) [32]byte {
	return blake2b.Sum256(data)
}

// HashBlindingFactor compute a hash of alpha
// and secret to use as a blinding factor
func (s *Params) HashBlindingFactor(alpha []byte, secret [32]byte) [32]byte {
	h := []byte{}
	h = append(h, hashBlindPrefix)
	h = append(h, alpha...)
	h = append(h, secret[:]...)
	return s.group.MakeExp(s.Hash(h))
}

// HashHMAC is used to hash the secret with a suffix for use with HMAC
func (s *Params) GenerateHMACKey(secret [32]byte) [16]byte {
	h := []byte{}
	h = append(h, hashMuPrefix)
	h = append(h, secret[:]...)
	hash := s.Hash(h)
	var ret [16]byte
	copy(ret[:], hash[0:16])
	return ret
}

func (s *Params) HashSeen(secret [32]byte) [32]byte {
	h := []byte{}
	h = append(h, hashTauPrefix)
	h = append(h, secret[:]...)
	return s.Hash(h[0:32])
}

// CreateBlockCipherKey returns the LIONESS block cipher key
func (s *Params) CreateBlockCipherKey(secret [32]byte) ([lioness.KeyLen]byte, error) {
	var ret [lioness.KeyLen]byte
	streamCipherKey := s.GenerateStreamCipherKey(secret)
	r, err := s.GenerateCipherStream(streamCipherKey, 208)
	if err != nil {
		return ret, err
	}
	copy(ret[:], r)
	return ret, nil
}
