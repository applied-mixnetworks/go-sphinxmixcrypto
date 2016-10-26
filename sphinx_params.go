package sphinxnetcrypto

import (
	"bytes"
	"io"

	"git.schwanenlied.me/yawning/chacha20"
	"github.com/david415/go-lioness"
	"github.com/minio/blake2b-simd"
	"golang.org/x/crypto/curve25519"
)

const (
	chachaNonceLen  = 8
	chachaKeyLen    = 32
	secretKeyLen    = chachaKeyLen + chachaNonceLen
	hashRhoSuffix   = byte(0xFF)
	hashBlindSuffix = byte(0xFE)
	hashMuSuffix    = byte(0xFD)
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

type SphinxParams struct {
	pki       SphinxPKI
	nymServer SphinxNymServer
	group     *GroupCurve25519
	r         int
	m         int // Payload size/LIONESS block size
	// XXX TODO: add clients map: destniation -> client
}

// NewSphinxParams creates a new SphinxParams struct
// with max mixnet nodes per route set to r
func NewSphinxParams(r, m int) *SphinxParams {
	s := SphinxParams{
		r:     r,
		m:     m,
		group: NewGroupCurve25519(),
	}
	return &s
}

// Rho is our PRG; key is of length secretKeyLen,
// output is of length (2r+3)k where k is secretKeyLen
func (s *SphinxParams) Rho(key [secretKeyLen]byte) ([]byte, error) {
	chacha, err := chacha20.NewCipher(key[:chachaKeyLen], key[chachaKeyLen:chachaKeyLen+chachaNonceLen])
	if err != nil {
		return nil, err
	}
	count := (2*s.r + 3) * secretKeyLen
	r := bytes.Repeat([]byte{0}, count)
	chacha.XORKeyStream(r, r)
	return r, nil
}

// Mu is our HMAC; key and output are of length secretKeyLen
func (s *SphinxParams) Mu(key [secretKeyLen]byte, data []byte) [secretKeyLen]byte {
	h := blake2b.NewMAC(secretKeyLen, key[:])
	h.Reset()
	h.Write(data)
	var ret [secretKeyLen]byte
	copy(ret[:], h.Sum(nil)[0:40])
	return ret
}

// Pi is our PRP in this case the LIONESS block cipher
// key is of length secretKeyLen, data is of length m
func (s *SphinxParams) Pi(key [secretKeyLen]byte, data []byte) ([]byte, error) {
	cipher := lioness.NewLionessCipher(key[:], s.m)
	ciphertext, err := cipher.Encrypt(data)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// PiInverse implements the inverse of Pi, that is decryption
func (s *SphinxParams) PiInverse(key [secretKeyLen]byte, data []byte) ([]byte, error) {
	cipher := lioness.NewLionessCipher(key[:], s.m)
	ciphertext, err := cipher.Decrypt(data)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (s *SphinxParams) Hash(data []byte) [32]byte {
	return blake2b.Sum256(data)
}

func (s *SphinxParams) HashBlindingFactor(alpha []byte, secret [secretKeyLen]byte) [32]byte {
	h := make([]byte, 41)
	h = append(secret[0:secretKeyLen], hashBlindSuffix)
	h = append(h, alpha...)
	return s.Hash(h[0:32])
}

// HashRho computes a hash of secret to use as a key for Rho our PRG
func (s *SphinxParams) HashRho(secret [secretKeyLen]byte) [32]byte {
	h := make([]byte, 41)
	h = append(secret[0:secretKeyLen], hashRhoSuffix)
	return s.Hash(h[0:32])
}

func (s *SphinxParams) HashMu(secret [secretKeyLen]byte) [32]byte {
	h := make([]byte, 41)
	h = append(secret[0:secretKeyLen], hashMuSuffix)
	return s.Hash(h[0:32])
}
