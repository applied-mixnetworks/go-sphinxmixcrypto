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
	hashPiSuffix    = byte(0xFC)
	hashTauSuffix   = byte(0xFB)
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

type Crypt struct {
	pki       SphinxPKI
	nymServer SphinxNymServer
	group     *GroupCurve25519
	maxHops   int
	blockSize int // Payload size
	// XXX TODO: add clients map: destniation -> client
}

// NewCrypt creates a new Crypt struct
// with max mixnet nodes per route set to r
func NewCrypt(maxHops, blockSize int) *Crypt {
	s := Crypt{
		maxHops:   maxHops,
		blockSize: blockSize,
		group:     NewGroupCurve25519(),
	}
	return &s
}

// Rho is our PRG; key is of length secretKeyLen,
// output is of length (2r+3)k where k is secretKeyLen
func (s *Crypt) Rho(key [secretKeyLen]byte) ([]byte, error) {
	chacha, err := chacha20.NewCipher(key[:chachaKeyLen], key[chachaKeyLen:chachaKeyLen+chachaNonceLen])
	if err != nil {
		return nil, err
	}
	count := (2*s.maxHops + 3) * secretKeyLen
	r := bytes.Repeat([]byte{0}, count)
	chacha.XORKeyStream(r, r)
	return r, nil
}

// Mu is our HMAC; key and output are of length secretKeyLen
func (s *Crypt) Mu(key [secretKeyLen]byte, data []byte) [secretKeyLen]byte {
	h := blake2b.NewMAC(secretKeyLen, key[:])
	h.Reset()
	h.Write(data)
	var ret [secretKeyLen]byte
	copy(ret[:], h.Sum(nil)[0:40])
	return ret
}

func (s *Crypt) EncryptBlock(key [lioness.LionessKeyLen]byte, data []byte) ([]byte, error) {
	cipher := lioness.NewCipher(key, s.blockSize)
	ciphertext, err := cipher.Encrypt(data)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (s *Crypt) DecryptBlock(key [lioness.LionessKeyLen]byte, data []byte) ([]byte, error) {
	cipher := lioness.NewCipher(key, s.blockSize)
	ciphertext, err := cipher.Decrypt(data)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (s *Crypt) Hash(data []byte) [32]byte {
	return blake2b.Sum256(data)
}

func (s *Crypt) HashBlindingFactor(alpha []byte, secret [secretKeyLen]byte) [32]byte {
	h := make([]byte, 41)
	h = append(secret[0:secretKeyLen], hashBlindSuffix)
	h = append(h, alpha...)
	return s.Hash(h[0:32])
}

func (s *Crypt) HashRho(secret [secretKeyLen]byte) [32]byte {
	h := make([]byte, 41)
	h = append(secret[0:secretKeyLen], hashRhoSuffix)
	return s.Hash(h[0:32])
}

func (s *Crypt) HashMu(secret [secretKeyLen]byte) [32]byte {
	h := make([]byte, 41)
	h = append(secret[0:secretKeyLen], hashMuSuffix)
	return s.Hash(h[0:32])
}

// CreateBlockCipherKey creates our LIONESS block cipher key given a 40 byte secret
func (s *Crypt) CreateBlockCipherKey(secret [secretKeyLen]byte) ([lioness.LionessKeyLen]byte, error) {
	var ret [lioness.LionessKeyLen]byte
	chacha, err := chacha20.NewCipher(secret[:chachaKeyLen], secret[chachaKeyLen:chachaKeyLen+chachaNonceLen])
	if err != nil {
		return ret, err
	}
	r := bytes.Repeat([]byte{0}, lioness.LionessKeyLen)
	chacha.XORKeyStream(r, r)
	copy(ret[:], r)
	return ret, nil
}

func (s *Crypt) HashTau(secret [secretKeyLen]byte) [32]byte {
	h := make([]byte, 41)
	h = append(secret[0:secretKeyLen], hashTauSuffix)
	return s.Hash(h[0:32])
}
