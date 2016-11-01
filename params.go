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
	securityParameter = 16
	keyLen            = 32 // curve25519 uses 32 byte keys
	chachaNonceLen    = 8
	chachaKeyLen      = 32
	secretKeyLen      = chachaKeyLen + chachaNonceLen
	hashRhoPrefix     = byte(0xFF)
	hashBlindPrefix   = byte(0xFE)
	hashMuPrefix      = byte(0xFD)
	hashPiPrefix      = byte(0xFC)
	hashTauPrefix     = byte(0xFB)
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
	maxHops   int
	blockSize int
	group     *GroupCurve25519
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

func (s *Crypt) generateStreamCipherKey(secret [32]byte) [secretKeyLen]byte {
	// XXX or we could set the nonce to all zeros since the key is only used once
	h := make([]byte, 33)
	h = append(h, hashRhoPrefix)
	h = append(h, secret[0:32])
	return blake2b.Sum512(h[0:33])[0:secretKeyLen]
}

func (s *Crypt) generateCipherStream(key [secretKeyLen]byte, numBytes uint) ([]byte, error) {
	chacha, err := chacha20.NewCipher(key[:chachaKeyLen], key[chachaKeyLen:chachaKeyLen+chachaNonceLen])
	if err != nil {
		return nil, err
	}
	r := make([]byte, numBytes)
	chacha.XORKeyStream(r, r)
	return r, nil
}

// HMAC authenticates our message.
func (s *Crypt) HMAC(key [secretKeyLen]byte, data []byte) [securityParameter]byte {
	h := blake2b.NewMAC(secretKeyLen, key[:])
	h.Reset()
	h.Write(data)
	var ret [securityParameter]byte
	copy(ret[:], h.Sum(nil)[0:securityParameter])
	return ret
}

func (s *Crypt) EncryptBlock(key [lioness.KeyLen]byte, data []byte) ([]byte, error) {
	cipher := lioness.NewCipher(key, s.blockSize)
	ciphertext, err := cipher.Encrypt(data)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (s *Crypt) DecryptBlock(key [lioness.KeyLen]byte, data []byte) ([]byte, error) {
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

func (s *Crypt) HashBlindingFactor(alpha []byte, secret [32]byte) [32]byte {
	h := make([]byte, 41)
	h = append(h, hashBlindPrefix)
	h = append(h, alpha...)
	h = append(h, secret)
	return s.Hash(h)
}

// HashMu is used to hash the secret with a suffix for use with HMAC
func (s *Crypt) HashMu(secret [32]byte) [32]byte {
	h := make([]byte, 32)
	h = append(h, hashMuPrefix)
	h = append(h, secret)
	return s.Hash(h)
}

// CreateBlockCipherKey creates the LIONESS block cipher
func (s *Crypt) CreateBlockCipherKey(secret [32]byte) ([lioness.KeyLen]byte, error) {
	var ret [lioness.KeyLen]byte
	var nonce [8]byte // zero nonce is OK since the key is used only once
	chacha, err := chacha20.NewCipher(secret, nonce)
	if err != nil {
		return ret, err
	}
	r := bytes.Repeat([]byte{0}, lioness.KeyLen)
	chacha.XORKeyStream(r, r)
	copy(ret[:], r)
	return ret, nil
}

func (s *Crypt) HashTau(secret [32]byte) [32]byte {
	h := make([]byte, 41)
	h = append(h, hashTauPrefix)
	h = append(h, secret)
	return s.Hash(h[0:32])
}
