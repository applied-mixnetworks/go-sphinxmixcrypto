package sphinxmixcrypto

import (
	"bytes"
	"io"

	"git.schwanenlied.me/yawning/chacha20"
	"github.com/david415/go-lioness"
	"github.com/minio/blake2b-simd"
	"golang.org/x/crypto/curve25519"
)

const (
	// The number of bytes produced by our CSPRG for the key stream
	// implementing our stream cipher to encrypt/decrypt the mix header. The
	// last 2 * securityParameter bytes are only used in order to generate/check
	// the MAC over the header.
	numStreamBytes = (2*NumMaxHops + 3) * securityParameter

	// Size in bytes of the shared secrets.
	sharedSecretSize = 32

	securityParameter = 16
	pubKeyLen         = 32 // curve25519 uses 32 byte keys
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

type Params struct {
	maxHops   int
	blockSize int
	group     *GroupCurve25519
}

// NewParams creates a new Params struct
// with max mixnet nodes per route set to r
func NewParams(maxHops, blockSize int) *Params {
	s := Params{
		maxHops:   maxHops,
		blockSize: blockSize,
		group:     NewGroupCurve25519(),
	}
	return &s
}

func (s *Params) GenerateStreamCipherKey(secret [32]byte) [secretKeyLen]byte {
	// XXX or we could set the nonce to all zeros since the key is only used once
	h := make([]byte, 33)
	h = append(h, hashRhoPrefix)
	h = append(h, secret[0:32]...)
	hashed := blake2b.Sum512(h[0:33])
	var ret [secretKeyLen]byte
	copy(ret[:], hashed[:secretKeyLen])
	return ret
}

func (s *Params) GenerateCipherStream(key [secretKeyLen]byte, numBytes uint) ([]byte, error) {
	chacha, err := chacha20.NewCipher(key[:chachaKeyLen], key[chachaKeyLen:chachaKeyLen+chachaNonceLen])
	if err != nil {
		return nil, err
	}
	r := make([]byte, numBytes)
	chacha.XORKeyStream(r, r)
	return r, nil
}

// HMAC authenticates our message.
func (s *Params) HMAC(key [32]byte, data []byte) [32]byte {
	h := blake2b.NewMAC(32, key[:])
	h.Reset()
	h.Write(data)
	var ret [32]byte
	copy(ret[:], h.Sum(nil)[0:securityParameter])
	return ret
}

func (s *Params) EncryptBlock(key [lioness.KeyLen]byte, data []byte) ([]byte, error) {
	cipher := lioness.NewCipher(key, s.blockSize)
	ciphertext, err := cipher.Encrypt(data)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (s *Params) DecryptBlock(key [lioness.KeyLen]byte, data []byte) ([]byte, error) {
	cipher := lioness.NewCipher(key, s.blockSize)
	ciphertext, err := cipher.Decrypt(data)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (s *Params) Hash(data []byte) [32]byte {
	return blake2b.Sum256(data)
}

func (s *Params) HashBlindingFactor(alpha []byte, secret [32]byte) [32]byte {
	h := make([]byte, 41)
	h = append(h, hashBlindPrefix)
	h = append(h, alpha...)
	h = append(h, secret[:]...)
	return s.Hash(h)
}

// HashHMAC is used to hash the secret with a suffix for use with HMAC
func (s *Params) GenerateHMACKey(secret [32]byte) [32]byte {
	h := make([]byte, 32)
	h = append(h, hashMuPrefix)
	h = append(h, secret[:]...)
	return s.Hash(h)
}

func (s *Params) HashSeen(secret [32]byte) [32]byte {
	h := make([]byte, 41)
	h = append(h, hashTauPrefix)
	h = append(h, secret[:]...)
	return s.Hash(h[0:32])
}

// CreateBlockCipherKey returns the LIONESS block cipher key
func (s *Params) CreateBlockCipherKey(secret [32]byte) ([lioness.KeyLen]byte, error) {
	var ret [lioness.KeyLen]byte
	var nonce [8]byte // zero nonce is OK since the key is used only once
	chacha, err := chacha20.NewCipher(secret[:], nonce[:])
	if err != nil {
		return ret, err
	}
	r := bytes.Repeat([]byte{0}, lioness.KeyLen)
	chacha.XORKeyStream(r, r)
	copy(ret[:], r)
	return ret, nil
}
