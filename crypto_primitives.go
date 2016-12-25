// Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file in the root of the source
// tree.

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
	sharedSecretSize  = 32
	securityParameter = 16
	// curve25519
	pubKeyLen       = 32
	chachaNonceLen  = 8
	chachaKeyLen    = 32
	secretKeyLen    = chachaKeyLen + chachaNonceLen
	hashRhoPrefix   = byte(0x22)
	hashBlindPrefix = byte(0x11)
	hashMuPrefix    = byte(0x33)
	hashPiPrefix    = byte(0x44)
	hashTauPrefix   = byte(0x55)
)

// BlockCipher is an interface for our Lioness block cipher
type BlockCipher interface {
	Decrypt(key [lioness.KeyLen]byte, block []byte) ([]byte, error)
	Encrypt(key [lioness.KeyLen]byte, block []byte) ([]byte, error)
	CreateBlockCipherKey(secret [32]byte) ([lioness.KeyLen]byte, error)
}

// StreamCipher is an interface for our chacha20 stream generator
type StreamCipher interface {
	GenerateStream(key [chachaKeyLen]byte, n uint) ([]byte, error)
}

// Digest is an interface for our use of Blake2b as a hash and hmac
type Digest interface {
	HMAC(key [securityParameter]byte, data []byte) ([securityParameter]byte, error)
	Hash(data []byte) [32]byte
	DeriveHMACKey(secret [32]byte) [16]byte
	DeriveStreamCipherKey(secret [32]byte) [32]byte
	HashReplay(secret [32]byte) [32]byte
	HashBlindingFactor(alpha [32]byte, secret [32]byte) [32]byte
}

// Chacha20Stream the StreamCipher interface
type Chacha20Stream struct{}

// GenerateStream generates a stream of n bytes given a key
func (s *Chacha20Stream) GenerateStream(key [chachaKeyLen]byte, n uint) ([]byte, error) {
	var nonce [8]byte
	chacha, err := chacha20.NewCipher(key[:chachaKeyLen], nonce[:])
	if err != nil {
		return nil, err
	}
	r := make([]byte, n)
	chacha.XORKeyStream(r, r)
	return r, nil
}

// LionessBlockCipher implements the BlockCipher interface.
type LionessBlockCipher struct {
	streamCipher StreamCipher
	digest       Digest
}

// NewLionessBlockCipher creates a lioness block cipher
func NewLionessBlockCipher() *LionessBlockCipher {
	l := LionessBlockCipher{
		streamCipher: &Chacha20Stream{},
		digest:       NewBlake2bDigest(),
	}
	return &l
}

// Decrypt decrypts a block of data with the given key.
func (l *LionessBlockCipher) Decrypt(key [lioness.KeyLen]byte, block []byte) ([]byte, error) {
	cipher, err := lioness.NewCipher(key, PayloadSize)
	if err != nil {
		return nil, err
	}
	ciphertext, err := cipher.Decrypt(block)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// Encrypt encrypts a block of data with the given key.
func (l *LionessBlockCipher) Encrypt(key [lioness.KeyLen]byte, block []byte) ([]byte, error) {
	cipher, err := lioness.NewCipher(key, PayloadSize)
	if err != nil {
		return nil, err
	}
	ciphertext, err := cipher.Encrypt(block)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// CreateBlockCipherKey returns the Lioness block cipher key
func (l *LionessBlockCipher) CreateBlockCipherKey(secret [32]byte) ([lioness.KeyLen]byte, error) {
	var ret [lioness.KeyLen]byte
	streamCipherKey := l.digest.DeriveStreamCipherKey(secret)
	r, err := l.streamCipher.GenerateStream(streamCipherKey, lioness.KeyLen)
	if err != nil {
		return ret, err
	}
	copy(ret[:], r)
	return ret, nil
}

// Blake2bDigest implements our Digest interface
type Blake2bDigest struct {
	group *GroupCurve25519
}

// NewBlake2bDigest returns a blake2b digest
func NewBlake2bDigest() *Blake2bDigest {
	b := Blake2bDigest{
		group: NewGroupCurve25519(),
	}
	return &b
}

// Hash returns a 32 byte hash of the data
func (b *Blake2bDigest) Hash(data []byte) [32]byte {
	return blake2b.Sum256(data)
}

// DeriveHMACKey derives a key to be used with an HMAC
func (b *Blake2bDigest) DeriveHMACKey(secret [32]byte) [16]byte {
	h := []byte{}
	h = append(h, hashMuPrefix)
	h = append(h, secret[:]...)
	hash := b.Hash(h)
	var ret [16]byte
	copy(ret[:], hash[0:16])
	return ret
}

// DeriveStreamCipherKey derives a key to be used with a stream cipher
func (b *Blake2bDigest) DeriveStreamCipherKey(secret [32]byte) [32]byte {
	h := []byte{}
	h = append(h, hashRhoPrefix)
	h = append(h, secret[:]...)
	return blake2b.Sum256(h)
}

// HMAC computes a HMAC
func (b *Blake2bDigest) HMAC(key [securityParameter]byte, data []byte) ([securityParameter]byte, error) {
	var ret [securityParameter]byte
	h := blake2b.NewMAC(securityParameter, key[:])
	_, err := h.Write(data)
	if err != nil {
		return ret, err
	}
	copy(ret[:], h.Sum(nil))
	return ret, nil
}

// HashBlindingFactor is used to hash the blinding factory
func (b *Blake2bDigest) HashBlindingFactor(alpha [32]byte, secret [32]byte) [32]byte {
	h := []byte{}
	h = append(h, hashBlindPrefix)
	h = append(h, alpha[:]...)
	h = append(h, secret[:]...)
	return b.group.MakeExp(b.Hash(h))
}

// HashReplay produces a hash of the hop key for catching replay attacks
func (b *Blake2bDigest) HashReplay(secret [32]byte) [32]byte {
	h := []byte{}
	h = append(h, hashTauPrefix)
	h = append(h, secret[:]...)
	return b.Hash(h[0:32])
}

// GroupCurve25519 performs group operations on the curve
type GroupCurve25519 struct {
	g [32]byte
}

// NewGroupCurve25519 creates a new GroupCurve25519
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

// GenerateSecret generats a new key
func (g *GroupCurve25519) GenerateSecret(rand io.Reader) ([32]byte, error) {
	var key [32]byte
	_, err := io.ReadFull(rand, key[:32])
	if err != nil {
		return key, err
	}
	return g.makeSecret(key), nil
}

// ExpOn does scalar multiplication on the curve
func (g *GroupCurve25519) ExpOn(base, exp [32]byte) [32]byte {
	var dst [32]byte
	curve25519.ScalarMult(&dst, &exp, &base)
	return dst
}

// MultiExpOn does multiple scalar multiplication operations and
// returns the accumulator
func (g *GroupCurve25519) MultiExpOn(base [32]byte, exps [][32]byte) [32]byte {
	acc := base
	for i := 0; i < len(exps); i++ {
		acc = g.ExpOn(acc, exps[i])
	}
	return acc
}

// MakeExp flips some bits
func (g *GroupCurve25519) MakeExp(data [32]byte) [32]byte {
	return g.makeSecret(data)
}
