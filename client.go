// Original work Copyright 2015 2016 Lightning Onion
// Modified work Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE and LICENSE-lightening-onion files
// in the root of the source tree.

package sphinxmixcrypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/david415/go-lioness"
)

type SphinxParams struct {
	// PayloadSize is the packet payload size
	PayloadSize int
	// NumMaxHops is the maximum path length.
	MaxHops int
}

// MixHeader contains the sphinx header but not the payload.
// A version number is also included; TODO: make the version
// number do something useful.
type MixHeader struct {
	Version      byte
	EphemeralKey [32]byte                // alpha
	RoutingInfo  []byte                  // beta
	HeaderMAC    [securityParameter]byte // gamma
}

// EncodeDestination encodes a destination using our
// prefix-free encoding
func EncodeDestination(destination []byte) []byte {
	if len(destination) > 127 || len(destination) == 0 {
		panic("wtf")
	}
	c := byte(len(destination))
	ret := []byte{}
	ret = append(ret, c)
	ret = append(ret, destination...)
	return ret
}

// MixHeaderFactory builds mix headers
type MixHeaderFactory struct {
	params       *SphinxParams
	group        *GroupCurve25519
	blockCipher  BlockCipher
	streamCipher StreamCipher
	digest       Digest
	pki          SphinxPKI
	randReader   io.Reader
}

// NewMixHeaderFactory creates a new mix header factory
func NewMixHeaderFactory(params *SphinxParams, pki SphinxPKI, randReader io.Reader) *MixHeaderFactory {
	factory := MixHeaderFactory{
		params:       params,
		group:        NewGroupCurve25519(),
		blockCipher:  NewLionessBlockCipher(),
		streamCipher: &Chacha20Stream{},
		digest:       NewBlake2bDigest(),
		pki:          pki,
		randReader:   randReader,
	}
	return &factory
}

// BuildHeader generates a mix header containing the neccessary onion
// routing information required to propagate the message through the mixnet.
// If the computation is successful then a *MixHeader is returned along with
// a slice of 32byte shared secrets for each mix hop.
func (f *MixHeaderFactory) BuildHeader(route [][16]byte, destination []byte, messageID [16]byte) (*MixHeader, [][32]byte, error) {
	routeLen := len(route)
	if routeLen > f.params.MaxHops {
		return nil, nil, fmt.Errorf("route length %d exceeds max hops %d", routeLen, f.params.MaxHops)
	}
	var secretPoint [32]byte
	var err error
	secretPoint, err = f.group.GenerateSecret(f.randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("faileed to generate curve25519 secret: %s", err)
	}

	paddingLen := (2*(f.params.MaxHops-routeLen)+2)*securityParameter - len(destination)
	padding := make([]byte, paddingLen)
	_, err = f.randReader.Read(padding)
	if err != nil {
		return nil, nil, fmt.Errorf("failure to read pseudo random data: %s", err)
	}

	numHops := routeLen
	hopEphemeralPubKeys := make([][32]byte, numHops)
	hopSharedSecrets := make([][32]byte, numHops)
	var hopBlindingFactors [][32]byte
	hopBlindingFactors = append(hopBlindingFactors, secretPoint)

	for i := 0; i < routeLen; i++ {
		hopEphemeralPubKeys[i] = f.group.MultiExpOn(f.group.g, hopBlindingFactors)
		pubKey, err := f.pki.Get(route[i])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve identity key from PKI: %s", err)
		}
		hopSharedSecrets[i] = f.group.MultiExpOn(pubKey, hopBlindingFactors)
		var keyArray [32]byte
		copy(keyArray[:], hopEphemeralPubKeys[i][:])
		b := f.digest.HashBlindingFactor(keyArray, hopSharedSecrets[i])
		hopBlindingFactors = append(hopBlindingFactors, b)
	}

	// compute the filler strings
	hopSize := 2 * securityParameter
	filler := make([]byte, (numHops-1)*hopSize)
	numStreamBytes := uint((2*f.params.MaxHops + 3) * securityParameter)
	for i := 1; i < numHops; i++ {
		min := (2*(f.params.MaxHops-i) + 3) * securityParameter
		streamKey := f.digest.DeriveStreamCipherKey(hopSharedSecrets[i-1])
		streamBytes, err := f.streamCipher.GenerateStream(streamKey, numStreamBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute filler strings: %s", err)
		}
		lioness.XorBytes(filler, filler, streamBytes[min:])
	}

	// compute beta and then gamma
	beta := make([]byte, len(destination)+len(messageID)+paddingLen)
	copy(beta, destination)
	copy(beta[len(destination):], messageID[:])
	copy(beta[len(destination)+len(messageID):], padding)

	betaLen := uint((2*routeLen + 1) * securityParameter)
	rhoKey := f.digest.DeriveStreamCipherKey(hopSharedSecrets[routeLen-1])
	cipherStream, err := f.streamCipher.GenerateStream(rhoKey, betaLen)
	if err != nil {
		return nil, nil, fmt.Errorf("stream cipher fail: %s", err)
	}
	lioness.XorBytes(beta, beta, cipherStream)
	beta = append(beta, filler...)
	gammaKey, err := f.digest.DeriveHMACKey(hopSharedSecrets[routeLen-1])
	if err != nil {
		return nil, nil, fmt.Errorf("HMAC key derivation fail: %s", err)
	}
	gamma, err := f.digest.HMAC(gammaKey, beta)
	if err != nil {
		return nil, nil, fmt.Errorf("HMAC fail: %s", err)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("HMAC fail: %s", err)
	}
	newBeta := []byte{}
	prevBeta := beta

	for i := routeLen - 2; i >= 0; i-- {
		mixID := route[i+1]
		newBeta = []byte{}
		newBeta = append(newBeta, mixID[:]...)
		newBeta = append(newBeta, gamma[:]...)
		betaSlice := uint((2*f.params.MaxHops - 1) * securityParameter)
		newBeta = append(newBeta, prevBeta[:betaSlice]...)
		rhoKey := f.digest.DeriveStreamCipherKey(hopSharedSecrets[i])
		streamSlice := uint((2*f.params.MaxHops + 1) * securityParameter)
		cipherStream, err := f.streamCipher.GenerateStream(rhoKey, streamSlice)
		if err != nil {
			return nil, nil, fmt.Errorf("stream cipher failure: %s", err)
		}
		lioness.XorBytes(newBeta, newBeta, cipherStream)
		key, err := f.digest.DeriveHMACKey(hopSharedSecrets[i])
		if err != nil {
			return nil, nil, fmt.Errorf("HMAC key derivation fail: %s", err)
		}
		gamma, err = f.digest.HMAC(key, newBeta)
		if err != nil {
			return nil, nil, fmt.Errorf("HMAC fail: %s", err)
		}
		prevBeta = newBeta
	}
	header := &MixHeader{
		Version:      0x01,
		EphemeralKey: hopEphemeralPubKeys[0],
		RoutingInfo:  newBeta,
		HeaderMAC:    gamma,
	}
	return header, hopSharedSecrets, nil
}

// SphinxPacket represents a forwarding message containing onion wrapped
// hop-to-hop routing information along with an onion encrypted payload message
// addressed to the final destination.
type SphinxPacket struct {
	Header  *MixHeader
	Payload []byte // delta
}

// NewOnionReply is used to create an SphinxPacket with a specified header and payload.
// This is used by the WrapReply to create Single Use Reply Blocks
func NewOnionReply(header *MixHeader, payload []byte) *SphinxPacket {
	return &SphinxPacket{
		Header:  header,
		Payload: payload,
	}
}

// SphinxPacketFactory builds onion packets
type SphinxPacketFactory struct {
	params           *SphinxParams
	group            *GroupCurve25519
	blockCipher      BlockCipher
	pki              SphinxPKI
	randReader       io.Reader
	mixHeaderFactory *MixHeaderFactory
}

// NewSphinxPacketFactory creates a new onion packet factory
func NewSphinxPacketFactory(params *SphinxParams, pki SphinxPKI, randReader io.Reader) *SphinxPacketFactory {
	factory := SphinxPacketFactory{
		params:           params,
		group:            NewGroupCurve25519(),
		blockCipher:      NewLionessBlockCipher(),
		pki:              pki,
		randReader:       randReader,
		mixHeaderFactory: NewMixHeaderFactory(params, pki, randReader),
	}
	return &factory
}

// BuildForwardSphinxPacket builds a forward oniion packet
func (f *SphinxPacketFactory) BuildForwardSphinxPacket(route [][16]byte, destination [16]byte, payload []byte) (*SphinxPacket, error) {

	// AddPadding has a 2 byte overhead
	if len(payload)+1+len(destination) > f.params.PayloadSize-2 {
		return nil, fmt.Errorf("wrong sized payload %d > %d", len(payload), f.params.PayloadSize)
	}
	addrPayload := []byte{}
	addrPayload = append(addrPayload, bytes.Repeat([]byte{0}, 16)...)
	encodedDest := EncodeDestination(destination[:])
	addrPayload = append(addrPayload, encodedDest...)
	addrPayload = append(addrPayload, payload[:]...)
	paddedPayload, err := AddPadding(addrPayload, f.params.PayloadSize)
	if err != nil {
		return nil, err
	}

	// Compute the mix header, and shared secerts for each hop.
	destinationType := []byte{byte(ExitNode)}

	var zeroDest [16]byte
	mixHeader, hopSharedSecrets, err := f.mixHeaderFactory.BuildHeader(route, destinationType, zeroDest)
	if err != nil {
		return nil, err
	}

	// compute the delta values
	blockCipherKey, err := f.blockCipher.CreateBlockCipherKey(hopSharedSecrets[len(route)-1])
	if err != nil {
		return nil, err
	}
	delta, err := f.blockCipher.Encrypt(blockCipherKey, paddedPayload)
	if err != nil {
		return nil, err
	}
	for i := len(route) - 2; i > -1; i-- {
		blockCipherKey, err := f.blockCipher.CreateBlockCipherKey(hopSharedSecrets[i])
		if err != nil {
			return nil, err
		}
		delta, err = f.blockCipher.Encrypt(blockCipherKey, delta)
		if err != nil {
			return nil, err
		}
	}
	return &SphinxPacket{
		Header:  mixHeader,
		Payload: delta,
	}, nil
}

// ReplyBlock is a struct that represents a single use reply block
type ReplyBlock struct {
	// Header is a mix header
	Header *MixHeader
	// Key is the symmetric encryption key
	Key [32]byte
	// FirstHop represent the first hop
	FirstHop [16]byte
}

// SphinxClient is used for sending and receiving messages
type SphinxClient struct {
	params           *SphinxParams
	id               []byte
	keysmap          map[[16]byte][][]byte
	pki              SphinxPKI
	randReader       io.Reader
	blockCipher      BlockCipher
	mixHeaderFactory *MixHeaderFactory
}

// NewSphinxClient creates a new SphinxClient
func NewSphinxClient(params *SphinxParams, pki SphinxPKI, id []byte, randReader io.Reader) (*SphinxClient, error) {
	var newID [4]byte
	if id == nil {
		_, err := randReader.Read(newID[:])
		if err != nil {
			return nil, err
		}
		id = []byte(fmt.Sprintf("Client %x", newID))
	}
	return &SphinxClient{
		params:           params,
		id:               id,
		keysmap:          make(map[[16]byte][][]byte),
		pki:              pki,
		randReader:       randReader,
		blockCipher:      NewLionessBlockCipher(),
		mixHeaderFactory: NewMixHeaderFactory(params, pki, randReader),
	}, nil
}

// CreateNym creates a SURB and associates it with a Nym
func (c *SphinxClient) CreateNym(route [][16]byte) (*ReplyBlock, error) {

	var messageID [securityParameter]byte
	_, err := c.randReader.Read(messageID[:])
	if err != nil {
		return nil, fmt.Errorf("create nym failure: %s", err)
	}
	encodedClientID := EncodeDestination(c.id[:])

	header, hopSharedSecrets, err := c.mixHeaderFactory.BuildHeader(route, encodedClientID, messageID)
	if err != nil {
		return nil, fmt.Errorf("create nym failure: %v", err)
	}
	var ktilde [32]byte
	_, err = c.randReader.Read(ktilde[:])
	if err != nil {
		return nil, fmt.Errorf("create nym failure: %s", err)
	}
	keys := [][]byte{}
	keys = append(keys, ktilde[:])
	for i := range hopSharedSecrets {
		key, err := c.blockCipher.CreateBlockCipherKey(hopSharedSecrets[i])
		if err != nil {
			return nil, fmt.Errorf("create nym failure: %s", err)
		}
		keys = append(keys, key[:])
	}
	c.keysmap[messageID] = keys
	surb := ReplyBlock{
		Header:   header,
		Key:      ktilde,
		FirstHop: route[0],
	}
	return &surb, nil
}

// Decrypt decrypts a reply-message, a message sent to us
// using a SURB we previously created. The given message ID
// is used to lookup the correct decryption key.
func (c *SphinxClient) Decrypt(messageID [securityParameter]byte, payload []byte) ([]byte, error) {
	var err error
	keys, ok := c.keysmap[messageID]
	if !ok {
		return nil, fmt.Errorf("key for message id %s not found", messageID)
	}
	ktilde := keys[0]
	keys = keys[1:]
	delete(c.keysmap, messageID)
	var keyArray [lioness.KeyLen]byte
	for i := len(keys) - 1; i > -1; i-- {
		copy(keyArray[:], keys[i])
		payload, err = c.blockCipher.Encrypt(keyArray, payload)
		if err != nil {
			return nil, fmt.Errorf("client decrypt failure: %v", err)
		}
	}
	var k [32]byte
	copy(k[:], ktilde)
	blockCipherKey, err := c.blockCipher.CreateBlockCipherKey(k)
	if err != nil {
		return nil, errors.New("client decrypt failed to derive a block cipher key")
	}
	payload, err = c.blockCipher.Decrypt(blockCipherKey, payload)
	if err != nil {
		return nil, fmt.Errorf("client decrypt failure: %v", err)
	}
	zeros := [securityParameter]byte{}
	if !bytes.Equal(payload[:securityParameter], zeros[:]) {
		return nil, errors.New("corrupt payload")
	}

	unpaddedPayload, err := RemovePadding(payload[securityParameter:])
	if err != nil {
		return nil, errors.New("failed to unpad payload")
	}
	return unpaddedPayload, nil
}

// WrapReply is used to compose a Single Use Reply Block
func (c *SphinxClient) WrapReply(surb *ReplyBlock, message []byte) ([]byte, *SphinxPacket, error) {
	key, err := c.blockCipher.CreateBlockCipherKey(surb.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapReply failed to create block cipher key: %v", err)
	}
	prefixedMessage := make([]byte, securityParameter)
	prefixedMessage = append(prefixedMessage, message...)
	paddedPayload, err := AddPadding(prefixedMessage, c.params.PayloadSize)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapReply failed to add padding: %v", err)
	}
	ciphertextPayload, err := c.blockCipher.Encrypt(key, paddedPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapReply failed to encrypt payload: %v", err)
	}
	if len(ciphertextPayload) != c.params.PayloadSize {
		return nil, nil, fmt.Errorf("WrapReply payload size mismatch error")
	}
	sphinxPacket := NewOnionReply(surb.Header, ciphertextPayload)
	return surb.FirstHop[:], sphinxPacket, nil
}
