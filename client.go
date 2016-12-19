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

const (
	// The number of bytes produced by our CSPRG for the key stream
	// implementing our stream cipher to encrypt/decrypt the mix header. The
	// last 2 * securityParameter bytes are only used in order to generate/check
	// the MAC over the header.
	numStreamBytes = (2*NumMaxHops + 3) * securityParameter

	// NumMaxHops is the maximum path length.
	NumMaxHops = 5

	// Fixed size of the the routing info. This consists of a 16
	// byte address and a 16 byte HMAC for each hop of the route,
	// the first pair in cleartext and the following pairs
	// increasingly obfuscated. In case fewer than numMaxHops are
	// used, then the remainder is padded with null-bytes, also
	// obfuscated.
	routingInfoSize = pubKeyLen + (2*NumMaxHops-1)*securityParameter

	// HopPayloadSize is the per-hop payload size in the header
	HopPayloadSize = 32
	// PayloadSize is the packet payload size
	PayloadSize = 1024
)

// MixHeader contains the sphinx header but not the payload.
// A version number is also included; TODO: make the version
// number do something useful.
type MixHeader struct {
	Version      byte
	EphemeralKey [32]byte                // alpha
	RoutingInfo  [routingInfoSize]byte   // beta
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
	group        *GroupCurve25519
	blockCipher  BlockCipher
	streamCipher StreamCipher
	digest       Digest
	pki          SphinxPKI
	randReader   io.Reader
}

// NewMixHeaderFactory creates a new mix header factory
func NewMixHeaderFactory(pki SphinxPKI, randReader io.Reader) *MixHeaderFactory {
	factory := MixHeaderFactory{
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
	if routeLen > NumMaxHops {
		return nil, nil, fmt.Errorf("route length %d exceeds max hops %d", routeLen, NumMaxHops)
	}
	var secretPoint [32]byte
	var err error
	secretPoint, err = f.group.GenerateSecret(f.randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("faileed to generate curve25519 secret: %s", err)
	}

	paddingLen := (2*(NumMaxHops-routeLen)+2)*securityParameter - len(destination)
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
	for i := 1; i < numHops; i++ {
		min := (2*(NumMaxHops-i) + 3) * securityParameter
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

	betaLen := uint((2*(NumMaxHops-routeLen) + 3) * securityParameter)
	rhoKey := f.digest.DeriveStreamCipherKey(hopSharedSecrets[routeLen-1])
	cipherStream, err := f.streamCipher.GenerateStream(rhoKey, betaLen)
	if err != nil {
		return nil, nil, fmt.Errorf("stream cipher fail: %s", err)
	}
	lioness.XorBytes(beta, beta, cipherStream)
	beta = append(beta, filler...)
	gammaKey := f.digest.DeriveHMACKey(hopSharedSecrets[routeLen-1])
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
		betaSlice := uint((2*NumMaxHops - 1) * securityParameter)
		newBeta = append(newBeta, prevBeta[:betaSlice]...)
		rhoKey := f.digest.DeriveStreamCipherKey(hopSharedSecrets[i])
		streamSlice := uint((2*NumMaxHops + 1) * securityParameter)
		cipherStream, err := f.streamCipher.GenerateStream(rhoKey, streamSlice)
		if err != nil {
			return nil, nil, fmt.Errorf("stream cipher failure: %s", err)
		}
		lioness.XorBytes(newBeta, newBeta, cipherStream)
		gamma, err = f.digest.HMAC(f.digest.DeriveHMACKey(hopSharedSecrets[i]), newBeta)
		if err != nil {
			return nil, nil, fmt.Errorf("HMAC fail: %s", err)
		}
		prevBeta = newBeta
	}
	finalBeta := [routingInfoSize]byte{}
	copy(finalBeta[:], newBeta[:])
	header := &MixHeader{
		Version:      0x01,
		EphemeralKey: hopEphemeralPubKeys[0],
		RoutingInfo:  finalBeta,
		HeaderMAC:    gamma,
	}
	return header, hopSharedSecrets, nil
}

// OnionPacket represents a forwarding message containing onion wrapped
// hop-to-hop routing information along with an onion encrypted payload message
// addressed to the final destination.
type OnionPacket struct {
	Header  *MixHeader
	Payload [PayloadSize]byte // delta
}

// NewOnionReply is used to create an OnionPacket with a specified header and payload.
// This is used by the WrapReply to create Single Use Reply Blocks
func NewOnionReply(header *MixHeader, payload [PayloadSize]byte) *OnionPacket {
	return &OnionPacket{
		Header:  header,
		Payload: payload,
	}
}

// OnionPacketFactory builds onion packets
type OnionPacketFactory struct {
	group            *GroupCurve25519
	blockCipher      BlockCipher
	pki              SphinxPKI
	randReader       io.Reader
	mixHeaderFactory *MixHeaderFactory
}

// NewOnionPacketFactory creates a new onion packet factory
func NewOnionPacketFactory(pki SphinxPKI, randReader io.Reader) *OnionPacketFactory {
	factory := OnionPacketFactory{
		group:            NewGroupCurve25519(),
		blockCipher:      NewLionessBlockCipher(),
		pki:              pki,
		randReader:       randReader,
		mixHeaderFactory: NewMixHeaderFactory(pki, randReader),
	}
	return &factory
}

// BuildForwardOnionPacket builds a forward oniion packet
func (f *OnionPacketFactory) BuildForwardOnionPacket(route [][16]byte, destination [16]byte, payload []byte) (*OnionPacket, error) {

	if len(payload)+1+len(destination) > PayloadSize-2 { // XXX AddPadding has a 2 byte overhead
		return nil, fmt.Errorf("wrong sized payload %d > %d", len(payload), PayloadSize)
	}
	addrPayload := []byte{}
	addrPayload = append(addrPayload, bytes.Repeat([]byte{0}, 16)...)
	encodedDest := EncodeDestination(destination[:])
	addrPayload = append(addrPayload, encodedDest...)
	addrPayload = append(addrPayload, payload[:]...)
	paddedPayload, err := AddPadding(addrPayload, PayloadSize)
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
	newPayload := [PayloadSize]byte{}
	copy(newPayload[:], delta)
	return &OnionPacket{
		Header:  mixHeader,
		Payload: newPayload,
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
	id               []byte
	keysmap          map[[16]byte][][]byte
	pki              SphinxPKI
	randReader       io.Reader
	blockCipher      BlockCipher
	mixHeaderFactory *MixHeaderFactory
}

// NewSphinxClient creates a new SphinxClient
func NewSphinxClient(pki SphinxPKI, id []byte, randReader io.Reader) *SphinxClient {
	var newID [4]byte
	if id == nil {
		_, err := randReader.Read(newID[:])
		if err != nil {
		}
		id = []byte(fmt.Sprintf("Client %x", newID))
	}
	return &SphinxClient{
		id:               id,
		keysmap:          make(map[[16]byte][][]byte),
		pki:              pki,
		randReader:       randReader,
		blockCipher:      NewLionessBlockCipher(),
		mixHeaderFactory: NewMixHeaderFactory(pki, randReader),
	}
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
func (c *SphinxClient) WrapReply(surb *ReplyBlock, message []byte) ([]byte, *OnionPacket, error) {
	key, err := c.blockCipher.CreateBlockCipherKey(surb.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapReply failed to create block cipher key: %v", err)
	}
	prefixedMessage := make([]byte, securityParameter)
	prefixedMessage = append(prefixedMessage, message...)
	paddedPayload, err := AddPadding(prefixedMessage, PayloadSize)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapReply failed to add padding: %v", err)
	}
	ciphertextPayload, err := c.blockCipher.Encrypt(key, paddedPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapReply failed to encrypt payload: %v", err)
	}
	var payload [PayloadSize]byte
	copy(payload[:], ciphertextPayload)
	onionPacket := NewOnionReply(surb.Header, payload)
	return surb.FirstHop[:], onionPacket, nil
}
