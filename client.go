// Original work Copyright 2015 2016 Lightning Onion
// Modified work Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE and LICENSE-lightening-onion files
// in the root of the source tree.

package sphinxmixcrypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

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

// NewMixHeader generates the a mix header containing the neccessary onion
// routing information required to propagate the message through the mixnet.
func NewMixHeader(params *Params, route [][16]byte, nodeMap map[[16]byte][32]byte,
	destinationType byte, destinationID [16]byte, secret []byte, padding []byte) (*MixHeader, [][32]byte, error) {
	routeLen := len(route)
	if routeLen > NumMaxHops {
		return nil, nil, fmt.Errorf("route length %d exceeds max hops %d", routeLen, NumMaxHops)
	}
	var secretPoint [32]byte
	var err error
	if secret == nil {
		secretPoint, err = params.group.GenerateSecret(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("faileed to generate curve25519 secret: %s", err)
		}
	} else {
		if len(secret) != 32 {
			return nil, nil, errors.New("secret must be 256 bits")
		}
		secretArray := [32]byte{}
		copy(secretArray[:], secret)
		secretPoint = params.group.makeSecret(secretArray)
	}
	randSliceLen := (2*(NumMaxHops-routeLen)+2)*securityParameter - 1
	if padding == nil {
		// minus 1 for one byte destination type marker
		randPadding := make([]byte, randSliceLen)
		_, err = rand.Read(randPadding)
		if err != nil {
			return nil, nil, fmt.Errorf("failure to read pseudo random data: %s", err)
		}
		copy(padding, randPadding)
	}
	numHops := routeLen
	hopEphemeralPubKeys := make([][32]byte, numHops)
	hopSharedSecrets := make([][32]byte, numHops)
	var hopBlindingFactors [][32]byte
	hopBlindingFactors = append(hopBlindingFactors, secretPoint)
	for i := 0; i < routeLen; i++ {
		hopEphemeralPubKeys[i] = params.group.MultiExpOn(params.group.g, hopBlindingFactors)
		hopSharedSecrets[i] = params.group.MultiExpOn(nodeMap[route[i]], hopBlindingFactors)
		b := params.HashBlindingFactor(hopEphemeralPubKeys[i][:], hopSharedSecrets[i])
		hopBlindingFactors = append(hopBlindingFactors, b)
	}

	// compute the filler strings
	hopSize := 2 * securityParameter
	filler := make([]byte, (numHops-1)*hopSize)
	for i := 1; i < numHops; i++ {
		min := (2*(NumMaxHops-i) + 3) * securityParameter
		streamKey := params.GenerateStreamCipherKey(hopSharedSecrets[i-1])
		streamBytes, err := params.GenerateCipherStream(streamKey, numStreamBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute filler strings: %s", err)
		}
		lioness.XorBytes(filler, filler, streamBytes[min:])
	}

	// compute beta and then gamma
	beta := make([]byte, randSliceLen+len(destinationID)+1)
	beta[0] = destinationType
	copy(beta[1:], destinationID[:])
	copy(beta[1+len(destinationID):], padding)
	betaLen := uint((2*(NumMaxHops-routeLen) + 3) * securityParameter)
	rhoKey := params.GenerateStreamCipherKey(hopSharedSecrets[routeLen-1])
	cipherStream, err := params.GenerateCipherStream(rhoKey, betaLen)
	if err != nil {
		return nil, nil, fmt.Errorf("stream cipher fail: %s", err)
	}
	lioness.XorBytes(beta, beta, cipherStream)
	beta = append(beta, filler...)
	gammaKey := params.GenerateHMACKey(hopSharedSecrets[routeLen-1])
	gamma := params.HMAC(gammaKey, beta)
	newBeta := []byte{}
	prevBeta := beta

	for i := routeLen - 2; i >= 0; i-- {
		mixID := route[i+1]
		newBeta = []byte{}
		newBeta = append(newBeta, mixID[:]...)
		newBeta = append(newBeta, gamma[:]...)
		betaSlice := uint((2*NumMaxHops - 1) * securityParameter)
		newBeta = append(newBeta, prevBeta[:betaSlice]...)
		rhoKey := params.GenerateStreamCipherKey(hopSharedSecrets[i])
		streamSlice := uint((2*NumMaxHops + 1) * securityParameter)
		cipherStream, err := params.GenerateCipherStream(rhoKey, streamSlice)
		if err != nil {
			return nil, nil, fmt.Errorf("stream cipher failure: %s", err)
		}
		lioness.XorBytes(newBeta, newBeta, cipherStream)
		gamma = params.HMAC(params.GenerateHMACKey(hopSharedSecrets[i]), newBeta)
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

// NewOnionPacket creates a mixnet packet
func NewOnionPacket(params *Params, route [][16]byte, nodeMap map[[16]byte][32]byte,
	destination [16]byte, payload []byte, secret []byte, padding []byte) (*OnionPacket, error) {

	if len(payload)+1+len(destination) > PayloadSize-8 { // XXX AddPadding has a 8 byte overhead
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
	destinationType := byte(ExitNode)
	var destinationID [16]byte
	copy(destinationID[:], bytes.Repeat([]byte{0}, 16))
	mixHeader, hopSharedSecrets, err := NewMixHeader(params, route, nodeMap, destinationType, destinationID, secret, padding)
	if err != nil {
		return nil, err
	}

	// compute the delta values
	blockCipherKey, err := params.CreateBlockCipherKey(hopSharedSecrets[len(route)-1])
	if err != nil {
		return nil, err
	}
	delta, err := params.EncryptBlock(blockCipherKey, paddedPayload)
	if err != nil {
		return nil, err
	}
	for i := len(route) - 2; i > -1; i-- {
		blockCipherKey, err := params.CreateBlockCipherKey(hopSharedSecrets[i])
		if err != nil {
			return nil, err
		}
		delta, err = params.EncryptBlock(blockCipherKey, delta)
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
