// Original work Copyright 2015 2016 Lightning Onion
// Modified work Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package sphinxmixcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mathrand "math/rand"
	"sync"

	"github.com/david415/go-lioness"
)

var (
	// ErrReplayedPacket indicates a replay attack
	ErrReplayedPacket = fmt.Errorf("sphinx packet replay error")
)

const (
	// ExitNode indicates an exit hop
	ExitNode = 0
	// MoreHops indicates another mix hop
	MoreHops = 255
	// ClientHop indicates a client hop
	ClientHop = 128
	// Failure indicates a prefix-free decoding failure
	Failure
)

// PrefixFreeDecode decodes the prefix-free encoding.
// Return the type, value, and the remainder of the input string
func PrefixFreeDecode(s []byte) (int, []byte, []byte) {
	if len(s) == 0 {
		return Failure, nil, nil
	}
	if int(s[0]) == 0 {
		return ExitNode, nil, s[1:]
	}
	if int(s[0]) == 255 {
		return MoreHops, s[:securityParameter], s[securityParameter:]
	}
	if int(s[0]) < 128 {
		return ClientHop, s[1 : int(s[0])+1], s[int(s[0])+1:]
	}
	return Failure, nil, nil
}

// UnwrappedMessage is produced by SphinxNode's Unwrap method
type UnwrappedMessage struct {
	ProcessAction int
	Alpha         []byte // ephemeral key
	Beta          []byte // routing information
	Gamma         []byte // MAC
	Delta         []byte // message body
	NextHop       []byte
	ClientID      []byte
	MessageID     []byte
}

// ReplayCache is an interface for detecting packet replays
type ReplayCache interface {
	// Get returns true if the hash value is present in the map
	Get([32]byte) bool
	// Set sets a hash value in the map
	Set([32]byte)
	// Flush flushes the map
	Flush()
}

// PrivateKey interface is used to access the private key so the mix
// can unwrap packets
type PrivateKey interface {
	// GetPrivateKey returns the private key
	GetPrivateKey() [32]byte
}

func SphinxPacketUnwrap(params *SphinxParams, replayCache ReplayCache, privateKey PrivateKey, packet *SphinxPacket) (*UnwrappedMessage, error) {
	group := NewGroupCurve25519()
	digest := NewBlake2bDigest()
	streamCipher := &Chacha20Stream{}
	blockCipher := NewLionessBlockCipher()

	result := &UnwrappedMessage{}
	mixHeader := packet.Header
	dhKey := mixHeader.EphemeralKey
	routeInfo := mixHeader.RoutingInfo
	sharedSecret := group.ExpOn(dhKey, privateKey.GetPrivateKey())
	headerMac := mixHeader.HeaderMAC
	payload := packet.Payload

	// Have we seen it already?
	tag := digest.HashReplay(sharedSecret)
	if replayCache.Get(tag) {
		return nil, ErrReplayedPacket
	}

	key, err := digest.DeriveHMACKey(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("HMAC key derivation fail: %s", err)
	}
	mac, err := digest.HMAC(key, routeInfo)
	if err != nil {
		return nil, fmt.Errorf("HMAC fail: %s", err)
	}
	if !bytes.Equal(headerMac[:], mac[:]) {
		// invalid MAC
		return nil, errors.New("invalid mac")
	}
	replayCache.Set(tag)
	cipherStreamSize := len(routeInfo) + (2 * securityParameter)
	cipherStream, err := streamCipher.GenerateStream(digest.DeriveStreamCipherKey(sharedSecret), uint(cipherStreamSize))
	if err != nil {
		// stream cipher failure
		return nil, fmt.Errorf("stream cipher failure: %s", err)
	}
	B := make([]byte, cipherStreamSize)
	padding := make([]byte, 2*securityParameter)
	lioness.XorBytes(B, append(routeInfo, padding...), cipherStream)

	deltaKey, err := blockCipher.CreateBlockCipherKey(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("createBlockCipherKey failure: %s", err)
	}
	delta, err := blockCipher.Decrypt(deltaKey, payload)
	if err != nil {
		return nil, fmt.Errorf("123 wide block cipher decryption failure: %s", err)
	}

	betaLen := uint((2*params.MaxHops + 1) * securityParameter)
	messageType, val, rest := PrefixFreeDecode(B)

	if messageType == MoreHops { // next hop
		var ray [32]byte
		copy(ray[:], dhKey[:])
		b := digest.HashBlindingFactor(ray, sharedSecret)
		alpha := group.ExpOn(dhKey, b)
		gamma := B[securityParameter : securityParameter*2]
		beta := B[securityParameter*2:]
		// send to next node in the route
		result.Alpha = alpha[:]
		result.Beta = make([]byte, betaLen)
		copy(result.Beta, beta)
		result.Gamma = gamma
		result.Delta = delta
		result.NextHop = val
		result.ProcessAction = MoreHops
		return result, nil
	} else if messageType == ExitNode { // process
		zeros := bytes.Repeat([]byte{0}, securityParameter)
		if bytes.Equal(delta[:securityParameter], zeros) {
			innerType, val, rest := PrefixFreeDecode(delta[securityParameter:])
			if innerType == ClientHop {
				body, err := RemovePadding(rest)
				if err != nil {
					return nil, err
				}
				// deliver body to val
				result.Delta = body
				result.ClientID = val
				result.ProcessAction = ExitNode
				return result, nil
			}
		}
		return nil, errors.New("invalid message special destination")
	} else if messageType == ClientHop { // client
		if len(rest) < securityParameter {
			return nil, fmt.Errorf("malformed client hop message")
		}
		messageID := rest[:securityParameter]
		result.ClientID = val
		result.MessageID = messageID
		result.Delta = delta
		result.ProcessAction = ClientHop
		return result, nil
	}
	return nil, fmt.Errorf("Invalid message type %d", messageType)
}
