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
	ErrReplayedPacket = fmt.Errorf("sphinx packet replay attempted")
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

// UnwrappedMessage is produced by SphinxNode's Unwrap method
type UnwrappedMessage struct {
	ProcessAction             int
	Alpha, Beta, Gamma, Delta []byte
	NextHop                   []byte
	ClientID                  []byte
	MessageID                 []byte
}

// SphinxNodeOptions are node state options such as pub/priv key and an ID
type SphinxNodeOptions struct {
	privateKey [32]byte
	publicKey  [32]byte
	id         [16]byte
}

// NewSphinxNodeOptions creates new key material and node id.
// Not suitable for deterministic unit tests.
// TODO: replace use of mathrand with io.Reader interface.
func NewSphinxNodeOptions() (*SphinxNodeOptions, error) {
	group := NewGroupCurve25519()
	var err error
	n := SphinxNodeOptions{}
	n.privateKey, err = group.GenerateSecret(rand.Reader)
	if err != nil {
		return nil, err
	}
	n.publicKey = group.ExpOn(group.g, n.privateKey)
	idnum := mathrand.Int31()
	n.id = idEncode(uint32(idnum))
	return &n, nil
}

// idEncode transforms a uint32 into a 16 byte ID
func idEncode(idnum uint32) [16]byte {
	count := 16 - 4 - 1
	zeros := bytes.Repeat([]byte{0}, count)
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, idnum)
	id := []byte{}
	id = append(id, byte(0xff))
	id = append(id, bs...)
	id = append(id, zeros...)
	var ret [16]byte
	copy(ret[:], id)
	return ret
}

// SphinxNode is used to keep track of a mix node's state
type SphinxNode struct {
	sync.RWMutex
	pki          SphinxPKI
	group        *GroupCurve25519
	privateKey   [32]byte
	publicKey    [32]byte
	id           [16]byte
	seenSecrets  map[[32]byte]bool
	digest       Digest
	streamCipher StreamCipher
	blockCipher  BlockCipher
}

// NewSphinxNode creates a new SphinxNode
func NewSphinxNode(options *SphinxNodeOptions) *SphinxNode {
	n := SphinxNode{
		group:        NewGroupCurve25519(),
		seenSecrets:  make(map[[32]byte]bool),
		digest:       NewBlake2bDigest(),
		streamCipher: &Chacha20Stream{},
		blockCipher:  NewLionessBlockCipher(),
	}
	n.privateKey = options.privateKey
	n.publicKey = options.publicKey
	n.id = options.id
	return &n
}

// PrefixFreeDecode decodes the prefix-free encoding.
// Return the type, value, and the remainder of the input string
func (n *SphinxNode) PrefixFreeDecode(s []byte) (int, []byte, []byte) {
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

// Unwrap unwraps a layer of encryption from a sphinx packet
// and upon success returns an UnwrappedMessage, otherwise an error.
func (n *SphinxNode) Unwrap(packet *SphinxPacket) (*UnwrappedMessage, error) {
	result := &UnwrappedMessage{}
	mixHeader := packet.Header
	dhKey := mixHeader.EphemeralKey
	routeInfo := mixHeader.RoutingInfo
	sharedSecret := n.group.ExpOn(dhKey, n.privateKey)
	headerMac := mixHeader.HeaderMAC
	payload := packet.Payload

	// Have we seen it already?
	n.RLock()
	tag := n.digest.HashReplay(sharedSecret)
	_, ok := n.seenSecrets[tag]
	if ok {
		n.RUnlock()
		return nil, ErrReplayedPacket
	}
	n.RUnlock()

	key, err := n.digest.DeriveHMACKey(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("HMAC key derivation fail: %s", err)
	}
	mac, err := n.digest.HMAC(key, routeInfo[:])
	if err != nil {
		return nil, fmt.Errorf("HMAC fail: %s", err)
	}

	if !bytes.Equal(headerMac[:], mac[:]) {
		// invalid MAC
		return nil, errors.New("invalid mac")
	}

	// look again for replay attack just in case another goroutine added the tag
	n.Lock()
	_, ok = n.seenSecrets[tag]
	if ok {
		n.RUnlock()
		return nil, errors.New("replay-attack detected")
	}
	n.seenSecrets[tag] = true
	n.Unlock()

	cipherStreamSize := len(routeInfo) + (2 * securityParameter)
	cipherStream, err := n.streamCipher.GenerateStream(n.digest.DeriveStreamCipherKey(sharedSecret), uint(cipherStreamSize))
	if err != nil {
		// stream cipher failure
		return nil, fmt.Errorf("stream cipher failure: %s", err)
	}
	B := make([]byte, cipherStreamSize)
	padding := make([]byte, 2*securityParameter)
	lioness.XorBytes(B, append(routeInfo[:], padding...), cipherStream)

	deltaKey, err := n.blockCipher.CreateBlockCipherKey(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("createBlockCipherKey failure: %s", err)
	}
	delta, err := n.blockCipher.Decrypt(deltaKey, payload[:])
	if err != nil {
		return nil, fmt.Errorf("wide block cipher decryption failure: %s", err)
	}

	messageType, val, rest := n.PrefixFreeDecode(B)

	if messageType == MoreHops { // next hop
		var ray [32]byte
		copy(ray[:], dhKey[:])
		b := n.digest.HashBlindingFactor(ray, sharedSecret)
		alpha := n.group.ExpOn(dhKey, b)
		gamma := B[securityParameter : securityParameter*2]
		beta := B[securityParameter*2:]
		// send to next node in the route
		result.Alpha = alpha[:]
		result.Beta = beta
		result.Gamma = gamma
		result.Delta = delta
		result.NextHop = val
		result.ProcessAction = MoreHops
		return result, nil
	} else if messageType == ExitNode { // process
		zeros := bytes.Repeat([]byte{0}, securityParameter)
		if bytes.Equal(delta[:securityParameter], zeros) {
			innerType, val, rest := n.PrefixFreeDecode(delta[securityParameter:])
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
