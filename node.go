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
	ErrReplayedPacket = fmt.Errorf("sphinx packet replay attempted")
)

type UnwrappedType int

const (
	ExitNode  = 0
	MoreHops  = 255
	ClientHop = 128
	Failure
)

type UnwrappedMessage struct {
	ProcessAction             int
	Alpha, Beta, Gamma, Delta []byte
	NextHop                   []byte
	ClientID                  []byte
	MessageID                 []byte
}

type SphinxNodeOptions struct {
	privateKey [32]byte
	publicKey  [32]byte
	id         [16]byte
}

type SphinxNode struct {
	sync.RWMutex
	params      *Params
	pki         SphinxPKI
	nymServer   SphinxNymServer
	group       *GroupCurve25519
	crypt       *Params
	privateKey  [32]byte
	publicKey   [32]byte
	id          [16]byte
	seenSecrets map[[32]byte]bool
}

func NewSphinxNode(params *Params, options *SphinxNodeOptions) (*SphinxNode, error) {
	n := SphinxNode{
		params:      params,
		group:       NewGroupCurve25519(),
		seenSecrets: make(map[[32]byte]bool),
	}
	if options == nil {
		var err error
		n.privateKey, err = n.group.GenerateSecret(rand.Reader)
		if err != nil {
			return nil, err
		}
		n.publicKey = n.group.ExpOn(n.group.g, n.privateKey)
		idnum := mathrand.Int31()
		n.id = n.idEncode(uint32(idnum))
	} else {
		n.privateKey = options.privateKey
		n.publicKey = options.publicKey
		n.id = options.id
	}
	return &n, nil
}

// idEncode transforms a uint32 into a 16 byte ID
func (n *SphinxNode) idEncode(idnum uint32) [16]byte {
	count := 16 - 4 - 1 // 4 is len of uint32
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

// Decode the prefix-free encoding.
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
func (n *SphinxNode) Unwrap(packet *OnionPacket) (*UnwrappedMessage, error) {
	fmt.Println("UNWRAP")
	result := &UnwrappedMessage{}

	mixHeader := packet.Header
	dhKey := mixHeader.EphemeralKey
	routeInfo := mixHeader.RoutingInfo
	sharedSecret := n.group.ExpOn(dhKey, n.privateKey)
	headerMac := mixHeader.HeaderMAC
	payload := packet.Payload

	// Have we seen it already?
	n.RLock()
	tag := n.params.HashSeen(sharedSecret)
	_, ok := n.seenSecrets[tag]
	if ok {
		n.RUnlock()
		return nil, ErrReplayedPacket
	}
	n.RUnlock()

	mac := n.params.HMAC(n.params.GenerateHMACKey(sharedSecret), routeInfo[:])
	if !bytes.Equal(headerMac[:], mac[:]) {
		// invalid MAC
		return nil, errors.New("Invalid MAC.")
	}

	// look again for replay attack just in case another goroutine added the tag
	n.Lock()
	_, ok = n.seenSecrets[tag]
	if ok {
		n.RUnlock()
		return nil, errors.New("Replay-attack detected. Shared-secret already seen.")
	}
	n.seenSecrets[tag] = true
	n.Unlock()

	cipherStreamSize := len(routeInfo) + (2 * securityParameter)
	cipherStream, err := n.params.GenerateCipherStream(n.params.GenerateStreamCipherKey(sharedSecret), uint(cipherStreamSize))
	if err != nil {
		// stream cipher failure
		return nil, fmt.Errorf("Stream cipher failure: %s", err)
	}
	B := make([]byte, cipherStreamSize)
	padding := make([]byte, 2*securityParameter)
	lioness.XorBytes(B, append(routeInfo[:], padding...), cipherStream)

	deltaKey, err := n.params.CreateBlockCipherKey(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("CreateBlockCipherKey failure: %s", err)
	}
	delta, err := n.params.DecryptBlock(deltaKey, payload[:])
	if err != nil {
		return nil, fmt.Errorf("wide block cipher decryption failure: %s", err)
	}

	//fmt.Printf("B %x\n", B)
	messageType, val, rest := n.PrefixFreeDecode(B)

	if messageType == MoreHops { // next hop
		b := n.params.HashBlindingFactor(dhKey[:], sharedSecret)
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
		return nil, errors.New("Invalid message special destination.")
	} else if messageType == ClientHop { // client
		message_id := rest[:securityParameter]
		result.ClientID = val
		result.MessageID = message_id
		result.Delta = delta
		result.ProcessAction = ClientHop
		return result, nil
	}
	return nil, fmt.Errorf("Invalid message type %d", messageType)
}
