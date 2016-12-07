package sphinxnetcrypto

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

type UnwrappedType int

const (
	ExitNode = iota
	MoreHops
	ClientHop
	Failure
)

type Packet struct {
	Alpha, Gamma [32]byte
	Beta, Delta  []byte
}

type UnwrappedMessage struct {
	Alpha, Beta, Gamma, Delta []byte
	NextHop                   []byte
	ClientID                  []byte
	MessageID                 []byte
}

type Options struct {
	privateKey [32]byte
	publicKey  [32]byte
	id         [16]byte
}

func AddPadding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func RemovePadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

type Node struct {
	sync.RWMutex
	pki         SphinxPKI
	nymServer   SphinxNymServer
	group       *GroupCurve25519
	crypt       *Crypt
	privateKey  [32]byte
	publicKey   [32]byte
	id          [16]byte
	seenSecrets map[[32]byte]bool
}

func NewNode(crypt *Crypt, options *Options) (*Node, error) {
	n := Node{
		crypt: crypt,
		group: NewGroupCurve25519(),
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
func (n *Node) idEncode(idnum uint32) [16]byte {
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
func (n *Node) PrefixFreeDecode(s []byte) (int, []byte, []byte) {
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

func (n *Node) Unwrap(packet Packet) (*UnwrappedMessage, error) {
	result := &UnwrappedMessage{}
	sharedSecret := n.group.ExpOn(packet.Alpha, n.privateKey)

	// Have we seen it already?
	n.RLock()
	tag := n.crypt.HashSeen(sharedSecret)
	_, ok := n.seenSecrets[tag]
	if ok {
		n.RUnlock()
		return nil, errors.New("Replay-attack detected. Shared-secret already seen.")
	}
	n.RUnlock()

	if packet.Gamma != n.crypt.HMAC(n.crypt.HashHMAC(sharedSecret), packet.Beta) {
		// invalid MAC
		return nil, errors.New("Invalid MAC.")
	}

	n.Lock()
	_, ok = n.seenSecrets[tag]
	if ok {
		n.RUnlock()
		return nil, errors.New("Replay-attack detected. Shared-secret already seen.")
	}
	n.seenSecrets[tag] = true
	n.Unlock()

	cipherStreamSize := len(packet.Beta) + (2 * securityParameter)
	hrho, err := n.crypt.generateCipherStream(n.crypt.generateStreamCipherKey(sharedSecret), uint(cipherStreamSize))
	if err != nil {
		// stream cipher failure
		return nil, fmt.Errorf("Stream cipher failure: %s", err)
	}

	deltaKey, err := n.crypt.CreateBlockCipherKey(sharedSecret)
	delta, err := n.crypt.DecryptBlock(deltaKey, packet.Delta)
	if err != nil {
		return nil, fmt.Errorf("wide block cipher decryption failure: %s", err)
	}

	padding := make([]byte, 2*securityParameter)
	B := []byte{}
	lioness.XorBytes(B, append(packet.Beta, padding...), hrho)
	messageType, val, rest := n.PrefixFreeDecode(B)

	if messageType == MoreHops {
		b := n.crypt.HashBlindingFactor(packet.Alpha[:], sharedSecret)
		alpha := n.group.ExpOn(packet.Alpha, b)
		gamma := B[securityParameter : securityParameter*2]
		beta := B[securityParameter*2:]
		// send to next node in the route
		result.Alpha = alpha[:]
		result.Beta = beta
		result.Gamma = gamma
		result.Delta = delta
		result.NextHop = val
		return result, nil
	} else if messageType == ExitNode { // process
		zeros := bytes.Repeat([]byte{0}, securityParameter)
		if bytes.Equal(delta[:securityParameter], zeros) {
			innerType, val, rest := n.PrefixFreeDecode(delta[securityParameter:])
			if innerType == ClientHop {
				body := RemovePadding(rest)
				// deliver body to val
				result.Delta = body
				result.ClientID = val
				return result, nil
			}
		}
		return nil, errors.New("Invalid message special destination.")
	} else if messageType == ClientHop { // client
		message_id := rest[:securityParameter]
		result.ClientID = val
		result.MessageID = message_id
		result.Delta = delta
		return result, nil
	}
	return nil, errors.New("Invalid message type.")
}
