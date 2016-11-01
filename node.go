package sphinxnetcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"

	"github.com/david415/go-lioness"
)

type Packet struct {
	Alpha, Gamma [32]byte
	Beta, Delta  []byte
}

type Options struct {
	privateKey [32]byte
	publicKey  [32]byte
	id         [16]byte
}

type Node struct {
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
/*func (n *Node) PrefixFreeDecode() (uint8, []byte, []byte) {

}*/

func (n *Node) Process(packet Packet) {
	sharedSecret := n.group.ExpOn(packet.Alpha, n.privateKey)
	// Have we seen it already?
	tag := n.crypt.HashTau(sharedSecret)
	_, ok := n.seenSecrets[tag]
	if ok {
		// we've already seen that shared-secret
		return
	}
	if packet.Gamma != n.crypt.HMAC(n.crypt.HashMu(sharedSecret), packet.Beta) {
		// invalid MAC
		return
	}
	seenSecrets[tag] = true
	cipherStreamSize := len(packet.Beta) + (2 * securityParameter)
	hrho, err := n.crypt.generateCipherStream(n.crypt.generateStreamCipherKey(sharedSecret, cipherStreamSize))
	if err != nil {
		// stream cipher failure
		return
	}
	padding := make([]byte, 2*securityParameter)
	B := lioness.XorBytes(append(packet.beta, padding), hrho)
	messageType, val, rest := n.PrefixFreeDecode()
	if messageType == NodeType {
		b := n.crypt.HashBlindingFactor(packet.Alpha, sharedSecret)
		alpha := n.group.ExpOn(alpha, b)
		gamma := B[securityParameter : securityParameter*2]
		beta := B[securityParameter*2:]
		deltaKey, err := CreateBlockCipherKey(sharedSecret, delta)
		delta := n.crypt.DecryptBlock(deltaKey)
		// send to next node in the route
		return
	} else if messageType == DspecType {
		deltaKey, err := CreateBlockCipherKey(sharedSecret, delta)
		delta := n.crypt.DecryptBlock(deltaKey)
		zeros := bytes.Repeat([]byte{0}, securityParameter)
		if bytes.Equal(delta[:securityParameter], zeros) {
			innerType, val, rest := n.PrefixFreeDecode(delta[securityParameter:])
			if innerType == DestType {
				body := unpadBody(rest)
				// deliver body to val
				return
			}
		}
	} else if messageType == DestType {
		id := rest[:securityParameter]
		deltaKey, err := CreateBlockCipherKey(sharedSecret)
		delta := n.crypt.DecryptBlock(deltaKey, packet.delta)
		// XXX ...
		return
	} else {
		// invalid message type
		return
	}
}
