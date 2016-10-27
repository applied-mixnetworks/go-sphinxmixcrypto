package sphinxnetcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
)

type Options struct {
	privateKey [32]byte
	publicKey  [32]byte
	id         [32]byte
}

type Node struct {
	crypt      *Crypt
	privateKey [32]byte
	publicKey  [32]byte
	id         [32]byte
}

func NewNode(crypt *Crypt, options *Options) (*Node, error) {
	s := Node{
		crypt: crypt,
	}
	if options == nil {
		var err error
		s.privateKey, err = crypt.group.GenerateSecret(rand.Reader)
		if err != nil {
			return nil, err
		}
		s.publicKey = crypt.group.ExpOn(crypt.group.g, s.privateKey)
		idnum := mathrand.Int31() // XXX
		s.id = s.idEncode(uint32(idnum))
	} else {
		s.privateKey = options.privateKey
		s.publicKey = options.publicKey
		s.id = options.id
	}
	return &s, nil
}

// idEncode transforms a uint32 into a 32 byte ID
// however maybe we should change the implementation,
// here i've written it to closely follow the Sphinx reference code
func (n *Node) idEncode(idnum uint32) [32]byte {
	count := chachaKeyLen - 4 - 1 // 4 is len of uint32
	zeros := bytes.Repeat([]byte{0}, count)
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, idnum)
	id := []byte{}
	id = append(id, byte(0xff))
	id = append(id, bs...)
	id = append(id, zeros...)
	var ret [32]byte
	copy(ret[:], id)
	return ret
}

func (n *Node) Process() {

}
