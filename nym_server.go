// Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE and LICENSE-lightening-onion files
// in the root of the source tree.

package sphinxmixcrypto

import (
	"fmt"
)

// WrapReply is used to compose a Single Use Reply Block
func WrapReply(params *Params, surb *ReplyBlock, message []byte) ([]byte, *OnionPacket, error) {
	key, err := params.CreateBlockCipherKey(surb.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapReply failed to create block cipher key: %v", err)
	}
	prefixedMessage := make([]byte, securityParameter)
	prefixedMessage = append(prefixedMessage, message...)
	paddedPayload, err := AddPadding(prefixedMessage, PayloadSize)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapReply failed to add padding: %v", err)
	}
	ciphertextPayload, err := params.EncryptBlock(key, paddedPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapReply failed to encrypt payload: %v", err)
	}
	var payload [PayloadSize]byte
	copy(payload[:], ciphertextPayload)
	onionPacket := NewOnionReply(surb.Header, payload)
	return surb.FirstHop[:], onionPacket, nil
}

// // SphinxNymServer interface XXX add more description here XXX
// type SphinxNymServer interface {
// 	// XXX fixme add methods
// }

// type NymServer struct {
// 	nymMap map[[16]byte]ReplyBlock
// }

// func NewNymServer() *NymServer {
// 	return &NymServer{}
// }

// func (n *NymServer) AddSURB() {
// }

// func (n *NymServer) Wrap(nym [16]byte, message []byte) {
// 	// surb, ok := n.nymMap[nym]
// 	// if !ok {
// 	// 	//return nil, fmt.Errorf("key for nym %s not found", nym)
// 	// }
// 	// delete(n.nymMap, nym)

// 	// XXX ...
// }
