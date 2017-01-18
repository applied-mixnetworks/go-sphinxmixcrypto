// Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package sphinxmixcrypto

import (
	"fmt"
)

var (
	// ErrorPKIKeyNotFound indicates an identity was not found
	ErrorPKIKeyNotFound = fmt.Errorf("Sphinx PKI identity not found")
)

// SphinxPKI is an interface specifying the Sphinx PKI.
type SphinxPKI interface {
	Get([16]byte) ([32]byte, error)
	Identities() [][16]byte
}

// DummyPKI implements the SphinxPKI interface
// however this is only really useful for testing
// mixnet functionality on a single machine.
type DummyPKI struct {
	nodeKeyStateMap map[[16]byte]*SimpleKeyState
}

// NewDummyPKI creates a new DummyPKI
func NewDummyPKI(nodeKeyStateMap map[[16]byte]*SimpleKeyState) *DummyPKI {
	return &DummyPKI{
		nodeKeyStateMap: nodeKeyStateMap,
	}
}

// Get returns the public key for a given identity.
// PKIKeyNotFound is returned upon failure.
func (p *DummyPKI) Get(id [16]byte) ([32]byte, error) {
	nilKey := [32]byte{}
	_, ok := p.nodeKeyStateMap[id]
	if ok {
		return p.nodeKeyStateMap[id].publicKey, nil
	}
	return nilKey, ErrorPKIKeyNotFound
}

// Identities returns all the identities the PKI knows about.
func (p *DummyPKI) Identities() [][16]byte {
	var identities [][16]byte
	for id := range p.nodeKeyStateMap {
		identities = append(identities, id)
	}
	return identities
}
