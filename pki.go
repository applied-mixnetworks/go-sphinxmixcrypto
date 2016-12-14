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
	nodeMap map[[16]byte][32]byte
}

// NewDummyPKI creates a new DummyPKI
func NewDummyPKI(nodeMap map[[16]byte][32]byte) *DummyPKI {
	return &DummyPKI{
		nodeMap: nodeMap,
	}
}

// Get returns the public key for a given identity.
// PKIKeyNotFound is returned upon failure.
func (p *DummyPKI) Get(id [16]byte) ([32]byte, error) {
	pubKey, ok := p.nodeMap[id]
	if ok {
		return pubKey, nil
	}
	return pubKey, ErrorPKIKeyNotFound
}

// Identities returns all the identities the PKI knows about.
func (p *DummyPKI) Identities() [][16]byte {
	var identities [][16]byte
	for id := range p.nodeMap {
		identities = append(identities, id)
	}
	return identities
}
