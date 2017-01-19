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
