// Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE and LICENSE-lightening-onion files
// in the root of the source tree.

package sphinxmixcrypto

import (
	"testing"
)

func TestPrefixFreeDecodeErrors(t *testing.T) {
	options, err := NewSphinxNodeOptions()
	if err != nil {
		t.Fatal(err)
	}
	params := SphinxParams{
		PayloadSize: 1024,
		MaxHops:     5,
	}
	node := NewSphinxNode(options, &params)
	s := []byte{}
	n, _, _ := node.PrefixFreeDecode(s)
	if n != Failure {
		t.Fatal("expected a Failure")
	}
	s = []byte{130}
	n, _, _ = node.PrefixFreeDecode(s)
	if n != Failure {
		t.Fatal("expected a Failure")
	}
}
