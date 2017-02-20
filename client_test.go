// Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE and LICENSE-lightening-onion files
// in the root of the source tree.

package sphinxmixcrypto

import (
	"encoding/hex"
	"testing"
)

func TestBuildHeaderErrors(t *testing.T) {
	route := make([][16]byte, 5)
	for i := range nodeHexOptions {
		nodeID, err := hex.DecodeString(nodeHexOptions[i].id)
		if err != nil {
			panic(err)
		}
		copy(route[i][:], nodeID)
	}
	keyStateMap := generateNodeKeyStateMap()
	pki := NewDummyPKI(keyStateMap)
	randReader, err := NewChachaEntropyReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
	if err != nil {
		t.Fatal("err")
	}
	params := SphinxParams{
		MaxHops:     5,
		PayloadSize: 1024,
	}
	headerFactory := NewMixHeaderFactory(&params, pki, randReader)
	badRoute := make([][16]byte, params.MaxHops+1)
	var messageID [16]byte
	_, _, err = headerFactory.BuildHeader(badRoute, route[len(route)-1][:], messageID)
	if err == nil {
		t.Fatal("expected headerFactory error")
	}

	// test pki lookup failure case
	headerFactory = NewMixHeaderFactory(&params, pki, randReader)
	var fakeDest [16]byte
	route[0] = fakeDest
	_, _, err = headerFactory.BuildHeader(route, fakeDest[:], messageID)
	if err == nil {
		t.Fatal("expected headerFactory error")
	}
}
