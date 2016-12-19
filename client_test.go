// Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE and LICENSE-lightening-onion files
// in the root of the source tree.

package sphinxmixcrypto

import (
	"testing"
)

func TestBuildHeaderErrors(t *testing.T) {
	nodeKeys, _, route := generateRoute()
	pki := NewDummyPKI(nodeKeys)
	randReader, err := NewFixedNoiseReader("")
	if err != nil {
		t.Fatal("unexpected NewFixedNoiseReader err")
	}
	headerFactory := NewMixHeaderFactory(pki, randReader)
	badRoute := make([][16]byte, NumMaxHops+1)
	var messageID [16]byte
	_, _, err = headerFactory.BuildHeader(badRoute, route[len(route)-1][:], messageID)
	if err == nil {
		t.Fatal("expected headerFactory error")
	}
	_, _, err = headerFactory.BuildHeader(route, route[len(route)-1][:], messageID)
	if err == nil {
		t.Fatal("expected headerFactory error")
	}

	// test for padding randReader failure
	randReader, err = NewFixedNoiseReader("d7314c8d2ba771dbe2982fa6299844f1b92736881e78ae7644f4bccbf8817a69")
	if err != nil {
		t.Fatal("unexpected NewFixedNoiseReader err")
	}
	headerFactory = NewMixHeaderFactory(pki, randReader)
	_, _, err = headerFactory.BuildHeader(route, route[len(route)-1][:], messageID)
	if err == nil {
		t.Fatal("expected headerFactory error")
	}

	// test pki lookup failure case
	randReader, err = NewFixedNoiseReader("eec3843cd06ffe5bd3773548fd405b38d7314c8d2ba771dbe2982fa6299844f1b92736881e78ae7644f4bccbf8817a69")
	if err != nil {
		t.Fatal("unexpected NewFixedNoiseReader err")
	}
	headerFactory = NewMixHeaderFactory(pki, randReader)
	var fakeDest [16]byte
	route[0] = fakeDest
	_, _, err = headerFactory.BuildHeader(route, fakeDest[:], messageID)
	if err == nil {
		t.Fatal("expected headerFactory error")
	}
}
