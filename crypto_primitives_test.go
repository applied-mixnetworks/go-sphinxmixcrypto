// Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package sphinxmixcrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestGroupCurve25519(t *testing.T) {
	group := NewGroupCurve25519()
	secret, err := hex.DecodeString("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	secretArray := [32]byte{}
	copy(secretArray[:], secret)
	x := group.makeSecret(secretArray)
	blinds := [][32]byte{x}
	alpha := group.MultiExpOn(group.g, blinds)
	want, err := hex.DecodeString("56f7f7946e62a79f2a4440cc5ca459a9d1b080c5972014c782230fa38cfe8277")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if !bytes.Equal(alpha[:], want) {
		t.Error("MultiExpOn produced unexpected result")
		t.Fail()
	}
}
