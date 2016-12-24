// Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package sphinxmixcrypto

import (
	"encoding/hex"
	"testing"
)

func TestGroupCurve25519(t *testing.T) {
	group := NewGroupCurve25519()
	secretString, err := hex.DecodeString("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	secretArray1 := [32]byte{}
	copy(secretArray1[:], secretString)
	sec1 := group.makeSecret(secretArray1)

	secretString, err = hex.DecodeString("4171bd9a48a58cf7579e9fa662fe0ac2acb8c6eed3056cd970fd35dd4d026cae")
	secretArray2 := [32]byte{}
	copy(secretArray2[:], secretString)
	sec2 := group.makeSecret(secretArray2)

	if group.ExpOn(group.ExpOn(group.g, sec1), sec2) != group.ExpOn(group.ExpOn(group.g, sec2), sec1) {
		t.Error("multiplication should be commutative")
		t.Fail()
	}

	secretSlice := [][32]byte{sec1, sec2}
	if group.ExpOn(group.ExpOn(group.g, sec1), sec2) != group.MultiExpOn(group.g, secretSlice) {
		t.Error("multiplication should be commutative")
		t.Fail()
	}
}
