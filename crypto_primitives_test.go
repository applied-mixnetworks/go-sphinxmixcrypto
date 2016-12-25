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
	result, err := hex.DecodeString("84b87479a6036249a18ef279b73db5a4811f641c50337ae3f21fb0be43cc8040")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	l := group.ExpOn(group.ExpOn(group.g, sec1), sec2)
	if !bytes.Equal(l[:], result) {
		t.Error("unexpected result")
		t.Fail()
	}
}

func TestHMAC(t *testing.T) {
	digest := NewBlake2bDigest()
	secret, err := hex.DecodeString("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	var secretArray [32]byte
	copy(secretArray[:], secret)
	key, err := digest.DeriveHMACKey(secretArray)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	wantKey, err := hex.DecodeString("eba2ad216a65c5230ad2018b4c536c45")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if !bytes.Equal(key[:], wantKey) {
		t.Error(err)
		t.Fail()
	}

	data, err := hex.DecodeString("4171bd9a48a58cf7579e9fa662fe0ac2acb8c6eed3056cd970fd35dd4d026cae")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	mac, err := digest.HMAC(key, data)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	wantMac, err := hex.DecodeString("77724528a77692be295f07bcfc8bd5eb")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if !bytes.Equal(mac[:], wantMac) {
		t.Error(err)
		t.Fail()
	}
}
