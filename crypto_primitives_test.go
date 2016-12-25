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

func TestStreamCipher(t *testing.T) {
	cipher := &Chacha20Stream{}
	key, err := hex.DecodeString("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	var keyArray [32]byte
	copy(keyArray[:], key)
	stream, err := cipher.GenerateStream(keyArray, 50)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	want, err := hex.DecodeString("8e295c33753c49121b3d4e8508a3f796079600df41a1401542d2346f32c0813082b2bef9059128e3da9a6bd73da43a44daa5")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if !bytes.Equal(stream, want) {
		t.Error("unexpected stream cipher results")
		t.Fail()
	}
}

func TestBlockCipher(t *testing.T) {
	cipher := NewLionessBlockCipher()
	secret, err := hex.DecodeString("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4")
	if err != nil {
		t.Fatal(err)
	}
	wantLionessKey, err := hex.DecodeString("c26abe4b265a2c8883961ee0c811e000c4161a5ab9674aa910cdcc4ffaa4c7561cb1efe443c530b7acf8c2b64f20b9f2a2b1c895d1f26529c77ba4df1683232cdc0b4ec48d07fd3749e750f276b006e047c65b9e006ba298c832edc56a1bf4d8d630ad2f7f61bfc12bca0ecbcb4a89b5a76c720d6276dd6cdbfd2798430d3d196eab45dabeabf0286c347ed30a9f8a13e28f6333ea77f05542922e357948e386ad92583f65b7269dfdfc469eba3cfa1adbec93a657eb5796c7080d85a5c9ccde")
	if err != nil {
		t.Fatal(err)
	}
	var secretArray [32]byte
	copy(secretArray[:], secret)
	lionessKey, err := cipher.CreateBlockCipherKey(secretArray)
	if !bytes.Equal(lionessKey[:], wantLionessKey) {
		t.Fatal("key derivation error")
	}
	block, err := hex.DecodeString("8e295c33753c49121b3d4e8508a3f796079600df41a1401542d2346f32c0813082b2bef9059128e3da9a6bd73da43a44daa54171bd9a48a58cf7579e9fa662fe0ac2acb8c6eed3056cd970fd35dd4d026cae")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := cipher.Encrypt(lionessKey, block)
	if err != nil {
		t.Fatal(err)
	}
	wantCiphertext, err := hex.DecodeString("31d8bc5ab4dc98c39d5371eb1431fc755d8d6b2e3a223878a685a57a77c941129a5a35e13e5db95541080435b33b30d845bdaa1d4292d3efda156abd816c9fce8ae764a0e99ddc1ed145f78a47ec53892e3b")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ciphertext, wantCiphertext) {
		t.Fatal("ciphertext mismatch err")
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
