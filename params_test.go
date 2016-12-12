package sphinxmixcrypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
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

func TestBlindingHash(t *testing.T) {
	params := NewParams()
	s, err := hex.DecodeString("ae573641850deb7324ad0c821af24a7e95f32d389db29ffd8dbe625d62a2794d")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	alpha, err := hex.DecodeString("56f7f7946e62a79f2a4440cc5ca459a9d1b080c5972014c782230fa38cfe8277")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	var sArray [32]byte
	copy(sArray[:], s)
	b := params.HashBlindingFactor(alpha[:], sArray)
	want, err := hex.DecodeString("b0967a0c4da220652d48e82e2863e2a10af37a4feafa1e3f7ecc48084ebbe070")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if !bytes.Equal(b[:], want) {
		t.Error("blinding factor mismatch")
		t.Fail()
	}
}

func TestCreateBlockCipherKey(t *testing.T) {
	params := NewParams()
	alpha, err := hex.DecodeString("56f7f7946e62a79f2a4440cc5ca459a9d1b080c5972014c782230fa38cfe8277")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	var alphaArray [32]byte
	copy(alphaArray[:], alpha)
	key, err := params.CreateBlockCipherKey(alphaArray)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	want, err := hex.DecodeString("8c8efb9ab5606f3ba6c4c2ec57f4c751147088dbab36fd464a561668472830480b409b9c0b3b4e64ab1f5542959fc24ca4b87c4927fd95eba14c541b18c59770fb0503288dd033f6c82542ad83618af3efa9ac6962892774b9c139832e307f5df711f505b5992fa09553259827769ba913fd36038ab15b753056124b9631e76729d36f313a321161cf2d1e3373e7985c23477613625b49fcdec292528aff7c0033d1668aec65c2c4b39573408437399921e553004240db08fa3c2b2599e280f79a8082613d67d8c17ed9cf7afaf108cf")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if !bytes.Equal(key[:], want) {
		fmt.Printf("key %x\n", key)
		t.Error("output not equal to test vector")
		t.Fail()
	}
}

func TestCreateStreamCipherKey(t *testing.T) {
	params := NewParams()
	alpha, err := hex.DecodeString("56f7f7946e62a79f2a4440cc5ca459a9d1b080c5972014c782230fa38cfe8277")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	var alphaArray [32]byte
	copy(alphaArray[:], alpha)
	key := params.GenerateStreamCipherKey(alphaArray)
	want, err := hex.DecodeString("44cbf1428c9e7f6915cb923e55e0835cfcf778822abbf323dee0fa4c76dde986")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if !bytes.Equal(key[:], want) {
		fmt.Printf("key %x\n", key)
		t.Error("output not equal to test vector")
		t.Fail()
	}
}
