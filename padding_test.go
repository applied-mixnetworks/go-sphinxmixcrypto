// Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package sphinxmixcrypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestPaddingVector(t *testing.T) {
	message := []byte("the quick brown fox")
	padded, err := AddPadding(message, 100)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	want, err := hex.DecodeString("74686520717569636b2062726f776e20666f78000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005100")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if !bytes.Equal(padded, want) {
		t.Error("expected a match")
		t.Fail()
	}
}

func TestPadding(t *testing.T) {
	message := []byte("the quick brown fox")
	blockSize := 2048
	_, err := AddPadding(message, 0)
	if err != ErrInvalidBlockSize {
		t.Error("expected ErrInvalidBlockSize")
		t.Fail()
	}
	_, err = AddPadding([]byte{}, 10)
	if err != ErrInvalidData {
		t.Error("expected ErrInvalidData")
		t.Fail()
	}
	paddedMessage, err := AddPadding(message, blockSize)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if len(paddedMessage) != blockSize {
		t.Error("paddedMessage is incorrect size")
		t.Fail()
	}
	unpaddedMessage, err := RemovePadding(paddedMessage)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if len(unpaddedMessage) != len(message) {
		t.Error("unpaddedMessage is incorrect size")
		t.Fail()
	}
	if !bytes.Equal(message, unpaddedMessage) {
		t.Error("message != unpaddedMessage")
		t.Fail()
	}

	// test broken padding offset
	paddedMessage = []byte("meowmeow123")
	brokenMessage := paddedMessage[:len(paddedMessage)-2]
	paddingBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(paddingBytes, uint16(9999))
	brokenMessage = append(brokenMessage, paddingBytes...)
	_, err = RemovePadding(brokenMessage)
	if err == nil {
		t.Errorf("expected offset padding failure")
		t.Fail()
	}
}
