package sphinxmixcrypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPadding(t *testing.T) {
	message := []byte("quick brown fox")
	padded_size := 2048
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
	padded_message, err := AddPadding(message, padded_size)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if len(padded_message) != padded_size {
		t.Error("padded_message is incorrect size")
		t.Fail()
	}
	unpadded_message, err := RemovePadding(padded_message)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if len(unpadded_message) != len(message) {
		t.Error("unpadded_message is incorrect size")
		t.Fail()
	}
	if !bytes.Equal(message, unpadded_message) {
		t.Error("message != unpadded_message")
		t.Fail()
	}

	// test broken padding offset
	padded_message = []byte("meowmeow123")
	broken_message := padded_message[:len(padded_message)-8]
	padding_bytes := make([]byte, 8)
	binary.PutUvarint(padding_bytes, uint64(3030))
	broken_message = append(broken_message, padding_bytes...)
	_, err = RemovePadding(broken_message)
	if err == nil {
		t.Errorf("expected offset padding failure")
		t.Fail()
	}
}
