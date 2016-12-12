package sphinxmixcrypto

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var (
	// ErrInvalidBlockSize indicates block size <= 0
	ErrInvalidBlockSize = errors.New("invalid block size")
	// ErrInvalidData indicates zero size data
	ErrInvalidData = errors.New("invalid data, empty")
	// ErrInvalidPadding indicates an invalid padded input
	ErrInvalidPadding = errors.New("invalid padding on input")
	// ErrInvalidPadOffset indicates a bad padding offset
	ErrInvalidPadOffset = errors.New("invalid padding offset")
	// ErrInputTooBig indicates the input data is too big
	ErrInputTooBig = errors.New("input too big")
)

// AddPadding returns src with padding appended
func AddPadding(src []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if src == nil || len(src) == 0 {
		return nil, ErrInvalidData
	}
	if len(src) > blockSize-2 {
		return nil, ErrInputTooBig
	}
	offset := blockSize - len(src)
	padtext := bytes.Repeat([]byte{byte(0)}, offset-2)
	out := append(src, padtext...)
	padding_bytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(padding_bytes, uint16(offset))
	out = append(out, padding_bytes...)
	return out, nil
}

// RemovePadding returns src with padding removed
func RemovePadding(src []byte) ([]byte, error) {
	length := uint16(len(src))
	unpadding := binary.LittleEndian.Uint16(src[length-2:])
	if unpadding > length {
		return nil, ErrInvalidPadding
	}
	return src[:(length - unpadding)], nil
}
