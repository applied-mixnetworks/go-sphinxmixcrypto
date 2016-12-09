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
)

// AddPadding returns src with padding appended
func AddPadding(src []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if src == nil || len(src) == 0 {
		return nil, ErrInvalidData
	}
	padding := blockSize - len(src)
	padtext := bytes.Repeat([]byte{byte(0)}, padding-8)
	out := append(src, padtext...)
	padding_bytes := make([]byte, 8)
	binary.PutUvarint(padding_bytes, uint64(padding))
	out = append(out, padding_bytes...)
	return out, nil
}

// RemovePadding returns src with padding removed
func RemovePadding(src []byte) ([]byte, error) {
	length := uint64(len(src))
	buf := bytes.NewReader(src[length-8:])
	unpadding, err := binary.ReadUvarint(buf)
	if err != nil {
		return nil, ErrInvalidPadOffset
	}
	if unpadding > length {
		return nil, ErrInvalidPadding
	}
	return src[:(length - unpadding)], nil
}
