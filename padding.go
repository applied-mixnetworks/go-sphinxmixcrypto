package sphinxmixcrypto

import (
	"bytes"
	"errors"
)

var (
	// ErrInvalidBlockSize indicates block size <= 0
	ErrInvalidBlockSize = errors.New("invalid block size")
	// ErrInvalidData indicates zero size data
	ErrInvalidData = errors.New("invalid data, empty")
	// ErrInvalidPadding indicates an invalid padded input
	ErrInvalidPadding = errors.New("invalid padding on input")
)

// AddPadding returns src with padding appended
func AddPadding(src []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if src == nil || len(src) == 0 {
		return nil, ErrInvalidData
	}
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...), nil
}

// RemovePadding returns src with padding removed
func RemovePadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > length {
		return nil, ErrInvalidPadding
	}
	return src[:(length - unpadding)], nil
}
