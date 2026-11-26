// SPDX-License-Identifier: AGPL-3.0-only

package relaycrypto

// NewBitmap allocates an LSB-first bitset able to represent totalChunks bits.
func NewBitmap(totalChunks int) ([]byte, error) {
	if totalChunks <= 0 || totalChunks > MaxChunks {
		return nil, ErrInvalidInput
	}
	return make([]byte, (totalChunks+7)/8), nil
}

// SetBit sets chunk index i (LSB-first: byte i/8, bit i%8).
func SetBit(bm []byte, i int) {
	if i < 0 || i/8 >= len(bm) {
		return
	}
	bm[i/8] |= 1 << uint(i%8)
}

// HasBit reports whether chunk index i is set in bm.
func HasBit(bm []byte, i int) bool {
	if i < 0 || i/8 >= len(bm) {
		return false
	}
	return (bm[i/8] & (1 << uint(i%8))) != 0
}

// EncodeBitmap encodes a chunk bitset as unpadded base64url (RFC 4648 §5).
func EncodeBitmap(bm []byte) string {
	return b64.EncodeToString(bm)
}

// DecodeBitmap decodes a base64url chunk bitset and validates its length against totalChunks.
func DecodeBitmap(encoded string, totalChunks int) ([]byte, error) {
	if totalChunks <= 0 || totalChunks > MaxChunks {
		return nil, ErrInvalidInput
	}
	bm, err := b64.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidInput
	}
	wantLen := (totalChunks + 7) / 8
	if len(bm) != wantLen {
		return nil, ErrInvalidInput
	}
	return bm, nil
}
