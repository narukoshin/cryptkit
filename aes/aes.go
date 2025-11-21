package aes

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// AES struct holds the key and the IV
type AES struct {
	Key []byte
	Iv  []byte
}

// state is a 4x4 matrix of bytes
type state [4][4]byte

var (
	errInvalidIV        = errors.New("aes: iv must be 16 bytes")
	errInvalidHex       = errors.New("aes: invalid hex input")
	errInvalidCipherLen = errors.New("aes: ciphertext too short or not multiple of 16")
	errInvalidPadding   = errors.New("aes: invalid padding")
	errInvalidKey       = errors.New("aes: key cannot be nil")
)



// This is the S-box substitution table used in AES.
var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// invSbox is the inverse S-box.
var invSbox = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

// rcon is used in the AES key expansion algorithm.
var rcon = [11]byte{
	0x00,
	0x01, 0x02, 0x04, 0x08,
	0x10, 0x20, 0x40, 0x80,
	0x1B, 0x36,
}

// gfMul multiplies two bytes together in the Galois Field of 2^8. It
// is used in the AES encryption algorithm. The multiplication is
// done in a bitwise manner, according to the Galois Field
// multiplication rules.
func gfMul(a, b byte) byte {
	var res byte
	var t byte = a
	for i := 0; i < 8; i++ {
		if (b & (1 << i)) != 0 {
			res ^= t
		}
		if t&0x80 != 0 {
			t = (t << 1) ^ 0x1b
		} else {
			t <<= 1
		}
	}
	return res
}

// normalizeKey takes a key of any length and normalizes it by
// taking the XOR of the key bytes modulo 16. The resulting
// key is 16 bytes long and is suitable for use with the AES
// encryption algorithm. If the given key is nil, an error is
// returned.
func normalizeKey(k []byte) ([]byte, error) {
	if k == nil {
		return nil, errInvalidKey
	}
	out := make([]byte, 16)
	if len(k) == 16 {
		copy(out, k)
		return out, nil
	}
	for i := 0; i < len(k); i++ {
		out[i%16] ^= k[i]
	}
	return out, nil
}

// keyExpansion: expand a 16-byte key into 176 bytes, using the AES key
// expansion algorithm. The output will be used for encrypting and
// decrypting data.
func keyExpansion(key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errInvalidKey
	}
	const nk = 4
	const nb = 4
	const nr = 10
	expanded := make([]byte, 4*(nb*(nr+1))) // 176
	copy(expanded[:16], key)

	var temp [4]byte
	for i := nk; i < nb*(nr+1); i++ {
		for t := 0; t < 4; t++ {
			temp[t] = expanded[(i-1)*4+t]
		}
		if i%nk == 0 {
			// rot
			t0 := temp[0]
			temp[0] = temp[1]
			temp[1] = temp[2]
			temp[2] = temp[3]
			temp[3] = t0
			// sub
			for t := 0; t < 4; t++ {
				temp[t] = sbox[temp[t]]
			}
			temp[0] ^= rcon[i/nk]
		}
		for t := 0; t < 4; t++ {
			expanded[i*4+t] = expanded[(i-nk)*4+t] ^ temp[t]
		}
	}
	return expanded, nil
}

// bytesToState: Converts a byte slice into a state. The byte slice is
// converted column-major order, i.e. the first column of the state
// becomes the first 4 bytes of the input, the second column the
// second 4 bytes, and so on. The state must be a multiple of 16
// bytes. An error is returned if the state is invalid.
func bytesToState(in []byte) state {
	var s state
	for c := range 4 {
		for r := range 4 {
			s[r][c] = in[c*4+r]
		}
	}
	return s
}

// stateToBytes: Converts a state into a byte slice. The state is
// converted column-major order, i.e. the first column of the state
// becomes the first 4 bytes of the output, the second column the
// second 4 bytes, and so on. The state must be a multiple of 16
// bytes. An error is returned if the state is invalid.
func stateToBytes(s state) []byte {
	out := make([]byte, 16)
	for c := range 4 {
		for r := range 4 {
			out[c*4+r] = s[r][c]
		}
	}
	return out
}

// SubBytes operation. This operation substitutes a state using the
// 8 sBoxes tables. The state is modified in place. The state
// must be a multiple of 16 bytes. An error is returned if the state is
// invalid.
func subBytes(s *state) {
	for r := range 4 {
		for c := range 4 {
			s[r][c] = sbox[s[r][c]]
		}
	}
}

// Inverse SubBytes operation. This is the inverse of the SubBytes
// operation. It is used in the AES decryption process to undo the effects
// of the SubBytes operation. The state is modified in place. The state
// must be a multiple of 16 bytes. An error is returned if the state is
// invalid.
func invSubBytes(s *state) {
	for r := range 4 {
		for c := range 4 {
			s[r][c] = invSbox[s[r][c]]
		}
	}
}

// Shift Rows operation. This operation shifts the rows of the state
// according to the given rotation. The state is modified in place.
// The state must be a multiple of 16 bytes. An error is returned if
// the state is invalid.
func shiftRows(s *state) {
	var tmp [4]byte
	for r := 1; r < 4; r++ {
		for c := range 4 {
			tmp[c] = s[r][(c+r)%4]
		}
		for c := range 4 {
			s[r][c] = tmp[c]
		}
	}
}

// Inverse Shift Rows operation. This is the inverse of the Shift Rows
// operation. It is used in the AES decryption process to undo the effects of
// the Shift Rows operation. The state is modified in place. The state
// must be a multiple of 16 bytes. An error is returned if the state is
// invalid.
func invShiftRows(s *state) {
	var tmp [4]byte
	for r := 1; r < 4; r++ {
		for c := range 4 {
			tmp[c] = s[r][(c-r+4)%4]
		}
		for c := range 4 {
			s[r][c] = tmp[c]
		}
	}
}

// Mix Column operation. This operation takes a column of 4 bytes and mixes
// the elements according to the Mix Column operation. The column is
// modified in place. The column must be a multiple of 4 bytes. An
// error is returned if the column is invalid.
func mixColumn(col *[4]byte) {
	a := col
	var t [4]byte
	t[0] = byte(gfMul(2, a[0]) ^ gfMul(3, a[1]) ^ a[2] ^ a[3])
	t[1] = byte(a[0] ^ gfMul(2, a[1]) ^ gfMul(3, a[2]) ^ a[3])
	t[2] = byte(a[0] ^ a[1] ^ gfMul(2, a[2]) ^ gfMul(3, a[3]))
	t[3] = byte(gfMul(3, a[0]) ^ a[1] ^ a[2] ^ gfMul(2, a[3]))
	for i := range 4 {
		col[i] = t[i]
	}
}

// Mix Columns operation. This operation takes a state and mixes the
// columns according to the Mix Column operation. The state is
// modified in place. The state must be a multiple of 16 bytes.
// An error is returned if the state is invalid.
func mixColumns(s *state) {
	for c := range 4 {
		var col [4]byte
		for r := range 4 {
			col[r] = s[r][c]
		}
		mixColumn(&col)
		for r := range 4 {
			s[r][c] = col[r]
		}
	}
}

// Inverse Mix Column operation. This is the inverse of the Mix Column
// operation. It is used in the AES decryption process to undo the effects of
// the Mix Column operation. The state is modified in place. The state
// must be a multiple of 16 bytes. An error is returned if the state is
// invalid.
func invMixColumn(col *[4]byte) {
	a := col
	var t [4]byte
	t[0] = byte(gfMul(14, a[0]) ^ gfMul(11, a[1]) ^ gfMul(13, a[2]) ^ gfMul(9, a[3]))
	t[1] = byte(gfMul(9, a[0]) ^ gfMul(14, a[1]) ^ gfMul(11, a[2]) ^ gfMul(13, a[3]))
	t[2] = byte(gfMul(13, a[0]) ^ gfMul(9, a[1]) ^ gfMul(14, a[2]) ^ gfMul(11, a[3]))
	t[3] = byte(gfMul(11, a[0]) ^ gfMul(13, a[1]) ^ gfMul(9, a[2]) ^ gfMul(14, a[3]))
	for i := range 4 {
		col[i] = t[i]
	}
}


// Inverse Mix Columns operation. This is the inverse of the Mix Columns
// operation. It is used in the AES decryption process to undo the effects of
// the Mix Columns operation. The state is modified in place. The state
// must be a multiple of 16 bytes. An error is returned if the state is
// invalid.
func invMixColumns(s *state) {
	for c := range 4 {
		var col [4]byte
		for r := range 4 {
			col[r] = s[r][c]
		}
		invMixColumn(&col)
		for r := range 4 {
			s[r][c] = col[r]
		}
	}
}
// addRoundKey adds a round key to the given state. The round key is added
// in a column-by-column fashion, i.e. each column of the state is
// XORed with the corresponding column of the round key. The round key
// must be a multiple of 16 bytes. An error is returned if the round
// keys are invalid. The state is modified in-place.

func addRoundKey(s *state, roundKey []byte) {
	for c := range 4 {
		for r := range 4 {
			s[r][c] ^= roundKey[c*4+r]
		}
	}
}


// EncryptBlock encrypts a single 16-byte block using the given round keys.
// The block is first transformed into a state, then the round keys are
// added in a round-by-round fashion. After each round key is added, the
// state is transformed according to the AES encryption algorithm. The
// encrypted state is then transformed back into a 16-byte block, and
// the resulting ciphertext is returned. The round keys must be a multiple of
// 16 bytes. An error is returned if the round keys are invalid. The
// encrypted ciphertext is suitable for encryption over an insecure channel.
func encryptBlock(in []byte, roundKeys []byte) []byte {
	s := bytesToState(in)
	addRoundKey(&s, roundKeys[0:16])
	for round := 1; round <= 9; round++ {
		subBytes(&s)
		shiftRows(&s)
		mixColumns(&s)
		addRoundKey(&s, roundKeys[round*16:(round+1)*16])
	}
	subBytes(&s)
	shiftRows(&s)
	addRoundKey(&s, roundKeys[10*16:11*16])
	return stateToBytes(s)
}

// DecryptBlock decrypts a single 16-byte block using the given round keys.
// The block is first XORed with the round key at round 10, then inverse
// substitutions are applied, followed by inverse row shifting and inverse mixing
// of columns. The round key at round 9 is then XORed with the result,
// followed by inverse substitutions, inverse row shifting, and inverse mixing of
// columns. The round key at round 8 is then XORed with the result,
// followed by inverse substitutions, inverse row shifting, and inverse mixing of
// columns. This process is repeated until round 1 is reached. The final
// result is then XORed with the round key at round 0, and the resulting
// plaintext is returned. The round keys are derived from the user-provided key
// using the AES key schedule. The resulting plaintext is suitable for decryption
// over an insecure channel.
func decryptBlock(in []byte, roundKeys []byte) []byte {
	s := bytesToState(in)
	addRoundKey(&s, roundKeys[10*16:11*16])
	for round := 9; round >= 1; round-- {
		invShiftRows(&s)
		invSubBytes(&s)
		addRoundKey(&s, roundKeys[round*16:(round+1)*16])
		invMixColumns(&s)
	}
	invShiftRows(&s)
	invSubBytes(&s)
	addRoundKey(&s, roundKeys[0:16])
	return stateToBytes(s)
}


// pkcs7Pad pads the given data with the PKCS#7 padding scheme
// to a multiple of the given blockSize. The padding is
// calculated as blockSize - (len(data) % blockSize), and if
// the calculated padding is zero, the blockSize is used
// instead. The padded data is suitable for encryption
// over an insecure channel.
func pkcs7Pad(data []byte) []byte {
	blockSize := 16
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := 0; i < padLen; i++ {
		out[len(data)+i] = byte(padLen)
	}
	return out
}

// pkcs7Unpad unpads the given data according to the PKCS#7 padding scheme.
// The function returns an error if the padding is invalid, and the
// unpadded data is returned if the padding is valid. The unpadded
// data is suitable for decryption over an insecure channel.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, errInvalidPadding
	}
	pad := int(data[len(data)-1])
	if pad <= 0 || pad > 16 {
		return nil, errInvalidPadding
	}
	for i := range pad {
		if data[len(data)-1-i] != byte(pad) {
			return nil, errInvalidPadding
		}
	}
	return data[:len(data)-pad], nil
}


// Encrypt encrypts a plaintext using the Advanced Encryption Standard
// (AES) algorithm with a single 32-byte key. The plaintext is first
// padded according to the PKCS#7 padding scheme, then encrypted according
// to the AES algorithm. A random 16-byte IV is generated and prepended
// to the ciphertext. The decrypted plaintext is then unpadded according
// to the PKCS#7 padding scheme, and the resulting plaintext is returned.
// The IV must be either nil or 16 bytes. An error is returned if the IV is
// invalid. The padded plaintext is suitable for encryption over an
// insecure channel. The decrypted plaintext is suitable for decryption over
// an insecure channel.
func (a *AES) Encrypt(plaintext []byte) (string, error) {
	// normalize key
	nk, err := normalizeKey(a.Key)
	if err != nil {
		return "", err
	}
	roundKeys, err := keyExpansion(nk)
	if err != nil {
		return "", err
	}

	// IV handling
	ivBuf := make([]byte, 16)
	if len(a.Iv) == 0 {
		_, err := rand.Read(ivBuf)
		if err != nil {
			return "", err
		}
	} else {
		if len(a.Iv) != 16 {
			return "", errInvalidIV
		}
		copy(ivBuf, a.Iv)
	}

	padded := pkcs7Pad(plaintext)
	out := make([]byte, len(padded))
	prev := make([]byte, 16)
	copy(prev, ivBuf)

	for i := 0; i < len(padded); i += 16 {
		block := padded[i : i+16]
		xorBlock := make([]byte, 16)
		for j := range 16 {
			xorBlock[j] = block[j] ^ prev[j]
		}
		enc := encryptBlock(xorBlock, roundKeys)
		copy(out[i:i+16], enc)
		copy(prev, enc)
	}

	// Prepend IV to ciphertext bytes and hex-encode.
	final := append(ivBuf, out...)
	return hex.EncodeToString(final), nil
}

// Decrypt decrypts a ciphertext using the Advanced Encryption Standard
// (AES) algorithm with a single 32-byte key. The ciphertext is first
// unpadded according to the PKCS#7 padding scheme, then decrypted according
// to the AES algorithm. A random 16-byte IV is prepended to the
// ciphertext. The decrypted plaintext is then unpadded according to the
// PKCS#7 padding scheme, and the resulting plaintext is returned. The IV
// must be either nil or 16 bytes. An error is returned if the IV is
// invalid. The padded plaintext is suitable for decryption over an insecure
// channel. The decrypted plaintext is suitable for decryption over an
// insecure channel.
func (a *AES) Decrypt(hexInput string) ([]byte, error) {
	data, err := hex.DecodeString(hexInput)
	if err != nil {
		return nil, errInvalidHex
	}
	if len(data) < 16 || len(data)%16 != 0 {
		return nil, errInvalidCipherLen
	}
	iv := data[:16]
	ciphertext := data[16:]
	if len(ciphertext) % 16 != 0 {
		return nil, errInvalidCipherLen
	}

	nk, err := normalizeKey(a.Key)
	if err != nil {
		return nil, err
	}
	roundKeys, err := keyExpansion(nk)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(ciphertext))
	prev := make([]byte, 16)
	copy(prev, iv)
	for i := 0; i < len(ciphertext); i += 16 {
		block := ciphertext[i : i+16]
		dec := decryptBlock(block, roundKeys)
		plain := make([]byte, 16)
		for j := range 16 {
			plain[j] = dec[j] ^ prev[j]
		}
		copy(out[i:i+16], plain)
		copy(prev, block)
	}

	// Unpad
	unp, err := pkcs7Unpad(out)
	if err != nil {
		return nil, err
	}
	return unp, nil
}
