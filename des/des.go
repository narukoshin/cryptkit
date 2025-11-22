package des

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// DES struct holds the 3 keys and the IV
// The keys are 16 bytes each
// The IV is 8 bytes
// Key total length is 48
type DES struct {
	Key1 []byte // 16 bytes
	Key2 []byte // 16 bytes
	Key3 []byte // 16 bytes

	Iv []byte // 8 bytes
}


// This code implements the Triple Data Encryption Algorithm (TDEA) in Go.
// TDEA is a block cipher that encrypts data in blocks of 8 bytes, using
// three 8-byte DES keys derived from a single 48-byte key. The algorithm
// is E(K1), D(K2), E(K3), where E and D are the DES encryption and decryption
// functions, respectively. The resulting ciphertext is suitable for transmission
// over an insecure channel.

// Initial permutation
var ip = []int{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

// Final permutation
var fp = []int{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
}

// Expansion permutation
var pc1 = []int{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

// Permutation after expansion
var pc2 = []int{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
}

// Key shift table
var keyShifts = []int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

// Expansion bit table
var ebit = []int{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
}

// Permutation box
var pbox = []int{
	16, 7, 20, 21, 29, 12, 28, 17,
	1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9,
	19, 13, 30, 6, 22, 11, 4, 25,
}

// S-Boxes
var sBoxes = [8][64]byte{
	{ // S-Box 1
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
	},
	{ // S-Box 2
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
	},
	{ // S-Box 3
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
	},
	{ // S-Box 4
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
	},
	{ // S-Box 5
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
	},
	{ // S-Box 6
		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
	},
	{ // S-Box 7
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
	},
	{ // S-Box 8
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
	},
}


// getBit extracts a single bit from value at position pos (1-based) with bitlength bitlen.
// The result is a uint64 with the extracted bit set to 1 if the bit is set, and 0 otherwise.
func getBit(value uint64, pos int, bitlen int) uint64 {
	shift := uint(bitlen - pos)
	return (value >> shift) & 1
}

// Set the bit at position pos (1-based) in value to b (0 or 1).
// The result is a uint64 with the bit set to b.
// bitlen is the total number of bits in value.
// Returns value with the bit set to b.
func setBit(value uint64, pos int, bitlen int, b uint64) uint64 {
	shift := uint(bitlen - pos)
	if b&1 == 1 {
		return value | (1 << shift)
	}
	return value & ^(uint64(1) << shift)
}

// permuteBits takes an input uint64 and permutes its bits according to the
// given table of indices. The resulting uint64 has the same bitlength as
// the input. The table should be a slice of int's, where each int is
// the index of a bit to be permuted to its corresponding position in the
// output (1-based). The output is a uint64 with the permuted bits set
// accordingly.
func permuteBits(input uint64, bitlen int, table []int) uint64 {
	var out uint64 = 0
	for i, t := range table {
		b := getBit(input, t, bitlen)
		out = setBit(out, i+1, len(table), b)
	}
	return out
}

// leftRotate28 rotates v left by n bits. n is taken modulo 28.
// The result is a uint32 with the rotated bits set accordingly.
func leftRotate28(v uint32, n int) uint32 {
	n = n % 28
	return ((v << n) & 0x0FFFFFFF) | (v >> (28-n))
}

// generateSubkeys generates 16 subkeys from a given key.
// The key is first permuted according to the pc1 table, then
// split into two 28-bit halves, c and d. The halves are then
// left rotated according to the keyShifts table, and permuted
// according to the pc2 table. The 16 resulting subkeys are
// stored in the subkeys slice.
func generateSubkeys(key uint64) [16]uint64 {
	pc1Out := permuteBits(key, 64, pc1)
	var c uint32 = uint32((pc1Out >> 28) & 0x0FFFFFFF)
	var d uint32 = uint32(pc1Out & 0x0FFFFFFF)

	var subkeys [16]uint64
	for i := range 16 {
		c = leftRotate28(c, keyShifts[i])
		d = leftRotate28(d, keyShifts[i])
		cd := uint64(c)<<28 | uint64(d)
		k := permuteBits(cd, 56, pc2)
		subkeys[i] = k
	}
	return subkeys
}

// expand32to48 expands a 32-bit value r into a 48-bit value by permuting its bits
// according to the ebit table. The result is a uint64 with the permuted bits set
// accordingly.
func expand32to48(r uint32) uint64 {
	return permuteBits(uint64(r), 32, ebit)
}

// sBoxSubstitute substitutes a 48-bit value in using the 8 sBoxes tables.
// The result is a uint32 with the substituted bits set accordingly.
// The sBoxes tables are derived from the DES S-Boxes.
func sBoxSubstitute(in48 uint64) uint32 {
	var out32 uint32 = 0
	for i := range 8 {
		shift := uint(48 - (i+1)*6)
		six := byte((in48 >> shift) & 0x3F)
		row := ((six>>5)&0x1)<<1 | (six & 0x1)
		col := (six >> 1) & 0x0F
		idx := int(row<<4 | col)
		val := sBoxes[i][idx]
		out32 = (out32 << 4) | uint32(val&0xF)
	}
	return out32
}

// pPermutation takes a 32-bit value and permutes its bits according to the
// pbox table. The result is a uint32 with the permuted bits set accordingly.
// The pbox table is derived from the DES P-Box.
func pPermutation(in32 uint32) uint32 {
	return uint32(permuteBits(uint64(in32), 32, pbox))
}

// fFunction takes a 32-bit value r and a 48-bit subkey, expands r to 48 bits,
// XORs it with the subkey, substitutes the result using the 8 sBoxes tables,
// and permutes the substituted result according to the pbox table.
// The result is a uint32 with the permuted bits set accordingly.
func fFunction(r uint32, subkey uint64) uint32 {
	expanded := expand32to48(r)
	xored := expanded ^ (subkey & ((1<<48)-1))
	sboxed := sBoxSubstitute(xored)
	return pPermutation(sboxed)
}

// Encrypt a single 8-byte block using the given 8-byte key.
// The key is first expanded into 16 48-bit subkeys, then the
// block is permuted according to the initial permutation (ip),
// divided into two 32-bit halves, l and r. For each of the 16
// subkeys, the right half r is expanded to 48 bits, XORed with
// the subkey, substituted using the 8 sBoxes tables, and
// permuted using the pbox table. The result is then XORed with
// the left half l, and the halves are swapped. The final two
// halves are then permuted according to the final permutation (fp),
// and the resulting 8-byte block is returned.
func encryptBlock(plain8 []byte, key8 []byte) ([]byte, error) {
	if len(plain8) != 8 || len(key8) != 8 {
		return nil, errors.New("encryptBlock: block and key must be 8 bytes")
	}
	block := binary.BigEndian.Uint64(plain8)
	key := binary.BigEndian.Uint64(key8)

	ipOut := permuteBits(block, 64, ip)
	l := uint32((ipOut >> 32) & 0xFFFFFFFF)
	r := uint32(ipOut & 0xFFFFFFFF)
	subkeys := generateSubkeys(key)

	for i := 0; i < 16; i++ {
		temp := r
		fout := fFunction(r, subkeys[i])
		r = l ^ fout
		l = temp
	}
	preout := (uint64(r) << 32) | uint64(l)
	cipher := permuteBits(preout, 64, fp)
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, cipher)
	return out, nil
}

// Decrypt a single 8-byte block using the given 8-byte key.
// The key is first expanded into 16 48-bit subkeys, then the
// block is permuted according to the initial permutation (ip),
// divided into two 32-bit halves, l and r. For each of the 16
// subkeys, the right half r is expanded to 48 bits, XORed with
// the subkey, substituted using the 8 sBoxes tables, and
// permuted using the pbox table. The result is then XORed with
// the left half l, and the halves are swapped. The final two
// halves are then permuted according to the final permutation (fp),
// and the resulting 8-byte block is returned.
func decryptBlock(cipher8 []byte, key8 []byte) ([]byte, error) {
	if len(cipher8) != 8 || len(key8) != 8 {
		return nil, errors.New("decryptBlock: block and key must be 8 bytes")
	}
	block := binary.BigEndian.Uint64(cipher8)
	key := binary.BigEndian.Uint64(key8)

	ipOut := permuteBits(block, 64, ip)
	l := uint32((ipOut >> 32) & 0xFFFFFFFF)
	r := uint32(ipOut & 0xFFFFFFFF)
	subkeys := generateSubkeys(key)

	for i := 15; i >= 0; i-- {
		temp := r
		fout := fFunction(r, subkeys[i])
		r = l ^ fout
		l = temp
	}
	preout := (uint64(r) << 32) | uint64(l)
	plain := permuteBits(preout, 64, fp)
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, plain)
	return out, nil
}

// deriveDESKeyFrom16 derives a single 8-byte DES key from a 16-byte key by
// XORing the two halves of the key together. The resulting key is
// suitable for use with the DES encryption algorithm.
func deriveDESKeyFrom16(k16 []byte) ([]byte, error) {
	if len(k16) != 16 {
		return nil, errors.New("deriveDESKeyFrom16: key must be 16 bytes")
	}
	out := make([]byte, 8)
	for i := range 8 {
		out[i] = k16[i] ^ k16[8+i]
	}
	return out, nil
}

// tripleDESEncryptBlock16 encrypts a single 8-byte block using the Triple Data
// Encryption Algorithm (TDEA) with three 8-byte DES keys derived from a
// single 48-byte key. The three keys are derived by XORing the two halves
// of the key together. The algorithm is E(K1), D(K2), E(K3), where E and D
// are the DES encryption and decryption functions, respectively. The resulting
// ciphertext is suitable for transmission over an insecure channel.
func tripleDESEncryptBlock16(plain8 []byte, key48 []byte) ([]byte, error) {
	if len(key48) != 48 {
		return nil, errors.New("tripleDESEncryptBlock16: key must be 48 bytes (3 * 16)")
	}
	// derive three 8-byte DES keys
	k1d, err := deriveDESKeyFrom16(key48[0:16])
	if err != nil {
		return nil, err
	}
	k2d, err := deriveDESKeyFrom16(key48[16:32])
	if err != nil {
		return nil, err
	}
	k3d, err := deriveDESKeyFrom16(key48[32:48])
	if err != nil {
		return nil, err
	}

	// E(K1)
	c1, err := encryptBlock(plain8, k1d)
	if err != nil {
		return nil, err
	}
	// D(K2)
	c2, err := decryptBlock(c1, k2d)
	if err != nil {
		return nil, err
	}
	// E(K3)
	c3, err := encryptBlock(c2, k3d)
	if err != nil {
		return nil, err
	}
	return c3, nil
}

// tripleDESDecryptBlock16 decrypts a single 8-byte block using the given 48-byte
// key. The key is first expanded into three 8-byte DES keys, then the block
// is decrypted according to the reverse of the triple DES encryption algorithm, i.e.
// D(K3), E(K2), D(K1). The resulting plaintext is suitable for decryption over an
// insecure channel.
func tripleDESDecryptBlock16(cipher8 []byte, key48 []byte) ([]byte, error) {
	if len(key48) != 48 {
		return nil, errors.New("tripleDESDecryptBlock16: key must be 48 bytes (3 * 16)")
	}
	k1d, err := deriveDESKeyFrom16(key48[0:16])
	if err != nil {
		return nil, err
	}
	k2d, err := deriveDESKeyFrom16(key48[16:32])
	if err != nil {
		return nil, err
	}
	k3d, err := deriveDESKeyFrom16(key48[32:48])
	if err != nil {
		return nil, err
	}

	p1, err := decryptBlock(cipher8, k3d)
	if err != nil {
		return nil, err
	}
	p2, err := encryptBlock(p1, k2d)
	if err != nil {
		return nil, err
	}
	p3, err := decryptBlock(p2, k1d)
	if err != nil {
		return nil, err
	}
	return p3, nil
}

// pkcs7Pad pads the given data with the PKCS#7 padding scheme
// to a multiple of the given blockSize. The padding is
// calculated as blockSize - (len(data) % blockSize), and if
// the calculated padding is zero, the blockSize is used
// instead. The padded data is suitable for encryption
// over an insecure channel.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// pkcs7Unpad removes the PKCS#7 padding from the given data.
// It returns the unpadded data and an error if the padding is invalid.
// The blockSize parameter specifies the block size of the data, which must be a multiple of the size of the padding.
// The function returns an error if the padded data is invalid (i.e. if the padding bytes do not match the padding length).
// The function returns the unpadded data and an error if the padding is invalid.
// The unpadded data is suitable for decryption over an insecure channel.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data")
	}
	p := data[len(data)-1]
	if p == 0 || int(p) > blockSize {
		return nil, errors.New("invalid padding")
	}
	for i := 0; i < int(p); i++ {
		if data[len(data)-1-i] != p {
			return nil, errors.New("invalid padding bytes")
		}
	}
	return data[:len(data)-int(p)], nil
}


// Encrypt encrypts a plaintext using the Triple Data Encryption Algorithm
// (TDEA) with a single 48-byte key. The plaintext is first padded
// according to the PKCS#7 padding scheme, then encrypted according
// to the TDEA algorithm. A random 8-byte IV is generated and
// prepended to the ciphertext. The decrypted plaintext is then
// unpadded according to the PKCS#7 padding scheme, and the resulting
// plaintext is returned. The IV must be either nil or 8 bytes.
// An error is returned if the IV is invalid. The padded plaintext is
// suitable for encryption over an insecure channel. The decrypted
// plaintext is suitable for decryption over an insecure channel.
func (d *DES) Encrypt(plaintext []byte) ([]byte, error) {
	key48 := append(append(d.Key1, d.Key2...), d.Key3...)
	if len(key48) != 48 {
		return nil, errors.New("TripleDESEncryptCBC: key must be 48 bytes (3 * 16)")
	}

	blockSize := 8
	data := pkcs7Pad(plaintext, blockSize)

	ivBuf := make([]byte, 8)

	// Generate a random 8-byte IV if not provided
	if len(d.Iv) == 0 {
		_, err := rand.Read(ivBuf)
		if err != nil {
			return nil, err
		}
	} else {
		// Use the provided IV
		copy(ivBuf, d.Iv)
	}

	out := make([]byte, 0, 8+len(data))

	// Prepend the IV to the ciphertext
	out = append(out, ivBuf...)

	prev := make([]byte, 8)
	copy(prev, ivBuf)

	for i := 0; i < len(data); i += 8 {
		block := make([]byte, 8)
		copy(block, data[i:i+8])
		for j := 0; j < 8; j++ {
			block[j] ^= prev[j]
		}
		enc, err := tripleDESEncryptBlock16(block, key48)
		if err != nil {
			return nil, err
		}
		out = append(out, enc...)
		copy(prev, enc)
	}
	return out, nil
}

// Decrypt decrypts a ciphertext using the Triple Data
// Encryption Algorithm (TDEA) with a single 48-byte key. The
// key is first expanded into three 8-byte DES keys, then the
// ciphertext is decrypted according to the reverse of the TDEA
// algorithm, i.e. D(K3), E(K2), D(K1). The resulting plaintext is
// suitable for decryption over an insecure channel. If the given IV is
// nil, a random 8-byte IV is generated and prepended to the
// ciphertext. Otherwise, the given IV is used verbatim. The IV
// must be either nil or 8 bytes. An error is returned if the IV is
// invalid. The padded plaintext is then unpadded according to the
// PKCS#7 padding scheme, and the resulting plaintext is returned.
func (d *DES) Decrypt(ciphertextWithIV []byte) ([]byte, error) {
	key48 := append(append(d.Key1, d.Key2...), d.Key3...)

	if len(key48) != 48 {
		return nil, errors.New("TripleDESDecryptCBC: key must be 48 bytes (3 * 16)")
	}
	if len(ciphertextWithIV) < 8 {
		return nil, errors.New("ciphertext too short; missing IV")
	}
	if (len(ciphertextWithIV)-8)%8 != 0 {
		return nil, errors.New("cipher length after IV must be multiple of 8")
	}

	iv := make([]byte, 8)
	copy(iv, ciphertextWithIV[:8])
	ciphertext := ciphertextWithIV[8:]

	out := make([]byte, 0, len(ciphertext))
	prev := make([]byte, 8)
	copy(prev, iv)

	for i := 0; i < len(ciphertext); i += 8 {
		block := ciphertext[i : i+8]
		dec, err := tripleDESDecryptBlock16(block, key48)
		if err != nil {
			return nil, err
		}
		for j := range 8 {
			dec[j] ^= prev[j]
		}
		out = append(out, dec...)
		copy(prev, block)
	}
	return pkcs7Unpad(out, 8)
}