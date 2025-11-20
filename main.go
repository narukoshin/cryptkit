package main

import (
	"encoding/hex"
	"fmt"

	"github.com/narukoshin/cryptkit/des"

)

func main() {
	k1, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	k2, _ := hex.DecodeString("102132435465768798A9BACCADAEAF0F")
	k3, _ := hex.DecodeString("FFEEDDCCBBAA99887766554433221100")

	des := des.DES{
		Key1: k1,
		Key2: k2,
		Key3: k3,
		Iv:   []byte("00000000"),
	}

	ciphertext, err := des.Encrypt([]byte("MY NAME IS RALF"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Ciphertext (hex, IV prepended): %X\n", ciphertext)

	decrypted, err := des.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", string(decrypted))
}