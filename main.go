package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"

	"os"

	"github.com/manifoldco/promptui"

	"github.com/narukoshin/cryptkit/des"
	"gopkg.in/yaml.v3"
)

type algorithm string
type operation string

type config struct {
	Algorithm algorithm `yaml:"algorithm"`
	Input string `yaml:"input"`
	Operation operation `yaml:"operation"`
	Keys []string `yaml:"keys"`
	Iv string `yaml:"iv"`
}

var c config

// Validation checks if the algorithm and operation are valid.
// If the algorithm is not aes or des, or if the operation is not
// encrypt or decrypt, it prints an error message and exits with
// status 1.
func Validation() {
	if c.Algorithm != "aes" && c.Algorithm != "des" {
			fmt.Printf("Algorithm must be aes or des. Got %v.\n", c.Algorithm)
			os.Exit(1)
		}
		if c.Operation != "encrypt" && c.Operation != "decrypt" {
			fmt.Printf("Operation must be encrypt or decrypt. Got %v.\n", c.Operation)
			os.Exit(1)
		}
}

// main is the entry point for the program. It parses flags and then either
// reads a config file or prompts the user for input. It then validates the
// input and then performs the desired operation based on the algorithm
// selected. If the algorithm is AES, it prompts for a key and then
// encrypts or decrypts the input. If the algorithm is DES, it prompts
// for three keys and an IV, and then encrypts or decrypts the input.
// If there is an error, it prints an error message and exits with status 1.
func main() {
	config := flag.String("config", "", "Path to config file")
	flag.Parse()

	if *config != "" {
		// Config mode
		if _, err := os.Stat(*config); err != nil {
			fmt.Println("Config file does not exist.")
			os.Exit(1)
		}

		// read config file
		file, err := os.ReadFile(*config)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		err = yaml.Unmarshal(file, &c)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		Validation()

		// switch what algorithm is being used
		switch c.Algorithm {
		case "aes":
			// switch what operation is being used
			switch c.Operation {
			case "encrypt":
				// encrypt the file
			case "decrypt":
				// decrypt the file
			}
		case "des":
			if c.Iv == "" {
				fmt.Println("IV is required for DES.")
				os.Exit(1)
			}
			if len(c.Keys) != 3 {
				fmt.Println("DES requires 3 keys.")
				os.Exit(1)
			}

			k1, _ := hex.DecodeString(c.Keys[0])
			k2, _ := hex.DecodeString(c.Keys[1])
			k3, _ := hex.DecodeString(c.Keys[2])

			des := des.DES {
				Key1: []byte(k1),
				Key2: []byte(k2),
				Key3: []byte(k3),
				Iv: []byte(c.Iv),
			}

			switch c.Operation {
			case "encrypt":
				ciphertext, err := des.Encrypt([]byte(c.Input))
				if err != nil {
					panic(err)
				}
				fmt.Println(hex.EncodeToString(ciphertext))
			case "decrypt":
				pxt, err := hex.DecodeString(c.Input)
				if err != nil {
					panic(err)
				}
				plaintext, err := des.Decrypt(pxt)
				if err != nil {
					panic(err)
				}
				fmt.Println(string(plaintext))
			}
		}
	} else {
		// prompt for what encryption algoritm to use 3DES or AES
		prompt := promptui.Select{
			Label: "Select algorithm",
			Items: []string{"3DES", "AES"},
		}

		_, result, err := prompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		// switch what algorithm is being used
		switch result {
		case "3DES":
			keyvalidator := func(input string) error {
				if len(input) != 32 {
						return errors.New("key must be 32 characters long")
					}
					return nil
			}

			c.Algorithm = "des"
			// key 1 prompt
			// validate key length
			prompt := promptui.Prompt{
				Label: "Enter key 1",
				Validate: keyvalidator,
			}

			k1prompt, err := prompt.Run()
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				return
			}

			k1, err := hex.DecodeString(k1prompt)
			if err != nil {
				panic(err)
			}

			// key 2 prompt
			prompt = promptui.Prompt{
				Label: "Enter key 2",
				Validate: keyvalidator,
			}

			k2prompt, err := prompt.Run()
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				return
			}

			k2, err := hex.DecodeString(k2prompt)
			if err != nil {
				panic(err)
			}

			// key 3 prompt
			prompt = promptui.Prompt{
				Label: "Enter key 3",
				Validate: keyvalidator,
			}

			k3prompt, err := prompt.Run()
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				return
			}

			k3, err := hex.DecodeString(k3prompt)
			if err != nil {
				panic(err)
			}

			// Operation prompt
			prompt2 := promptui.Select{
				Label: "Select operation",
				Items: []string{"encrypt", "decrypt"},
			}

			_, operationprompt, err := prompt2.Run()
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				return
			}
			c.Operation = operation(operationprompt)

			des := des.DES {
				Key1: k1,
				Key2: k2,
				Key3: k3,
			}

			// switch what operation is being used
			switch c.Operation {
			case "encrypt":

				// random IV or custom
				prompt := promptui.Select{
					Label: "Select IV",
					Items: []string{"Random", "Custom"},
				}

				_, ivtypeprompt, err := prompt.Run()
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}
				if ivtypeprompt == "Custom" {
					// Prompting input
					ivprompt := promptui.Prompt{
						Label: "Enter IV",
						Validate: func(input string) error {
							if len(input) != 8 {
								return errors.New("IV must be 8 bytes")
							}
							return nil
						},
					}

					iv, err := ivprompt.Run()
					if err != nil {
						fmt.Printf("Prompt failed %v\n", err)
						return
					}
					des.Iv = []byte(iv)
				}

				// Asking for plain text input
				ptxprompt := promptui.Prompt{
					Label: "Enter plain text",
				}

				plaintext, err := ptxprompt.Run()
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}
				c.Input = plaintext

				ciphertext, err := des.Encrypt([]byte(c.Input))
				if err != nil {
					panic(err)
				}
				fmt.Println(hex.EncodeToString(ciphertext))
				
			case "decrypt":
				// decrypt the file
				prompt = promptui.Prompt{
					Label: "Enter cipher text",
				}

				ciphertext, err := prompt.Run()
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}
				c.Input = ciphertext

				ctx, err := hex.DecodeString(ciphertext)
				if err != nil {
					panic(err)
				}

				ptx, err := des.Decrypt(ctx)
				if err != nil {
					panic(err)
				}
				fmt.Println(string(ptx))
			}
		case "AES":
			c.Algorithm = "aes"

			fmt.Println("Under construction")
		}

	}
}