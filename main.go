package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/manifoldco/promptui"
	"gopkg.in/yaml.v3"

	"github.com/narukoshin/cryptkit/aes"
	"github.com/narukoshin/cryptkit/des"
)

/**

Author: Naru Koshin (c) 2025
https://narukoshin.me
https://github.com/narukoshin
naru@narukoshin.me

This is a program that encrypts and decrypts plaintext using
the Advanced Encryption Standard (AES) or the Data Encryption
Standard (DES) algorithm. The program takes as input a
configuration file that specifies the algorithm, operation,
keys, and IV. The program then encrypts or decrypts the
plaintext using the specified algorithm and parameters.

This project is powered by Go, an absolute unit of a music playlist,
	and enough liters of energy drink to wake up a coma patient.

### TODO ###
	- add support to file encryption : DONE.

### Shoutout section ###
	NANOWAR OF STEEL - HelloWorld.java (https://youtu.be/yup8gIXxWDU)
		This is probably one of the best songs for programmers and made by people that aren't programmers.

	Sheeno Mirin - OSINT (https://youtu.be/N9gQqOf58mQ)
		hi- わかる、このコードは糞！ごめん。

	KAT x Aku P - Affection Addiction (https://youtu.be/UTcZHzDY3LU)
		Don't show this project to Aku, he will laugh at this code. It's too messy and I'm too lazy to clean it up.
		Btw, there is a metal cover that i just found.

	Staircatte - LOG OFF (https://youtu.be/qKOJ5_IkUXY)

**/

const Version string = "v1.0.0"

// algorithm is a type alias for string
type algorithm string

// operation is a type alias for string
type operation string

// operation constants for encrypt and decrypt
const (
	ENCRYPT operation = "Encrypt"
	DECRYPT operation = "Decrypt"
)

// I/O constants for text, file and stdout
const (
	TEXT string = "Text"
	FILE string = "File"
	STDOUT string = "Stdout"
)

// String returns the string representation of the operation.
func (o operation) String() string {
	return string(o)
}

// config is a struct that holds the configuration for the program
type config struct {
	Algorithm algorithm `yaml:"algorithm"`
	Input string `yaml:"input"`
	Operation operation `yaml:"operation"`
	Keys []string `yaml:"keys"`
	Iv string `yaml:"iv"`
	Otp string `yaml:"output_file"`
}

// c is a global variable that holds the configuration
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

// InputPrompt prompts the user for either plaintext or a file path to read
// plaintext from. If the user chooses plaintext, it prompts the user to enter
// plaintext. If the user chooses a file path, it prompts the user to enter a
// file path. It then reads the plaintext from the file and returns it as a byte
// slice. If an error occurs during this process, it returns an error.
func InputPrompt() ([]byte, error) {
	prompt := promptui.Select{
		Label: "Input",
		Items: []string{TEXT, FILE},
	}
	_, result, err := prompt.Run()
	if err != nil {
		return nil, err
	}
	switch result {
	case TEXT:
		prompt := promptui.Prompt{
			Label: "Enter the text",
		}
		plainText, err := prompt.Run()
		if err != nil {
			return nil, err
		}
		return []byte(plainText), nil
	case FILE:
		prompt := promptui.Prompt{
			Label: "Enter file path",
		}
		filePath, err := prompt.Run()
		if err != nil {
			return nil, err
		}
		file, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		return file, nil
	}
	return nil, nil
}

// IVPrompt is a function that asks the user if they want to use a random IV or
// a custom IV. If the user chooses custom, it then asks the user to input the
// IV. The IV is then validated according to the algorithm being used. If the
// IV is invalid, an error is returned. If the user chooses random, an empty
// string is returned. If an error occurs during this process, it returns an
// error.
func IVPrompt(algorithm string) (string, error) {
	ivValidator := func(input string) error {
		// des - 8 bytes
		// aes - 16 bytes
		if algorithm == "3DES" && len(input) != 8 {
			return errors.New("des iv should be 8 characters long")
		}
		if algorithm == "AES" && len(input) != 16 {
			return errors.New("aes iv should be 16 characters long")
		}
		return nil
	}
	// Select Random or custom
	prompt := promptui.Select{
		Label: "IV",
		Items: []string{"Random", "Custom"},
	}
	_, result, err := prompt.Run()
	if err != nil {
		return "", err
	}
	switch result {
	case "Random":
		return "", nil
	case "Custom":
		prompt := promptui.Prompt{
			Label: "Enter the IV",
			Validate: ivValidator,
		}
		iv, err := prompt.Run()
		if err != nil {
			return "", err
		}
		return iv, nil
	}
	return "", errors.New("invalid option")
}


// OperationPrompt prompts the user to select an operation, either
// ENCRYPT or DECRYPT. It then returns the selected operation and
// an error if one occurs. The returned operation is suitable for
// use with the Encrypt and Decrypt functions. The error is suitable
// for returning to the user.
func OperationPrompt() (operation, error) {
	prompt := promptui.Select{
		Label: "Operation",
		Items: []string{ENCRYPT.String(), DECRYPT.String()},
	}
	_, result, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return operation(result), nil
}


// OutputPrompt prompts the user to select where the output should be written.
// It then returns the selected output type and an error if one occurs.
// The returned output type is suitable for use with the Save function.
// The error is suitable for returning to the user.
func OutputPrompt(output string) error {
	// Output in file or stdout
	prompt := promptui.Select{
		Label: "Output",
		Items: []string{FILE, STDOUT},
	}
	_, result, err := prompt.Run()
	if err != nil {
		return err
	}

	switch result {
	case FILE:
		prompt := promptui.Prompt{
			Label: "Enter file path",
		}
		filePath, err := prompt.Run()
		if err != nil {
			return err
		}
		// Writing to file
		err = os.WriteFile(filePath, []byte(output), 0644)
		if err != nil {
			return err
		}
	case STDOUT:
		fmt.Fprintln(os.Stdout, output)
	}
	return nil
}

// main is the entry point of the program. It is responsible for
// parsing the arguments and loading the configuration file, if
// specified. It then prompts the user for what encryption
// algorithm to use, and whether to encrypt or decrypt. If the
// algorithm is 3DES, it prompts the user for three keys and an
// IV. If the algorithm is AES, it prompts the user for a single
// key and an IV. Finally, it encrypts or decrypts the given
// plaintext using the chosen algorithm and parameters.
func main() {
	config := flag.String("config", "", "Path to config file")
	flag.Parse()

	// Loading from the config
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

		var ptxinput []byte

		// Checking if there is a @ prefix
		if strings.HasPrefix(c.Input, "@") {
			// read file
			f, err := os.ReadFile(c.Input[1:])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			ptxinput = f
		} else {
			ptxinput = []byte(c.Input)
		}

		// switch what algorithm is being used
		switch c.Algorithm {
		case "aes":
			aes := aes.AES {
				Key: []byte(c.Keys[0]),
				Iv: []byte(c.Iv),
			}
			// switch what operation is being used
			switch strings.ToLower(c.Operation.String()) {
			case "encrypt":
				// encrypt the file
				ciphertext, err := aes.Encrypt(ptxinput)
				if err != nil {
					panic(err)
				}

				// writing output to the file
				if c.Otp != "" {
					err = os.WriteFile(c.Otp, []byte(ciphertext), 0644)
					if err != nil {
						panic(err)
					}
				} else {
					fmt.Println(ciphertext)
				}
			case "decrypt":
				// decrypt the file
				plaintext, err := aes.Decrypt(string(ptxinput))
				if err != nil {
					panic(err)
				}

				// writing output to the file
				if c.Otp != "" {
					err = os.WriteFile(c.Otp, []byte(plaintext), 0644)
					if err != nil {
						panic(err)
					}
				} else {
					fmt.Println(string(plaintext))
				}
			}
		case "des":
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

			switch strings.ToLower(c.Operation.String()) {
			case "encrypt":
				ciphertext, err := des.Encrypt(ptxinput)
				if err != nil {
					panic(err)
				}
				fmt.Println(hex.EncodeToString(ciphertext))
			case "decrypt":
				pxt, err := hex.DecodeString(string(ptxinput))
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
	// Using UI interaction mode
	} else {
		// prompt for what encryption algoritm to use 3DES or AES
		prompt := promptui.Select{
			Label: "Select algorithm",
			Items: []string{"3DES", "AES"},
		}

		_, algorithmprompt, err := prompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		keyvalidator := func(input string) error {
			if len(input) != 32 {
					return errors.New("key must be 32 characters long")
			}
			return nil
		}

		// switch what algorithm is being used
		switch algorithmprompt {
		case "3DES":
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

			c.Operation, err = OperationPrompt()
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				return
			}

			// create the DES struct
			des := des.DES {
				Key1: k1,
				Key2: k2,
				Key3: k3,
			}

			// switch what operation is being used
			switch c.Operation {
			case ENCRYPT:
				iv, err := IVPrompt(algorithmprompt)
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}
				des.Iv = []byte(iv)
				
				inputPrompt, err := InputPrompt()
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}

				ciphertext, err := des.Encrypt(inputPrompt)
				if err != nil {
					panic(err)
				}

				// print the ciphertext
				err = OutputPrompt(string(ciphertext))
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}
			case DECRYPT:
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

				// print the plaintext
				err = OutputPrompt(string(ptx))
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}
			}
		case "AES":
			// Asking for the key
			prompt := promptui.Prompt{
				Label: "Enter key",
				Validate: keyvalidator,
			}

			kprompt, err := prompt.Run()
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				return
			}
			
			c.Operation, err = OperationPrompt()
			if err != nil {
				fmt.Printf("Prompt failed %v\n", err)
				return
			}
			aes := aes.AES {
				Key: []byte(kprompt),
			}

			// switch what operation is being used
			switch c.Operation {
			case ENCRYPT: {
				// iv prompt
				ivprompt, err := IVPrompt(algorithmprompt)
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}
				aes.Iv = []byte(ivprompt)

				// Input prompt
				inputPrompt, err := InputPrompt()
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}
				
				ctx, err := aes.Encrypt(inputPrompt)
				if err != nil {
					panic(err)
				}

				// print the ciphertext
				err = OutputPrompt(string(ctx))
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}
			}
			case DECRYPT:
				// input prompt
				inputPrompt, err := InputPrompt()
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}

				ptx, err := aes.Decrypt(string(inputPrompt))
				if err != nil {
					panic(err)
				}

				// print the plaintext
				err = OutputPrompt(string(ptx))
				if err != nil {
					fmt.Printf("Prompt failed %v\n", err)
					return
				}
			}
		}
	}
}