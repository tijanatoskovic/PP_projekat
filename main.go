/*First: we accept arguments from user
Second:
	- we validate the file (see if the file exists)
	- ask for a password and validate it (for the encryption)
Finally: we encrypt/decrypt the file*/

/*				ENCRYPTION
We will create a random variable "nonce" which will be 12 bytes
and we will randomize it
The algorihtm we will be using is SHA-1
*/

/*				DECRYPTION
We will again ask for the password, then we will read the nonce by
reading the last 12 digits of the encrypted file
*/

/*
We will be encrypting and decrypting a text passed by the user
USING THE CEASER CIPHER
For example: 	HELLOWORLD		our key will be for now: 5

the original text: ABCDEFGHIJKLMOPQRSTUVWXYZ

	26 - (key)5 = 21	/		\
					  /			  \
		ABCDEFGHIJKLMOPQRSTU	  VWXYZ

the hashed text:	VWXYZABCDEFGHIJKLMOPQRSTU

	index of H in original text: 8
	and we aplly the formula:
	pos + len(original letters)) % len(original letters)
	In put case:	(8+26)%26 = 8
	H -----> C
*/
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/tijanatoskovic/PP_projekat/filecrypt"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	function := os.Args[1]

	switch function {
	case "help":
		printHelp()
	case "encryptFile":
		encryptHandle()
	case "decryptFile":
		decryptHandle()
	default:
		fmt.Println("Run:\t\"go run . help\"\tfor usage.")
		os.Exit(1)
	}
}

func encryptHandle() {
	if len(os.Args) < 4 {
		println("Missing the path to the file. For more info run go run . help")
		os.Exit(0)
	}
	algorithm := os.Args[2]
	filePath := os.Args[3]

	if !validateFile(filePath) {
		fmt.Println("File not found.")
		os.Exit(1)
	}

	switch algorithm {
	case "AES":
		password := getPassword()
		fmt.Println("\nEncrypting...")
		filecrypt.EncryptAES(filePath, password)
		fmt.Println("\nFile succesfully encrypted! Congratulations motherfuckers!")
	case "RSA":
		keyFile := os.Args[4]
		privateKey, err := loadPrivateKeyFromFile("private.pem")
		if err != nil {
			fmt.Println("Error loading private key:", err)
			os.Exit(1)
		}

		err = filecrypt.EncryptRSA("daisy.jpg", privateKey)
		if err != nil {
			fmt.Println("Error encrypting file:", err)
			os.Exit(1)
		}

		err = savePrivateKeyToFile(privateKey, keyFile)
		if err != nil {
			fmt.Println("Error saving private key:", err)
			return
		}

		fmt.Println("\nFile successfully encrypted with RSA")
	}
}

func decryptHandle() {
	if len(os.Args) < 3 {
		println("Missing arguments. Usage: go run . decryptFile RSA /path/to/your/file private_key.pem")
		os.Exit(0)
	}
	algorithm := os.Args[2]
	filePath := os.Args[3]

	if !validateFile(filePath) {
		fmt.Println("File not found.")
		os.Exit(1)
	}

	switch algorithm {
	case "AES":
		fmt.Print("Enter password:")
		password, _ := term.ReadPassword(0)
		fmt.Println("\nDecrypting...")
		filecrypt.Decrypt(filePath, password)
		fmt.Println("\nFile successfully decrypted")
	case "RSA":
		keyFile := os.Args[4]
		privateKey, err := loadPrivateKeyFromFile(keyFile)
		if err != nil {
			fmt.Println("Error loading private key:", err)
			os.Exit(1)
		}

		fmt.Println("\nDecrypting...")
		err = filecrypt.DecryptRSA(filePath, privateKey)
		if err != nil {
			fmt.Println("Error decrypting file:", err)
			os.Exit(1)
		}

		fmt.Println("\nFile successfully decrypted with RSA")
	}
}

func getPassword() []byte {
	fmt.Print("Enter password:")
	password, _ := term.ReadPassword(0)
	fmt.Print("\nConfirm Password: ")
	passwordConfirm, _ := term.ReadPassword(0)
	if !validatePassword(password, passwordConfirm) {
		fmt.Print("\nPasswords do no match. Please try again\n")
		return getPassword()
	}
	return password
}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}

func validatePassword(password1 []byte, password2 []byte) bool {
	return bytes.Equal(password1, password2)
}

func savePrivateKeyToFile(privateKey *rsa.PrivateKey, filename string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := pem.Encode(file, privateKeyPEM); err != nil {
		return err
	}

	fmt.Println("Private key saved to", filename)
	return nil
}

func loadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(file)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func printHelp() {
	fmt.Println("file encryption")
	fmt.Println("Simple file encrypter for your day-to-day needs.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("\tgo run . encryptFile [algorithm] /path/to/your/file [private_key_file.pem]")
	fmt.Println("\tgo run . decryptFile [algorithm] /path/to/your/file [private_key_file.pem]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("")
	fmt.Println("\t encryptFile\tEncrypts a file using the specified algorithm")
	fmt.Println("\t decryptFile\tDecrypts a file using the specified algorithm")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println("")
}
