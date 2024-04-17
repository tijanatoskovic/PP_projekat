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
	"io/ioutil"
	"log"
	"os"

	"github.com/tijanatoskovic/PP_projekat/filecrypt"
	"golang.org/x/term"
)

func main() {
	var function string
	fmt.Println("Do you want to encrypt (e) or decrypt (d) file?")
	fmt.Scanln(&function)

	switch function {
	case "help":
		printHelp()
	case "e":
		encryptHandle()
	case "d":
		decryptHandle()
	default:
		fmt.Println("Run:\t\"go run . help\"\tfor usage.")
		os.Exit(1)
	}
}

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var encryptedData []byte
var encryptedAESKey []byte

func encryptHandle() {

	var algorithm string
	var filePath string

	fmt.Println("Choose which algorithm you want to use[AES | RSA | ECC]: ")
	fmt.Println("Note! RSA and ECC algorithms only support text files becouse of complexity of algorithms!")
	fmt.Scanln(&algorithm)
	fmt.Println("Enter path to file you want to encrypt/decrypt: ")
	fmt.Scanln(&filePath)
	if !validateFile(filePath) {
		fmt.Println("File not found.")
		os.Exit(1)
	}

	var err error

	switch algorithm {
	case "AES":
		password := getPassword()
		fmt.Println("\nEncrypting...")
		filecrypt.EncryptAES(filePath, password)
		fmt.Println("\nFile succesfully encrypted!")
	case "RSA":
		// Generate RSA keys
		privateKey, publicKey, err = filecrypt.GenerateRSAKeys()
		if err != nil {
			log.Fatalf("Error generating RSA keys: %v", err)
		}

		// Read the file to be encrypted
		fileData, err := ioutil.ReadFile(filePath)
		if err != nil {
			log.Fatalf("Error reading file: %v", err)
		}
		var aesKey []byte
		// Encrypt the file with AES
		encryptedData, aesKey, err = filecrypt.EncryptWithAES(fileData)
		if err != nil {
			log.Fatalf("Error encrypting file data: %v", err)
		}
		err = ioutil.WriteFile("encrypted_data.txt", encryptedData, 0644)
		if err != nil {
			log.Fatalf("Error writing byte code: %v", err)
		}
		err = savePrivateKeyToFile(privateKey, "private_key.txt")
		if err != nil {
			log.Fatalf("Error saving private key: %v", err)
		}

		// Encrypt the AES key with RSA
		encryptedAESKey, err = filecrypt.EncryptKeyWithRSA(aesKey, publicKey)
		if err != nil {
			log.Fatalf("Error encrypting RSA key: %v", err)
		}
		err = ioutil.WriteFile("encryptedAESkey.txt", encryptedAESKey, 0644)
		if err != nil {
			log.Fatalf("Error writing byte code: %v", err)
		}

		err = ioutil.WriteFile(filePath, encryptedData, 0644)

	}
}

func decryptHandle() {
	var algorithm string
	var filePath string

	fmt.Println("Choose which algorithm you had encrypted with [AES | RSA | ECC]: ")
	fmt.Scanln(&algorithm)
	fmt.Println("Enter path to file you want to encrypt/decrypt: ")
	fmt.Scanln(&filePath)
	if !validateFile(filePath) {
		fmt.Println("File not found.")
		os.Exit(1)
	}

	switch algorithm {
	case "AES":
		fmt.Print("Enter password:")
		password, _ := term.ReadPassword(0)
		fmt.Println("\nDecrypting...")
		filecrypt.DecryptAES(filePath, password)
		fmt.Println("\nFile successfully decrypted")
	case "RSA":
		// Decrypt the AES key with RSA
		var err error

		privateKey, err = loadPrivateKeyFromFile("private_key.txt")
		if err != nil {
			log.Fatalf("FIled loading private key: %v", err)
		}
		encryptedData, err = ioutil.ReadFile("encrypted_data.txt")
		if err != nil {
			log.Fatalf("Error reading file data: %v", err)
		}
		encryptedAESKey, err = ioutil.ReadFile("encryptedAESkey.txt")
		if err != nil {
			log.Fatalf("Error reading file data: %v", err)
		}
		decryptedAESKey, err := filecrypt.DecryptKeyWithRSA([]byte(encryptedAESKey), privateKey)
		if err != nil {
			log.Fatalf("Error decrypting AES key: %v", err)
		}

		// Decrypt the file with AES
		decryptedData, err := filecrypt.DecryptWithAES([]byte(encryptedData), decryptedAESKey)
		if err != nil {
			log.Fatalf("Error decrypting file data: %v", err)
		}
		if err != nil {
			log.Fatalf("Error writing back to file: %v", err)
		}
		// Write the decrypted data back to the file (can replace with encryptedData to save encrypted file)
		err = ioutil.WriteFile(filePath, decryptedData, 0644)
		if err != nil {
			log.Fatalf("Error writing back to file: %v", err)
		}

		log.Println("File encryption and decryption completed successfully")
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
