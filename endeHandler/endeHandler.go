package endehandler

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/tijanatoskovic/PP_projekat/filecrypt"
	"github.com/tijanatoskovic/PP_projekat/files"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var encryptedData []byte
var encryptedAESKey []byte
var passs []byte

func EncryptHandle(filePath string) {

	//var algorithm string

	optAlgorithm, err := ioutil.ReadFile("tempAlg.txt")
	if err != nil {
		panic("Error reading file")
	}
	if err := os.Remove("tempAlg.txt"); err != nil {
		panic("Error removing file")
	}

	fmt.Println(string(optAlgorithm))

	// fmt.Println("Choose which algorithm you want to use[AES | RSA | ECC]: ")
	// fmt.Println("Note! RSA and ECC algorithms only support text files becouse of complexity of algorithms!")
	// //fmt.Scanln(&algorithm)
	// fmt.Println("Enter path to file you want to encrypt/decrypt: ")
	// fmt.Scanln(&filePath)
	// if !validateFile(filePath) {
	// 	fmt.Println("File not found.")
	// 	os.Exit(1)
	// }

	switch string(optAlgorithm) {
	case "AES":
		fmt.Println(passs)
		password := passs
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
		err = files.SavePrivateKeyToFile(privateKey, "private_key.txt")
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
		if err != nil {
			fmt.Println("Error while writing the filePath!")
			return
		}
		fmt.Println("File sucessfully encrypted!")

	}
}

func DecryptHandle(filePath string) {

	// fmt.Println("Choose which algorithm you had encrypted with [AES | RSA | ECC]: ")
	// fmt.Scanln(&algorithm)
	// fmt.Println("Enter path to file you want to encrypt/decrypt: ")
	// fmt.Scanln(&filePath)
	//fmt.Println(filePath)
	if !files.ValidateFile(filePath) {
		fmt.Println("File not found.")
		os.Exit(1)
	}

	optAlgorithm, err := ioutil.ReadFile("tempAlg.txt")
	if err != nil {
		panic("Error reading file")
	}
	if err := os.Remove("tempAlg.txt"); err != nil {
		panic("Error removing file")
	}
	fmt.Println(filePath, optAlgorithm)

	switch string(optAlgorithm) {
	case "AES":
		password := passs
		fmt.Println("\nDecrypting...")
		filecrypt.DecryptAES(filePath, password)
		fmt.Println("\nFile successfully decrypted")
	case "RSA":
		// Decrypt the AES key with RSA
		var err error
		privateKey, err = files.LoadPrivateKeyFromFile("private_key.txt")
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

		log.Println("File decryption completed successfully")

		if err := os.Remove("encrypted_data.txt"); err != nil {
			panic("Error while deleting files!")
		}
		if err := os.Remove("encryptedAESkey.txt"); err != nil {
			panic("Error while deleting files!")
		}
		if err := os.Remove("private_key.txt"); err != nil {
			panic("Error while deleting files!")
		}
	}

}
