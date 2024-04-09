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

package main

import (
	"bytes"
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
	case "encrypt":
		encryptHandle()
	case "decrypt":
		decryptHandle()
	default:
		fmt.Println("Run encrypt to encrypt a file, and decrypt to decrypt a file.")
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("file encryption")
	fmt.Println("Simple file encrypter for your day-to-day needs.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("\tgo run . encrypt /path/to/your/file")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("")
	fmt.Println("\t encrypt\tEncrypts a file given a password")
	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println("")

}

func encryptHandle() {
	if len(os.Args) < 3 {
		println("Missing the path to the file. More more info run go run . help")
		os.Exit(0)
	}

	file := os.Args[2] //the password
	if !validateFile(file) {
		panic("File not found")
	}

	password := getPassword()
	fmt.Println("\nEncrypting...")
	filecrypt.Encrypt(file, password)
	fmt.Println("\n file sucessfully protected")
}

func decryptHandle() {
	if len(os.Args) < 3 {
		println("Missing the path to the file. More more info run go run . help")
		os.Exit(0)
	}
	file := os.Args[2] //the password
	if !validateFile(file) {
		panic("File not found")
	}
	fmt.Print("Enter password:")
	password, _ := term.ReadPassword(0)
	fmt.Println("\nDecrypting...")
	filecrypt.Decrypt(file, password)
	fmt.Println("\n file sucessfully decrypted")
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
