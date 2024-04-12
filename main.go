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
	"fmt"
	"os"
	"strings"

	"github.com/tijanatoskovic/PP_projekat/filecrypt"

	"golang.org/x/term"
)

const originalLetter = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

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
	case "encryptText":
		encryptedText := encryptText(5)
		decryptText(5, encryptedText)
	default:
		fmt.Println("Run:\t\"go run . help\"\tfor usage.")
		os.Exit(1)
	}
}
func hashLetterFunc(key int, letter string) (result string) {
	//this func returns the hashedText
	runes := []rune(letter)
	lastLetterKey := string(runes[len(letter)-key : len(letter)])
	leftOverLetter := string(runes[0 : len(letter)-key])
	return fmt.Sprintf(`%s%s`, lastLetterKey, leftOverLetter)
	//NOTICE: We have to use `` charachers because we are using runes
}

func decryptText(key int, encryptedText string) (result string) {
	hashLetter := hashLetterFunc(key, originalLetter)
	var hashedString = ""
	findOne := func(r rune) rune {
		pos := strings.Index(hashLetter, string([]rune{r}))
		if pos != -1 {
			letterPos := (pos + len(originalLetter)) % len(originalLetter)
			hashedString = hashedString + string(originalLetter[letterPos])
		}
		return r
	}

	strings.Map(findOne, encryptedText)
	fmt.Println("Decrypted text: ", hashedString)
	return hashedString
}

func encryptText(key int) (result string) {
	fmt.Println("Input text: ")
	var plainText string
	_, err := fmt.Scan(&plainText)
	//TODO: Make it accept a string containing space and other characters
	if err != nil {
		panic("Error!\n")
	}
	hashLetter := hashLetterFunc(key, originalLetter)
	var hashedString = ""
	//rune represents a single UNI-CODE character
	// for example the letter A=65
	findOne := func(r rune) rune {
		pos := strings.Index(originalLetter, string([]rune{r}))
		//We want to check if this letter exist in our originalText
		if pos != -1 {
			letterPos := (pos + len(originalLetter)) % len(originalLetter)
			hashedString = hashedString + string(hashLetter[letterPos])
		}
		return r
	}

	strings.Map(findOne, plainText)
	//this func takes one by one letters of our plainText and sends
	//it to the func findOne
	fmt.Println("Encrypted text: ", hashedString)
	return hashedString
}

func printHelp() {
	fmt.Println("file encryption")
	fmt.Println("Simple file encrypter for your day-to-day needs.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("\tgo run . encryptFile /path/to/your/file")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("")
	fmt.Println("\t encryptFile\tEncrypts a file given a password")
	fmt.Println("\t decryptFile\tTries to decrypt a file using a password")
	fmt.Println("\t encryptText\tEncrypts a given text with ceaser cipher")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println("")

}

func encryptHandle() {
	if len(os.Args) < 3 {
		println("Missing the path to the file. More more info run go run . help")
		os.Exit(0)
	}
	algorithm := os.Args[2]

	file := os.Args[3] //the password
	if !validateFile(file) {
		panic("File not found")
	}
	password := getPassword() //pass nam treba samo za AES
	fmt.Println("\nEncrypting...")
	switch algorithm {
	case "AES":
		filecrypt.EncryptAES(file, password)
	case "RSA":
		privateKey, _, err := filecrypt.EncryptRSA(file, 4096)
		if err != nil {
			fmt.Println("Error generating RSA key pair:", err)
			return
		}

		err = filecrypt.savePrivateKeyToFile(privateKey, "private.pem")
		if err != nil {
			fmt.Println("Error saving private key:", err)
			return
		}

		publicKey := &privateKey.PublicKey
		err = savePublicKeyToFile(publicKey, "public.pem")
		if err != nil {
			fmt.Println("Error saving public key:", err)
			return
		}
	}

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
