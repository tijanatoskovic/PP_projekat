package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func EncryptAES(source string, password []byte) {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	srcFile, err := os.Open(source)
	if err != nil {
		panic(err.Error())
	}

	defer srcFile.Close()

	plaintext, err := io.ReadAll(srcFile)
	if err != nil {
		panic(err.Error())
	}

	key := password

	nonce := make([]byte, 12) //this will make [0, 0, 0, ..., 0]
	//Randomizing the nonce:
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Password-Based Key Derivation Function:
	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New) //derivate key

	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	cipherText := aesgcm.Seal(nil, nonce, plaintext, nil)
	//adding the 12 byte nonce at the end of the encrypted file
	cipherText = append(cipherText, nonce...)

	//creating the file
	dstFile, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}

	defer dstFile.Close()

	_, err = dstFile.Write(cipherText)
	if err != nil {
		panic(err.Error())
	}

}

func Decrypt(source string, password []byte) {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	srcFile, err := os.Open(source)
	if err != nil {
		panic(err.Error())
	}

	defer srcFile.Close()

	cipherText, err := io.ReadAll(srcFile)
	if err != nil {
		panic(err.Error())
	}

	key := password
	salt := cipherText[len(cipherText)-12:]
	str := hex.EncodeToString(salt)
	nonce, err := hex.DecodeString(str)
	if err != nil {
		panic(err.Error())
	}

	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plainText, err := aesgcm.Open(nil, nonce, cipherText[:len(cipherText)-12], nil)
	if err != nil {
		panic(err.Error())
	}

	//creating the file
	dstFile, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}
	defer dstFile.Close()

	_, err = dstFile.Write(plainText)
	if err != nil {
		panic(err.Error())
	}

}

func EncryptRSA(source string, privateKey *rsa.PrivateKey) error {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		return err
	}

	plaintext, err := os.ReadFile(source)
	if err != nil {
		return err
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, plaintext)
	if err != nil {
		return err
	}

	//creating the file
	dstFile, err := os.Create(source + ".enc")
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = dstFile.Write(ciphertext)
	if err != nil {
		return err
	}

	fmt.Println("\nFile successfully encrypted")
	return nil
}

func DecryptRSA(source string, privateKey *rsa.PrivateKey) error {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		return err
	}

	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}

	defer srcFile.Close()

	cipherText, err := io.ReadAll(srcFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(cipherText)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, block.Bytes)
	if err != nil {
		return err
	}

	//creating the file
	dstFile, err := os.Create(source)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = dstFile.Write(decryptedBytes)
	if err != nil {
		return err
	}

	return nil
}
