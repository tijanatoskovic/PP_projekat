package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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

func EncryptRSA(source string, bits int) (*rsa.PrivateKey, string, error) {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, source, err
	}
	return privateKey, source, nil
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

func savePublicKeyToFile(publicKey *rsa.PublicKey, filename string) error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := pem.Encode(file, publicKeyPEM); err != nil {
		return err
	}

	fmt.Println("Public key saved to", filename)
	return nil
}
