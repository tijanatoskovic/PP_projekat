package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
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

	block, err := aes.NewCipher(dk) //initializes an AES cipher with the provided key!!! Crucial step
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block) //create new gcm password using aes block
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

func DecryptAES(source string, password []byte) {
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

// GenerateRSAKeys generates a pair of RSA private and public keys
func GenerateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// EncryptWithAES encrypts data using AES-256-GCM
func EncryptWithAES(data []byte) ([]byte, []byte, error) {
	key := make([]byte, 32) // AES-256, so 32 bytes key
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), key, nil
}

// DecryptWithAES decrypts data using AES-256-GCM
func DecryptWithAES(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// EncryptKeyWithRSA encrypts the AES key using the RSA public key
func EncryptKeyWithRSA(key []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, key, nil)
}

// DecryptKeyWithRSA decrypts the AES key using the RSA private key
func DecryptKeyWithRSA(encryptedKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, nil)
}
