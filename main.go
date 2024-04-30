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

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	"github.com/tijanatoskovic/PP_projekat/filecrypt"
)

var passs []byte

func main() {
	a := app.New()
	w := a.NewWindow("EnDeCrypter")

	var filePath string
	labelFile := widget.NewLabel("Choose file: ")
	openButton := widget.NewButton("Open File", func() {
		openFile(w)

	})
	finishButton := widget.NewButton("", func() {
		data, err := ioutil.ReadFile("temp.txt")
		if err != nil {
			panic("Error reading file1")
		}
		if err := os.Remove("temp.txt"); err != nil {
			panic("Error removing file2")
		}
		filePath = string(data)
		//fmt.Println(filePath)

		optEncDec, err := ioutil.ReadFile("tempEnDe.txt")
		if err != nil {
			panic("Error reading file3")
		}
		if err := os.Remove("tempEnDe.txt"); err != nil {
			panic("Error removing file")
		}

		switch string(optEncDec) {
		case "help":
			printHelp()
		case "Encryption":
			encryptHandle(filePath)
		case "Decryption":
			decryptHandle(filePath)
		default:
			fmt.Println("Run:\t\"go run . help\"\tfor usage.")
			os.Exit(1)
		}
		a.Quit()
	})

	labelEncDec := widget.NewLabel("Choose Encryption/Decryption: ")

	radioEnDe := widget.NewRadioGroup([]string{"Encryption", "Decryption"}, func(s string) {
		//fmt.Println("Selected method: ", s)
		if err := ioutil.WriteFile("tempEnDe.txt", []byte(s), 0644); err != nil {
			panic("Error writting filepath into file")
		}
		finishButton.Text = s[:len(s)-3]
		finishButton.Refresh()
	})

	radioEnDe.SetSelected("Decryption")

	//var selectedAlgorithm string
	labelAlgorithm := widget.NewLabel("Choose preferred algorithm: ")
	radioAlgorithm := widget.NewRadioGroup([]string{"RSA", "AES"}, func(s string) {
		//fmt.Println("Selected algrothm: ", s)
		if s == "AES" {
			showAESWindow(a)
		}

		if err := ioutil.WriteFile("tempAlg.txt", []byte(s), 0644); err != nil {
			panic("Error writting filepath into file")
		}
	})
	// radioAlgorithm.SetSelected("RSA")

	// labelPass := widget.NewLabel("Password: ")

	helpButton := widget.NewButton("Help!", func() {
		help(w)
	})

	ctrlW := &desktop.CustomShortcut{KeyName: fyne.KeyW, Modifier: fyne.KeyModifierControl}
	w.Canvas().AddShortcut(ctrlW, func(shortcut fyne.Shortcut) {
		fyne.App.Quit(a)
	})
	HContainerRadio := container.NewHBox(radioAlgorithm)
	Hcontainer := container.NewHBox(finishButton, helpButton)
	container1 := container.NewVBox(labelFile, openButton, labelEncDec, radioEnDe, labelAlgorithm, HContainerRadio)
	w.SetContent(container.NewVBox(container1, Hcontainer))

	w.Resize(fyne.NewSize(800, 400))
	w.ShowAndRun()
}

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var encryptedData []byte
var encryptedAESKey []byte

func encryptHandle(filePath string) {

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
		if err != nil {
			fmt.Println("Error while writing the filePath!")
			return
		}
		fmt.Println("File sucessfully encrypted!")

	}
}

func decryptHandle(filePath string) {

	// fmt.Println("Choose which algorithm you had encrypted with [AES | RSA | ECC]: ")
	// fmt.Scanln(&algorithm)
	// fmt.Println("Enter path to file you want to encrypt/decrypt: ")
	// fmt.Scanln(&filePath)
	//fmt.Println(filePath)
	if !validateFile(filePath) {
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

func getPassword(pass string) []byte {
	return []byte(pass)
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

func help(w fyne.Window) {
	textEntry := widget.NewEntry()
	textEntry.MultiLine = true
	textEntry.Text = "File encrypter for your data!\nSteps:\n\tChoose file you want to encrypt/decrypt by clicking on \"Open File\" button\n\t2.Choose do you want to encrypt or decrypt! \n\t\tNOTE: file can be encrypted only once!\n\t3.Choose algorithm:\n\t4. Click encrypt/decrypt!"
	//textEntry.Scroll = true
	textEntry.SetMinRowsVisible(10)
	textEntry.Disable()
	// Postavljanje rasporeda za Entry
	w.SetContent(container.NewVBox(
		textEntry,
	))
}

func openFile(window fyne.Window) {
	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		if reader == nil {
			return
		}
		defer reader.Close() //for closing file together with dialog

		fileURI := reader.URI() // string for choosen file
		if fileURI != nil {
			filePath := fileURI.Path()
			dialog.ShowInformation("File Path", filePath, window)

			if err := ioutil.WriteFile("temp.txt", []byte(filePath), 0644); err != nil { //it automaticli closes opened file after writting into file
				fmt.Println("Error writting filepath into file")
				return
			}
		} // } else {
		// 	dialog.ShowError(, window)
		// }
	}, window)

}
func showAESWindow(app fyne.App) {
	encryptionWindow := app.NewWindow("Encryption Window")

	passwordEntry := widget.NewPasswordEntry()
	confirmEntry := widget.NewPasswordEntry()
	labelNotMatch := widget.NewLabel("")

	submitButton := widget.NewButton("Submit", func() {
		password := passwordEntry.Text
		confirmPassword := confirmEntry.Text
		if password == confirmPassword {
			fmt.Println("Passwords match!")
			passs = getPassword(password)

		} else {
			//labelNotMatch.SetColor(color.RGB(255, 0, 0))
			labelNotMatch.SetText("Passwords do not match")
		}
	})

	// Postavljanje rasporeda za elemente u novom prozoru
	encryptionWindow.SetContent(container.NewVBox(
		widget.NewLabel("Enter Password:"),
		passwordEntry,
		widget.NewLabel("Confirm Password:"),
		confirmEntry,
		submitButton,
		labelNotMatch,
	))

	// Prikazivanje novog prozora
	encryptionWindow.Resize(fyne.NewSize(400, 300))
	encryptionWindow.Show()
}
