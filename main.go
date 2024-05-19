package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	endehandler "github.com/tijanatoskovic/PP_projekat/endeHandler"
)

var Passs []byte

func main() {
	//Creating a window for our app
	a := app.New()
	w := a.NewWindow("EnDeCrypter")

	//Fetching the file we want to encrypt/decrypt
	var filePath string
	labelFile := widget.NewLabel("Choose file: ")
	openButton := widget.NewButton("Open File", func() {
		openFile(w)
	})

	//We are using the finish button
	finishButton := widget.NewButton("", func() {
		/*Here we are using a temporary file to memorize the path of the file we want to
		encrypt/decrypt. This was the only way we could use the file path outside this
		function*/
		data, err := ioutil.ReadFile("temp.txt")
		if err != nil {
			panic("Error reading temp.txt")
		}
		if err := os.Remove("temp.txt"); err != nil {
			panic("Error removing temp.txt")
		}
		filePath = string(data)

		/*In the file "tempEnDe.txt" we will save wich option we will use*/
		optEncDec, err := ioutil.ReadFile("tempEnDe.txt")
		if err != nil {
			panic("Error reading file3")
		}
		if err := os.Remove("tempEnDe.txt"); err != nil {
			panic("Error removing file")
		}

		switch string(optEncDec) {
		case "Encryption":
			endehandler.EncryptHandle(filePath)
		case "Decryption":
			endehandler.DecryptHandle(filePath)
		default:
			fmt.Println("Run:\t\"go run . help\"\tfor usage.")
			os.Exit(1)
		}
		a.Quit()
	})

	labelEncDec := widget.NewLabel("Choose Encryption/Decryption: ")

	finishButton.Text = "Select option"

	radioEnDe := widget.NewRadioGroup([]string{"Encryption", "Decryption"}, func(s string) {
		//We write down the choosen option in a file:
		if err := ioutil.WriteFile("tempEnDe.txt", []byte(s), 0644); err != nil {
			panic("Error writting filepath into file")
		}
		finishButton.Text = s[:len(s)-3]
		finishButton.Refresh()
	})

	labelAlgorithm := widget.NewLabel("Choose preferred algorithm: ")
	radioAlgorithm := widget.NewRadioGroup([]string{"RSA", "AES"}, func(s string) {
		if s == "AES" {
			showAESWindow(a)
		}

		if err := ioutil.WriteFile("tempAlg.txt", []byte(s), 0644); err != nil {
			panic("Error writting filepath into file")
		}
	})

	helpButton := widget.NewButton("Help!", func() {
		help(a)
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

func getPassword(pass string) []byte {
	return []byte(pass)
}

func help(app fyne.App) {
	helpWindow := app.NewWindow("Help!")

	buttonBack := widget.NewButton("Back", func() {
		helpWindow.Close()
	})
	textEntry := widget.NewEntry()
	textEntry.MultiLine = true
	textEntry.Text = "File encrypter for your data!\nSteps:\n\t1.Choose file you want to encrypt/decrypt by clicking on \"Open File\" button\n\t2.Choose do you want to encrypt or decrypt! \n\t\tNOTE: file can be encrypted only once!\n\t3.Choose algorithm:\n\t4. Click encrypt/decrypt!"
	textEntry.SetMinRowsVisible(10)
	textEntry.Disable()
	helpWindow.SetContent(container.NewVBox(
		textEntry,
		buttonBack,
	))
	helpWindow.Resize(fyne.NewSize(600, 300))
	helpWindow.Show()
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

			if err := ioutil.WriteFile("temp.txt", []byte(filePath), 0644); err != nil { //it automatically closes opened file after writting into file
				fmt.Println("Error writting filepath into file")
				return
			}
		}
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
		if password != "" && confirmPassword != "" && password == confirmPassword {
			fmt.Println("Passwords match!")
			Passs = getPassword(password)
			endehandler.Passs = Passs
			encryptionWindow.Close()
		} else {
			labelNotMatch.SetText("Passwords do not match")
		}
	})

	encryptionWindow.SetContent(container.NewVBox(
		widget.NewLabel("Enter Password:"),
		passwordEntry,
		widget.NewLabel("Confirm Password:"),
		confirmEntry,
		submitButton,
		labelNotMatch,
	))

	encryptionWindow.Resize(fyne.NewSize(400, 300))
	encryptionWindow.Show()
}
