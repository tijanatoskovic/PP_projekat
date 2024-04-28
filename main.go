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
)

func help(w fyne.Window) {
	textEntry := widget.NewEntry()
	textEntry.MultiLine = true
	textEntry.Text = "Prvi red\nDrugi red\nTreći red"

	textEntry.Disable()

	// Postavljanje rasporeda za Entry
	w.SetContent(container.NewVBox(
		textEntry,
	))
}

// TODO: resiti problem lokalne promenljive u dialogu tako da moze da bude povratna vrednost za ovu fju
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

	// Kreiranje polja za unos šifre i potvrdu šifre
	passwordEntry := widget.NewPasswordEntry()
	confirmEntry := widget.NewPasswordEntry()

	// Kreiranje dugmeta za potvrdu šifre
	submitButton := widget.NewButton("Submit", func() {
		password := passwordEntry.Text
		confirmPassword := confirmEntry.Text

		// Provera da li su šifre ispravne
		if password == confirmPassword {
			fmt.Println("Passwords match:", password)
			// Ovde možete upisati šifre u promenljive ili obaviti druge operacije
		} else {
			fmt.Println("Passwords do not match")
			// Ovde možete prikazati obaveštenje korisniku da šifre nisu ispravne
		}
	})

	// Postavljanje rasporeda za elemente u novom prozoru
	encryptionWindow.SetContent(container.NewVBox(
		widget.NewLabel("Enter Password:"),
		passwordEntry,
		widget.NewLabel("Confirm Password:"),
		confirmEntry,
		submitButton,
	))

	// Prikazivanje novog prozora
	encryptionWindow.Resize(fyne.NewSize(400, 300))
	encryptionWindow.Show()
}

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
			fmt.Println("Error reading file")
			return
		}
		if err := os.Remove("temp.txt"); err != nil {
			fmt.Println("Error removing file")
			return
		}
		filePath = string(data)
		fmt.Println(filePath)
	})
	labelEncDec := widget.NewLabel("Choose Encryption/Decryption: ")
	var selectedOption string
	radioEnDe := widget.NewRadioGroup([]string{"Encrption", "Decryption"}, func(s string) {
		fmt.Println("Selected method: ", s)

		selectedOption = s
		finishButton.Text = s[:len(s)-3]
		finishButton.Refresh()
	})

	radioEnDe.SetSelected("Decrption")
	if selectedOption == "Encrption" {
		//panic("Not implemented")
	} else {
		//panic("Same")
	}
	//var selectedAlgorithm string
	labelAlgorithm := widget.NewLabel("Choose preferred algorithm: ")
	radioAlgorithm := widget.NewRadioGroup([]string{"RSA", "AES"}, func(s string) {
		fmt.Println("Selected algrothm: ", s)
		if s == "AES" {
			showAESWindow(a)
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
