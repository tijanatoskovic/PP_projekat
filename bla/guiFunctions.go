package guifunctions

import (
	"io/ioutil"

	"fyne.io/fyne/v2/widget"
)

func radioButtonFunc(s string, finishButton *widget.Button) {
	if err := ioutil.WriteFile("tempEnDe.txt", []byte(s), 0644); err != nil {
		panic("Error writting filepath into file")
	}
	finishButton.Text = s[:len(s)-3]
	finishButton.Refresh()
}
