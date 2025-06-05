package filecrypt

import (
	"io"
	"os"
)

func EncryptFile(filePath string, password []byte) (string, error) {
	encPath := filePath + ".enc"
	in, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.Create(encPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	// Dummy encryption = just copy for now
	_, err = io.Copy(out, in)
	if err != nil {
		return "", err
	}

	return encPath, nil
}
