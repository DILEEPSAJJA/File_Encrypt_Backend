package filecrypt

import (
	"io"
	"os"
)

func EncryptFile(inputPath string, password []byte) (string, error) {
	outputPath := inputPath + ".enc"
	in, err := os.Open(inputPath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return outputPath, err
}

func DecryptFile(inputPath string, password []byte) (string, error) {
	outputPath := inputPath[:len(inputPath)-4]
	in, err := os.Open(inputPath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return outputPath, err
}
