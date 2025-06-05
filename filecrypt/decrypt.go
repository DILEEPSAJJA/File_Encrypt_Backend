package filecrypt

import (
	"io"
	"os"
	"strings"
)

func DecryptFile(filePath string, password []byte) (string, error) {
	decPath := strings.TrimSuffix(filePath, ".enc") + "_decrypted"
	in, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.Create(decPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	// Dummy decryption = just copy for now
	_, err = io.Copy(out, in)
	if err != nil {
		return "", err
	}

	return decPath, nil
}
