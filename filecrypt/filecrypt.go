package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io"
	"os"
)

// Derive AES-256 key from password
func createHash(password []byte) []byte {
	hash := sha256.Sum256(password)
	return hash[:]
}

func EncryptFile(inputPath string, password []byte) (string, error) {
	outputPath := inputPath + ".enc"
	inFile, err := os.Open(inputPath)
	if err != nil {
		return "", err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	key := createHash(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := key[:aes.BlockSize]
	stream := cipher.NewCFBEncrypter(block, iv)

	writer := &cipher.StreamWriter{S: stream, W: outFile}
	_, err = io.Copy(writer, inFile)
	return outputPath, err
}

func DecryptFile(inputPath string, password []byte) (string, error) {
	outputPath := inputPath[:len(inputPath)-4] // remove .enc
	inFile, err := os.Open(inputPath)
	if err != nil {
		return "", err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	key := createHash(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := key[:aes.BlockSize]
	stream := cipher.NewCFBDecrypter(block, iv)

	reader := &cipher.StreamReader{S: stream, R: inFile}
	_, err = io.Copy(outFile, reader)
	return outputPath, err
}
