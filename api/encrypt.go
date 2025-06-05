package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	//"github.com/DILEEPSAJJA/File_Encrypt/filecrypt"
	"github.com/gin-gonic/gin"
)

func EncryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	r.ParseMultipartForm(10 << 20) // 10MB limit
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	password := r.FormValue("password")
	if len(password) < 4 {
		http.Error(w, "Password must be at least 4 characters", http.StatusBadRequest)
		return
	}

	tempPath := filepath.Join(os.TempDir(), header.Filename)
	out, _ := os.Create(tempPath)
	defer out.Close()
	defer os.Remove(tempPath)

	_, _ = out.ReadFrom(file)

	encPath, err := filecrypt.EncryptFile(tempPath, []byte(password))
	if err != nil {
		http.Error(w, fmt.Sprintf("Encryption failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(encPath)

	w.Header().Set("Content-Disposition", "attachment; filename="+header.Filename+".enc")
	http.ServeFile(w, r, encPath)
}

// Required by Vercel
var Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	EncryptHandler(w, r)
})