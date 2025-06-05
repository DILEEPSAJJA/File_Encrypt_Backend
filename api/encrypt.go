package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"file_encrypt_backend/filecrypt"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		addCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	addCORSHeaders(w)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

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
	out, err := os.Create(tempPath)
	if err != nil {
		http.Error(w, "Failed to save uploaded file", http.StatusInternalServerError)
		return
	}
	defer out.Close()
	io.Copy(out, file)
	defer os.Remove(tempPath)

	encPath, err := filecrypt.EncryptFile(tempPath, []byte(password))
	if err != nil {
		http.Error(w, fmt.Sprintf("Encryption failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(encPath)

	w.Header().Set("Content-Disposition", "attachment; filename="+header.Filename+".enc")
	http.ServeFile(w, r, encPath)
}

func addCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "https://file-encrypt-frontend.vercel.app")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}
