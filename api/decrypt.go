// --- api/decrypt.go ---
package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	//"github.com/DILEEPSAJJA/File_Encrypt/filecrypt"
)

func DecryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	r.ParseMultipartForm(10 << 20)
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

	decPath, err := filecrypt.DecryptFile(tempPath, []byte(password))
	if err != nil {
		http.Error(w, fmt.Sprintf("Decryption failed: %v", err), http.StatusBadRequest)
		return
	}
	defer os.Remove(decPath)

	origName := header.Filename[:len(header.Filename)-4] // remove ".enc"
	w.Header().Set("Content-Disposition", "attachment; filename="+origName)
	http.ServeFile(w, r, decPath)
}

var Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	DecryptHandler(w, r)
})
