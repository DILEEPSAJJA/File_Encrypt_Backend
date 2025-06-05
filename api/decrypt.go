package decrypt

import (
	"File_Encrypt_Backend/filecrypt"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")

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
		http.Error(w, "Could not save uploaded file", http.StatusInternalServerError)
		return
	}
	defer out.Close()
	io.Copy(out, file)

	decPath, err := filecrypt.DecryptFile(tempPath, []byte(password))
	if err != nil {
		http.Error(w, fmt.Sprintf("Decryption failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(decPath)

	http.ServeFile(w, r, decPath)
}
