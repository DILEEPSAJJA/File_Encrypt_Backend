package main

import (
	"log"
	"net/http"

	"file_encrypt_backend/api"
)

func main() {
	http.HandleFunc("/", api.Handler)
	http.HandleFunc("/api/encrypt", api.EncryptHandler)
	http.HandleFunc("/api/decrypt", api.DecryptHandler)

	log.Println("Running on http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
