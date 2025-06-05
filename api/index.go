package index

import (
	"net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://file-encrypt-frontend.vercel.app/", http.StatusTemporaryRedirect)
}
