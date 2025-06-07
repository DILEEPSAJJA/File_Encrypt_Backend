package api

import "net/http"

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://file-encrypt-frontend.vercel.app", http.StatusTemporaryRedirect)
}
