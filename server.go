package main

import (
    "github.com/abbot/go-http-auth"
    "golang.org/x/crypto/bcrypt"
    "net/http"
)

func Secret(user, realm string) string {
    if user == "${username}" {
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte("${password}"), bcrypt.DefaultCost)
        if err == nil {
            return string(hashedPassword)
        }
    }
    return ""
}

func handle(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
    http.FileServer(http.Dir("${path}")).ServeHTTP(w, &r.Request)
}

func main() {
    authenticator := auth.NewBasicAuthenticator("", Secret)
    http.HandleFunc("/", authenticator.Wrap(handle))
    http.ListenAndServe(":8000", nil)
}
