package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type jwtNotaryClaims struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Permissions int    `json:"permissions"`
	jwt.StandardClaims
}

// Helper function to generate a JWT
func generateJWT(id int, username string, jwtSecret []byte, permissions int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtNotaryClaims{
		ID:          id,
		Username:    username,
		Permissions: permissions,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func Login(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userRequest db.User
		if err := json.NewDecoder(r.Body).Decode(&userRequest); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}
		if userRequest.Username == "" {
			writeError(w, http.StatusBadRequest, "Username is required")
			return
		}
		if userRequest.Password == "" {
			writeError(w, http.StatusBadRequest, "Password is required")
			return
		}
		userAccount, err := env.DB.RetrieveUserByUsername(userRequest.Username)
		if err != nil {
			log.Println(err)
			if errors.Is(err, db.ErrIdNotFound) {
				writeError(w, http.StatusUnauthorized, "The username or password is incorrect. Try again.")
				return
			}
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(userAccount.Password), []byte(userRequest.Password)); err != nil {
			writeError(w, http.StatusUnauthorized, "The username or password is incorrect. Try again.")
			return
		}
		jwt, err := generateJWT(userAccount.ID, userAccount.Username, env.JWTSecret, userAccount.Permissions)
		if err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(jwt)); err != nil {
			log.Println(err)
			writeError(w, http.StatusInternalServerError, "Internal Error")
		}
	}
}
