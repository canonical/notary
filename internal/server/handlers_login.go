package server

import (
	"encoding/json"
	"errors"
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

func Login(env *Environment) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userRequest db.User
		if err := json.NewDecoder(r.Body).Decode(&userRequest); err != nil {
			logErrorAndWriteResponse("Invalid JSON format", http.StatusBadRequest, w)
			return
		}
		if userRequest.Username == "" {
			logErrorAndWriteResponse("Username is required", http.StatusBadRequest, w)
			return
		}
		if userRequest.Password == "" {
			logErrorAndWriteResponse("Password is required", http.StatusBadRequest, w)
			return
		}
		userAccount, err := env.DB.RetrieveUserByUsername(userRequest.Username)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, db.ErrIdNotFound) {
				logErrorAndWriteResponse("The username or password is incorrect. Try again.", http.StatusUnauthorized, w)
				return
			}
			logErrorAndWriteResponse(err.Error(), status, w)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(userAccount.Password), []byte(userRequest.Password)); err != nil {
			logErrorAndWriteResponse("The username or password is incorrect. Try again.", http.StatusUnauthorized, w)
			return
		}
		jwt, err := generateJWT(userAccount.ID, userAccount.Username, env.JWTSecret, userAccount.Permissions)
		if err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(jwt)); err != nil {
			logErrorAndWriteResponse(err.Error(), http.StatusInternalServerError, w)
		}
	}
}
