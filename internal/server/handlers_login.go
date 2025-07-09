package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/hashing"
	"github.com/golang-jwt/jwt/v5"
)

func expireAfter() time.Time {
	return time.Now().Add(time.Hour * 1)
}

type jwtNotaryClaims struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	RoleID   RoleID `json:"role_id"`
	jwt.RegisteredClaims
}

type LoginParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

// Helper function to generate a JWT
func generateJWT(id int64, username string, jwtSecret []byte, roleID RoleID) (string, error) {
	expiresAt := jwt.NewNumericDate(expireAfter())
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtNotaryClaims{
		ID:       id,
		Username: username,
		RoleID:   roleID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expiresAt,
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
		var loginParams LoginParams
		if err := json.NewDecoder(r.Body).Decode(&loginParams); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.Logger)
			return
		}
		if loginParams.Username == "" {
			err := errors.New("username is required")
			writeError(w, http.StatusBadRequest, "Username is required", err, env.Logger)
			return
		}
		if loginParams.Password == "" {
			err := errors.New("password is required")
			writeError(w, http.StatusBadRequest, "Password is required", err, env.Logger)
			return
		}
		userAccount, err := env.DB.GetUser(db.ByUsername(loginParams.Username))
		if err != nil {
			if !errors.Is(err, db.ErrNotFound) && !errors.Is(err, db.ErrInvalidFilter) {
				writeError(w, http.StatusInternalServerError, "Internal Error", err, env.Logger)
				return
			}
		}
		hashedPassword := ""
		if userAccount != nil {
			hashedPassword = userAccount.HashedPassword
		}
		if err := hashing.CompareHashAndPassword(hashedPassword, loginParams.Password); err != nil {
			writeError(w, http.StatusUnauthorized, "The username or password is incorrect", err, env.Logger)
			return
		}
		jwt, err := generateJWT(userAccount.ID, userAccount.Username, env.JWTSecret, RoleID(userAccount.RoleID))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.Logger)
			return
		}
		loginResponse := LoginResponse{
			Token: jwt,
		}
		err = writeResponse(w, loginResponse, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.Logger)
			return
		}
	}
}
