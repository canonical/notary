package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/canonical/notary/internal/auth"
	"github.com/canonical/notary/internal/db"
	"github.com/canonical/notary/internal/hashing"
	"github.com/canonical/notary/internal/logging"
	"github.com/golang-jwt/jwt/v5"
)

func expireAfter() time.Time {
	return time.Now().Add(time.Hour * 1)
}

type LoginParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

// Helper function to generate a JWT
func generateJWT(id int64, email string, jwtSecret []byte, roleID RoleID) (string, error) {
	expiresAt := jwt.NewNumericDate(expireAfter())
	permissionList := getPermissionsFromRoleID(roleID)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.NotaryJWTClaims{
		Email:       email,
		Permissions: permissionList,
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
			writeError(w, http.StatusBadRequest, "Invalid JSON format", err, env.SystemLogger)
			return
		}
		if loginParams.Email == "" {
			err := errors.New("email is required")
			writeError(w, http.StatusBadRequest, "Email is required", err, env.SystemLogger)
			return
		}
		if loginParams.Password == "" {
			err := errors.New("password is required")
			writeError(w, http.StatusBadRequest, "Password is required", err, env.SystemLogger)
			return
		}
		userAccount, err := env.DB.GetUser(db.ByEmail(loginParams.Email))
		if err != nil {
			if !errors.Is(err, db.ErrNotFound) && !errors.Is(err, db.ErrInvalidFilter) {
				writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
				return
			}
		}
		hashedPassword := ""
		if userAccount != nil {
			hashedPassword = userAccount.HashedPassword
		}
		if err := hashing.CompareHashAndPassword(hashedPassword, loginParams.Password); err != nil {
			env.AuditLogger.LoginFailed(loginParams.Email,
				logging.WithRequest(r),
				logging.WithReason("invalid credentials"),
			)
			writeError(w, http.StatusUnauthorized, "The email or password is incorrect", err, env.SystemLogger)
			return
		}
		jwt, err := generateJWT(userAccount.ID, userAccount.Email, env.JWTSecret, RoleID(userAccount.RoleID))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Internal Error", err, env.SystemLogger)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     CookieSessionTokenKey,
			Value:    jwt,
			HttpOnly: true,
			Secure:   true,
			Expires:  time.Now().Add(2 * time.Hour),
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})
		env.AuditLogger.TokenCreated(userAccount.Email, logging.WithRequest(r))
		env.AuditLogger.LoginSuccess(userAccount.Email, logging.WithRequest(r))
		err = writeResponse(w, SuccessResponse{Message: "success"}, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}

// Expire both cookies if logging out
func Logout(env *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:    CookieSessionTokenKey,
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),
		})
		err := writeResponse(w, SuccessResponse{Message: "success"}, http.StatusOK)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error", err, env.SystemLogger)
			return
		}
	}
}
